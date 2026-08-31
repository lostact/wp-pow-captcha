<?php
/**
 * Standalone early PoW runtime.
 *
 * This file deliberately has no WordPress API dependencies because it is loaded
 * from wp-content/advanced-cache.php before normal plugins and themes.
 */

// The early runtime executes before WordPress APIs exist, so enqueue and core
// escaping helpers are unavailable. Its output uses the local context-aware
// escape() method and intentionally emits a self-contained bootstrap page.
// phpcs:disable WordPress.WP.EnqueuedResources.NonEnqueuedStylesheet, WordPress.WP.EnqueuedResources.NonEnqueuedScript, WordPress.Security.EscapeOutput.OutputNotEscaped

if ( ! class_exists( 'PoW_Captcha_Early_Runtime', false ) ) {
    final class PoW_Captcha_Early_Runtime {

        /** Current challenge protocol version. */
        private const VERSION = 3;

        /** Current proof-of-work algorithm. */
        private const ALGORITHM = 'sha256-fine-v3';

        /** Fractional-bit thresholds. */
        private const FRACTION_THRESHOLDS = array( 256, 239, 223, 208, 194, 181, 169, 158, 147, 137 );

        /** Maximum accepted cookie length. */
        private const MAX_COOKIE_LENGTH = 512;

        /**
         * Process the current request and either return immediately or emit a challenge.
         *
         * @param array $config Generated runtime configuration.
         */
        public static function run( array $config ): void {
            if ( empty( $config['enabled'] ) || empty( $config['secret_key'] ) || empty( $config['url_patterns'] ) ) {
                return;
            }

            $request_uri = filter_input( INPUT_SERVER, 'REQUEST_URI', FILTER_SANITIZE_URL );
            $request_uri = is_string( $request_uri ) ? $request_uri : '';
            if ( '' === $request_uri || strlen( $request_uri ) > 65535 || ! self::matches( $request_uri, $config['url_patterns'] ) ) {
                return;
            }

            $maximum_query_length = isset( $config['max_query_length'] ) ? self::clamp( (int) $config['max_query_length'], 0, 65535 ) : 0;
            if ( $maximum_query_length > 0 && self::query_string_length( $request_uri ) > $maximum_query_length ) {
                $page_strings = isset( $config['page_strings'] ) && is_array( $config['page_strings'] ) ? $config['page_strings'] : array();
                $message      = isset( $page_strings['long_query'] ) ? (string) $page_strings['long_query'] : 'Request blocked: query string is too long.';
                self::block_long_query( $message );
            }

            $secret = (string) $config['secret_key'];
            $expiry = self::clamp( isset( $config['expiry_time'] ) ? (int) $config['expiry_time'] : 300, 30, 3600 );
            $ip     = self::client_ip( isset( $config['trusted_proxy_ranges'] ) && is_array( $config['trusted_proxy_ranges'] ) ? $config['trusted_proxy_ranges'] : array() );

            $clearance_cookie = filter_input( INPUT_COOKIE, 'pow_cleared', FILTER_SANITIZE_FULL_SPECIAL_CHARS );
            if ( is_string( $clearance_cookie ) && self::valid_clearance( $clearance_cookie, $secret, $expiry, $ip ) ) {
                self::mark_passed();
                return;
            }

            $solution_error = false;
            $solution_cookie = filter_input( INPUT_COOKIE, 'pow_solution', FILTER_SANITIZE_FULL_SPECIAL_CHARS );
            if ( is_string( $solution_cookie ) ) {
                $solution_error = true;
                $cookie         = $solution_cookie;
                self::delete_cookie( 'pow_solution' );
                unset( $_COOKIE['pow_solution'] );

                $solved = self::verify_solution_cookie( $cookie, $secret, $ip );
                if ( false !== $solved ) {
                    $clearance = self::create_clearance( (int) $solved['expires'], $secret, $ip );
                    self::set_cookie( 'pow_cleared', $clearance, (int) $solved['expires'], true );
                    $_COOKIE['pow_cleared'] = $clearance;
                    self::mark_passed();
                    return;
                }
            }

            self::show_challenge( $config, $secret, $ip, $solution_error );
        }

        /** Return the raw query string length in bytes. */
        private static function query_string_length( string $request_uri ): int {
            if ( isset( $_SERVER['QUERY_STRING'] ) ) {
                $query_string = filter_input( INPUT_SERVER, 'QUERY_STRING', FILTER_UNSAFE_RAW );
                return is_string( $query_string ) ? strlen( $query_string ) : 0;
            }

            $separator = strpos( $request_uri, '?' );
            return false === $separator ? 0 : strlen( substr( $request_uri, $separator + 1 ) );
        }

        /** Emit a minimal response for an oversized matching query. */
        private static function block_long_query( string $message ): void {
            if ( ! headers_sent() ) {
                http_response_code( 414 );
                header( 'Content-Type: text/plain; charset=UTF-8' );
                header( 'Cache-Control: private, no-store, no-cache, must-revalidate, max-age=0' );
                header( 'Pragma: no-cache' );
                header( 'X-Robots-Tag: noindex, nofollow', true );
            }
            echo self::escape( $message );
            exit;
        }

        /** Match the request against administrator-validated regular expressions. */
        private static function matches( string $request_uri, array $patterns ): bool {
            $count = 0;
            foreach ( $patterns as $pattern ) {
                if ( ++$count > 100 || ! is_string( $pattern ) || strlen( $pattern ) > 512 ) {
                    continue;
                }
                $compiled = self::compile_pattern( $pattern );
                if ( null !== $compiled && 1 === preg_match( $compiled, $request_uri ) ) {
                    return true;
                }
            }
            return false;
        }

        /** Compile an undelimited expression from generated configuration. */
        private static function compile_pattern( string $pattern ): ?string {
            $pattern = trim( $pattern );
            if ( '' === $pattern || 1 === preg_match( '/^([\/~#%!@;`]).+\1[a-zA-Z]*$/s', $pattern ) ) {
                return null;
            }
            $compiled = chr( 31 ) . $pattern . chr( 31 );
            return false !== @preg_match( $compiled, '' ) ? $compiled : null;
        }

        /** Mark a matching request as cleared for the normal plugin fallback. */
        private static function mark_passed(): void {
            if ( ! defined( 'POW_CAPTCHA_EARLY_PASSED' ) ) {
                define( 'POW_CAPTCHA_EARLY_PASSED', true );
            }
        }

        /** Validate a signed clearance cookie. */
        private static function valid_clearance( string $cookie, string $secret, int $maximum_lifetime, string $ip ): bool {
            if ( strlen( $cookie ) > self::MAX_COOKIE_LENGTH ) {
                return false;
            }

            $parts = explode( ':', $cookie );
            if ( 4 !== count( $parts ) ) {
                return false;
            }

            $version = (int) $parts[0];
            $expires = (int) $parts[1];
            $nonce   = $parts[2];
            $hmac    = $parts[3];
            $now     = time();

            if (
                self::VERSION !== $version ||
                $expires < $now ||
                $expires > $now + $maximum_lifetime ||
                32 !== strlen( $nonce ) ||
                ! ctype_xdigit( $nonce ) ||
                64 !== strlen( $hmac ) ||
                ! ctype_xdigit( $hmac )
            ) {
                return false;
            }

            $payload  = implode( ':', array( $version, 'cleared', $expires, $nonce, $ip ) );
            $expected = hash_hmac( 'sha256', $payload, $secret );
            return hash_equals( $expected, $hmac );
        }

        /** Verify a one-use browser solution cookie and return its signed metadata. */
        private static function verify_solution_cookie( string $cookie, string $secret, string $ip ) {
            if ( strlen( $cookie ) > self::MAX_COOKIE_LENGTH ) {
                return false;
            }

            $parts = explode( ':', $cookie );
            if ( 7 !== count( $parts ) ) {
                return false;
            }

            $challenge  = $parts[0];
            $expires    = (int) $parts[1];
            $difficulty = (int) $parts[2];
            $version    = (int) $parts[3];
            $algorithm  = $parts[4];
            $signature  = $parts[5];
            $solution   = $parts[6];

            if (
                self::VERSION !== $version ||
                self::ALGORITHM !== $algorithm ||
                time() > $expires ||
                32 !== strlen( $challenge ) ||
                ! ctype_xdigit( $challenge ) ||
                $difficulty < 0 ||
                $difficulty > 140 ||
                64 !== strlen( $signature ) ||
                ! ctype_xdigit( $signature ) ||
                ! ctype_digit( $solution ) ||
                strlen( $solution ) > 20
            ) {
                return false;
            }

            $payload  = implode( ':', array( $version, $algorithm, $challenge, $expires, $difficulty, $ip ) );
            $expected = hash_hmac( 'sha256', $payload, $secret );
            if ( ! hash_equals( $expected, $signature ) ) {
                return false;
            }

            $hash = hash( 'sha256', $challenge . $solution, true );
            if ( ! self::hash_meets_difficulty( $hash, $difficulty ) ) {
                return false;
            }

            return array( 'expires' => $expires );
        }

        /** Create a signed IP-bound clearance value. */
        private static function create_clearance( int $expires, string $secret, string $ip ): string {
            $nonce   = bin2hex( random_bytes( 16 ) );
            $payload = implode( ':', array( self::VERSION, 'cleared', $expires, $nonce, $ip ) );
            return implode( ':', array( self::VERSION, $expires, $nonce, hash_hmac( 'sha256', $payload, $secret ) ) );
        }

        /** Generate and emit the standalone challenge response. */
        private static function show_challenge( array $config, string $secret, string $ip, bool $error ): void {
            $difficulty = self::clamp( isset( $config['url_difficulty'] ) ? (int) $config['url_difficulty'] : 60, 0, 140 );
            $expiry     = self::clamp( isset( $config['expiry_time'] ) ? (int) $config['expiry_time'] : 300, 30, 3600 );
            $challenge  = bin2hex( random_bytes( 16 ) );
            $expires    = time() + $expiry;
            $payload    = implode( ':', array( self::VERSION, self::ALGORITHM, $challenge, $expires, $difficulty, $ip ) );
            $signature  = hash_hmac( 'sha256', $payload, $secret );
            $site_name  = isset( $config['site_name'] ) ? (string) $config['site_name'] : 'Website';
            $locale     = isset( $config['locale'] ) ? str_replace( '_', '-', (string) $config['locale'] ) : 'en-US';
            $direction  = isset( $config['text_direction'] ) && 'rtl' === $config['text_direction'] ? 'rtl' : 'ltr';
            $is_persian = 1 === preg_match( '/^fa(?:_|-)/i', $locale );
            $asset_url  = isset( $config['asset_url'] ) ? rtrim( (string) $config['asset_url'], '/' ) : '';
            $version    = isset( $config['plugin_version'] ) ? (string) $config['plugin_version'] : '1';
            $interaction_mode = isset( $config['interaction_mode'] ) ? (string) $config['interaction_mode'] : 'automatic';
            $debug_progress   = ! empty( $config['debug_progress'] );
            if ( ! in_array( $interaction_mode, array( 'automatic', 'mouse', 'checkbox' ), true ) ) {
                $interaction_mode = 'automatic';
            }
            $frontend_strings = isset( $config['frontend_strings'] ) && is_array( $config['frontend_strings'] ) ? $config['frontend_strings'] : array();
            $page_strings     = isset( $config['page_strings'] ) && is_array( $config['page_strings'] ) ? $config['page_strings'] : array();
            $page_title       = isset( $page_strings['title'] ) ? str_replace( '%s', $site_name, (string) $page_strings['title'] ) : $site_name . ' — Security Check';
            $heading          = isset( $page_strings['heading'] ) ? (string) $page_strings['heading'] : 'Checking your browser…';
            $retry            = isset( $page_strings['retry'] ) ? (string) $page_strings['retry'] : 'The previous security check failed. Complete the new check to try again.';
            $progress_label   = isset( $page_strings['progress'] ) ? (string) $page_strings['progress'] : 'Security check in progress';
            $please_wait      = isset( $page_strings['please_wait'] ) ? (string) $page_strings['please_wait'] : 'Please wait while we verify your browser…';
            $starting         = isset( $page_strings['starting'] ) ? (string) $page_strings['starting'] : 'Starting secure worker…';

            if ( '' === $asset_url ) {
                return;
            }

            if ( ! headers_sent() ) {
                http_response_code( 403 );
                header( 'Content-Type: text/html; charset=UTF-8' );
                header( 'Cache-Control: private, no-store, no-cache, must-revalidate, max-age=0' );
                header( 'Pragma: no-cache' );
                header( 'X-Robots-Tag: noindex, nofollow', true );
            }

            $json_flags = JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES;
            $worker_url = $asset_url . '/pow-worker.js?ver=' . rawurlencode( $version );
            $solver_url = $asset_url . '/pow-solver.js?ver=' . rawurlencode( $version );
            $style_url  = $asset_url . '/pow-challenge.css?ver=' . rawurlencode( $version );
            ?>
<!doctype html>
<html lang="<?php echo self::escape( $locale ); ?>" dir="<?php echo $direction; ?>"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title><?php echo self::escape( $page_title ); ?></title>
<?php if ( $is_persian ) : ?><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700&display=swap"><?php endif; ?>
<link rel="stylesheet" href="<?php echo self::escape( $style_url ); ?>"></head>
<body><main class="pow-container" data-pow-state="solving" dir="<?php echo $direction; ?>"><div class="pow-icon">&#128274;</div><h1><?php echo self::escape( $heading ); ?></h1>
<?php if ( $error ) : ?><div class="pow-error"><?php echo self::escape( $retry ); ?></div><?php endif; ?>
<div class="pow-progress" role="progressbar" aria-label="<?php echo self::escape( $progress_label ); ?>" aria-busy="true" hidden><span></span></div><p id="pow-status" role="status" aria-live="polite"><?php echo self::escape( $please_wait ); ?></p><p id="pow-details" hidden><?php echo self::escape( $starting ); ?></p></main>
<script>window.powChallenge=<?php echo json_encode( $challenge, $json_flags ); ?>;window.powExpires=<?php echo (int) $expires; ?>;window.powDifficulty=<?php echo (int) $difficulty; ?>;window.powVersion=<?php echo self::VERSION; ?>;window.powAlgorithm=<?php echo json_encode( self::ALGORITHM, $json_flags ); ?>;window.powSig=<?php echo json_encode( $signature, $json_flags ); ?>;window.powInteractionMode=<?php echo json_encode( $interaction_mode, $json_flags ); ?>;window.powDebugProgress=<?php echo $debug_progress ? 'true' : 'false'; ?>;window.powI18n=<?php echo json_encode( $frontend_strings, $json_flags ); ?>;window.powWorkerUrl=<?php echo json_encode( $worker_url, $json_flags ); ?>;</script>
<script src="<?php echo self::escape( $solver_url ); ?>"></script></body></html>
            <?php
            exit;
        }

        /** Set a cookie using native PHP only. */
        private static function set_cookie( string $name, string $value, int $expires, bool $http_only ): void {
            if ( headers_sent() ) {
                return;
            }
            setcookie( $name, $value, array(
                'expires'  => $expires,
                'path'     => '/',
                'secure'   => self::is_ssl(),
                'httponly' => $http_only,
                'samesite' => 'Strict',
            ) );
        }

        /** Delete a cookie. */
        private static function delete_cookie( string $name ): void {
            self::set_cookie( $name, '', time() - 3600, true );
        }

        /** Determine HTTPS without WordPress helpers. */
        private static function is_ssl(): bool {
            $https = filter_input( INPUT_SERVER, 'HTTPS', FILTER_SANITIZE_FULL_SPECIAL_CHARS );
            return ( is_string( $https ) && 'off' !== strtolower( $https ) ) ||
                ( isset( $_SERVER['SERVER_PORT'] ) && 443 === (int) $_SERVER['SERVER_PORT'] );
        }

        /** Return a normalized client IP, trusting configured proxy ranges only. */
        private static function client_ip( array $trusted_ranges ): string {
            $remote = self::normalize_ip( filter_input( INPUT_SERVER, 'REMOTE_ADDR', FILTER_SANITIZE_FULL_SPECIAL_CHARS ) );
            if ( '' === $remote ) {
                return 'unknown';
            }
            if ( self::ip_in_ranges( $remote, $trusted_ranges ) ) {
                $ipv6 = self::normalize_ip( filter_input( INPUT_SERVER, 'HTTP_CF_CONNECTING_IPV6', FILTER_SANITIZE_FULL_SPECIAL_CHARS ) );
                if ( '' !== $ipv6 && false !== strpos( $ipv6, ':' ) ) {
                    return $ipv6;
                }
                $forwarded = self::normalize_ip( filter_input( INPUT_SERVER, 'HTTP_CF_CONNECTING_IP', FILTER_SANITIZE_FULL_SPECIAL_CHARS ) );
                if ( '' !== $forwarded ) {
                    return $forwarded;
                }
            }
            return $remote;
        }

        /** Normalize an IPv4 or IPv6 address. */
        private static function normalize_ip( $ip ): string {
            $packed = @inet_pton( trim( (string) $ip ) );
            return false === $packed ? '' : (string) inet_ntop( $packed );
        }

        /** Check an IP against IPv4/IPv6 CIDRs. */
        private static function ip_in_ranges( string $ip, array $ranges ): bool {
            $binary = @inet_pton( $ip );
            if ( false === $binary ) {
                return false;
            }
            foreach ( $ranges as $range ) {
                $parts = explode( '/', (string) $range, 2 );
                if ( 2 !== count( $parts ) ) {
                    continue;
                }
                $network = @inet_pton( trim( $parts[0] ) );
                $prefix  = (int) $parts[1];
                if ( false === $network || strlen( $network ) !== strlen( $binary ) || $prefix < 0 || $prefix > 8 * strlen( $binary ) ) {
                    continue;
                }
                $bytes = intdiv( $prefix, 8 );
                $bits  = $prefix % 8;
                if ( substr( $binary, 0, $bytes ) !== substr( $network, 0, $bytes ) ) {
                    continue;
                }
                if ( $bits > 0 ) {
                    $mask = ( 0xff << ( 8 - $bits ) ) & 0xff;
                    if ( ( ord( $binary[ $bytes ] ) & $mask ) !== ( ord( $network[ $bytes ] ) & $mask ) ) {
                        continue;
                    }
                }
                return true;
            }
            return false;
        }

        /** Verify whole and fractional proof-of-work bits. */
        private static function hash_meets_difficulty( string $hash, int $difficulty ): bool {
            $whole     = 10 + intdiv( $difficulty, 10 );
            $fraction  = $difficulty % 10;
            $bytes     = array_values( unpack( 'C*', $hash ) );
            $full      = intdiv( $whole, 8 );
            $remaining = $whole % 8;
            for ( $i = 0; $i < $full; $i++ ) {
                if ( 0 !== $bytes[ $i ] ) {
                    return false;
                }
            }
            $offset = $full * 8;
            if ( $remaining > 0 ) {
                $mask = ( 0xff << ( 8 - $remaining ) ) & 0xff;
                if ( 0 !== ( $bytes[ $full ] & $mask ) ) {
                    return false;
                }
                $offset += $remaining;
            }
            if ( 0 === $fraction ) {
                return true;
            }
            $index = intdiv( $offset, 8 );
            $shift = $offset % 8;
            $next  = 0 === $shift ? $bytes[ $index ] : ( ( $bytes[ $index ] << $shift ) & 0xff ) | ( $bytes[ $index + 1 ] >> ( 8 - $shift ) );
            return $next < self::FRACTION_THRESHOLDS[ $fraction ];
        }

        /** Clamp an integer. */
        private static function clamp( int $value, int $minimum, int $maximum ): int {
            return max( $minimum, min( $maximum, $value ) );
        }

        /** Escape HTML without WordPress. */
        private static function escape( string $value ): string {
            return htmlspecialchars( $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8' );
        }
    }
}
