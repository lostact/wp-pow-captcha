<?php
/**
 * Standalone early PoW runtime.
 *
 * This file deliberately has no WordPress API dependencies because it is loaded
 * from wp-content/advanced-cache.php before normal plugins and themes.
 */

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

            $request_uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '';
            if ( '' === $request_uri || strlen( $request_uri ) > 8192 || ! self::matches( $request_uri, $config['url_patterns'] ) ) {
                return;
            }

            $secret = (string) $config['secret_key'];
            $expiry = self::clamp( isset( $config['expiry_time'] ) ? (int) $config['expiry_time'] : 300, 30, 3600 );
            $ip     = self::client_ip( isset( $config['trusted_proxy_ranges'] ) && is_array( $config['trusted_proxy_ranges'] ) ? $config['trusted_proxy_ranges'] : array() );

            if ( isset( $_COOKIE['pow_cleared'] ) && self::valid_clearance( (string) $_COOKIE['pow_cleared'], $secret, $expiry, $ip ) ) {
                self::mark_passed();
                return;
            }

            $solution_error = false;
            if ( isset( $_COOKIE['pow_solution'] ) ) {
                $solution_error = true;
                $cookie         = (string) $_COOKIE['pow_solution'];
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

        /** Match the request against administrator-validated regular expressions. */
        private static function matches( string $request_uri, array $patterns ): bool {
            $count = 0;
            foreach ( $patterns as $pattern ) {
                if ( ++$count > 100 || ! is_string( $pattern ) || strlen( $pattern ) > 512 ) {
                    continue;
                }
                if ( 1 === @preg_match( $pattern, $request_uri ) ) {
                    return true;
                }
            }
            return false;
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
            $asset_url  = isset( $config['asset_url'] ) ? rtrim( (string) $config['asset_url'], '/' ) : '';
            $version    = isset( $config['plugin_version'] ) ? (string) $config['plugin_version'] : '1';

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
            ?>
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title><?php echo self::escape( $site_name ); ?> — Security Check</title>
<style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;background:#f0f0f1;color:#1d2327;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}.pow-container{width:100%;max-width:500px;padding:40px;text-align:center;background:#fff;border:1px solid #c3c4c7;border-radius:4px;box-shadow:0 1px 3px #0002}.pow-icon{font-size:48px}.site-name{margin:8px 0 24px;color:#646970}.pow-container h1{font-size:1.3em}.pow-progress{position:relative;height:8px;margin-top:22px;overflow:hidden;border-radius:99px;background:#dcdcde}.pow-progress span{position:absolute;inset:0 auto 0 -35%;width:35%;border-radius:inherit;background:#2271b1;animation:p 1.15s ease-in-out infinite}[data-pow-state=solved] .pow-progress span{left:0;width:100%;background:#00a32a;animation:none}[data-pow-state=error] .pow-progress span{left:0;width:100%;background:#d63638;animation:none}@keyframes p{to{left:100%}}#pow-status{margin:16px 0 0;font-weight:600;color:#50575e}#pow-details{min-height:1.5em;margin-top:6px;font-size:.8em;color:#646970}.pow-error{margin-bottom:20px;padding:12px;color:#b32d2e;background:#fcf0f1;border:1px solid #d63638;border-radius:4px}</style></head>
<body><main class="pow-container" data-pow-state="solving"><div class="pow-icon">&#128274;</div><div class="site-name"><?php echo self::escape( $site_name ); ?></div><h1>Checking your browser…</h1>
<?php if ( $error ) : ?><div class="pow-error">The previous security check failed. A new check is running automatically.</div><?php endif; ?>
<div class="pow-progress" role="progressbar" aria-label="Security check in progress" aria-busy="true"><span></span></div><p id="pow-status" role="status" aria-live="polite">Please wait while we verify your browser…</p><p id="pow-details">Starting secure worker…</p></main>
<script>window.powChallenge=<?php echo json_encode( $challenge, $json_flags ); ?>;window.powExpires=<?php echo (int) $expires; ?>;window.powDifficulty=<?php echo (int) $difficulty; ?>;window.powVersion=<?php echo self::VERSION; ?>;window.powAlgorithm=<?php echo json_encode( self::ALGORITHM, $json_flags ); ?>;window.powSig=<?php echo json_encode( $signature, $json_flags ); ?>;window.powWorkerUrl=<?php echo json_encode( $worker_url, $json_flags ); ?>;</script>
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
            return ( isset( $_SERVER['HTTPS'] ) && 'off' !== strtolower( (string) $_SERVER['HTTPS'] ) ) ||
                ( isset( $_SERVER['SERVER_PORT'] ) && 443 === (int) $_SERVER['SERVER_PORT'] );
        }

        /** Return a normalized client IP, trusting configured proxy ranges only. */
        private static function client_ip( array $trusted_ranges ): string {
            $remote = self::normalize_ip( isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : '' );
            if ( '' === $remote ) {
                return 'unknown';
            }
            if ( self::ip_in_ranges( $remote, $trusted_ranges ) ) {
                $ipv6 = self::normalize_ip( isset( $_SERVER['HTTP_CF_CONNECTING_IPV6'] ) ? $_SERVER['HTTP_CF_CONNECTING_IPV6'] : '' );
                if ( '' !== $ipv6 && false !== strpos( $ipv6, ':' ) ) {
                    return $ipv6;
                }
                $forwarded = self::normalize_ip( isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ? $_SERVER['HTTP_CF_CONNECTING_IP'] : '' );
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
