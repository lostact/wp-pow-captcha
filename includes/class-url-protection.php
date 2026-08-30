<?php
/**
 * URL Protection class: intercepts requests to matching URLs and issues PoW challenges.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class PoW_Captcha_URL_Protection {

    /**
     * @var PoW_Captcha_Challenge
     */
    private $challenge;

    /**
     * Constructor.
     *
     * @param PoW_Captcha_Challenge $challenge Challenge instance.
     */
    public function __construct( PoW_Captcha_Challenge $challenge ) {
        $this->challenge = $challenge;
        add_action( 'template_redirect', array( $this, 'intercept' ) );
    }

    /**
     * Intercept requests to matching URLs.
     */
    public function intercept() {
        // The advanced-cache gateway already validated this matching request.
        if ( defined( 'POW_CAPTCHA_EARLY_PASSED' ) && POW_CAPTCHA_EARLY_PASSED ) {
            return;
        }

        $patterns = get_option( 'pow_url_patterns', array() );

        if ( empty( $patterns ) || ! is_array( $patterns ) ) {
            return;
        }

        $request_uri = isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
        $matched     = false;

        foreach ( $patterns as $pattern ) {
            if ( @preg_match( $pattern, $request_uri ) ) {
                $matched = true;
                break;
            }
        }

        if ( ! $matched ) {
            return;
        }

        $maximum_query_length = (int) get_option( 'pow_max_query_length', 0 );
        if ( $maximum_query_length > 0 && $this->query_string_length( $request_uri ) > $maximum_query_length ) {
            $this->block_long_query();
        }

        $secret_key = get_option( 'pow_secret_key', '' );

        // Check the signed, server-expiring, IP-bound clearance cookie.
        if ( isset( $_COOKIE['pow_cleared'] ) ) {
            $cookie_value = sanitize_text_field( wp_unslash( $_COOKIE['pow_cleared'] ) );
            $parts        = explode( ':', $cookie_value );

            if ( 4 === count( $parts ) ) {
                $version = (int) $parts[0];
                $expires = (int) $parts[1];
                $nonce   = sanitize_text_field( $parts[2] );
                $hmac    = sanitize_text_field( $parts[3] );

                $maximum_lifetime = max( 30, min( 3600, (int) get_option( 'pow_expiry_time', 300 ) ) );
                $valid_window     = $expires >= time() && $expires <= time() + $maximum_lifetime;
                $valid_nonce      = 32 === strlen( $nonce ) && ctype_xdigit( $nonce );
                $payload          = implode( ':', array( $version, 'cleared', $expires, $nonce, PoW_Captcha_Challenge::client_ip() ) );
                $expected_hmac    = hash_hmac( 'sha256', $payload, $secret_key );

                if ( PoW_Captcha_Challenge::VERSION === $version && $valid_window && $valid_nonce && hash_equals( $expected_hmac, $hmac ) ) {
                    return;
                }
            }

            // Remove malformed, expired, legacy, or IP-mismatched clearances.
            setcookie( 'pow_cleared', '', array(
                'expires'  => time() - HOUR_IN_SECONDS,
                'path'     => COOKIEPATH,
                'domain'   => COOKIE_DOMAIN,
                'secure'   => is_ssl(),
                'httponly' => true,
                'samesite' => 'Strict',
            ) );
        }

        // Check for solution cookie.
        if ( isset( $_COOKIE['pow_solution'] ) ) {
            $cookie_value = sanitize_text_field( wp_unslash( $_COOKIE['pow_solution'] ) );
            $parts        = explode( ':', $cookie_value );

            // Delete the pow_solution cookie immediately regardless of outcome.
            setcookie( 'pow_solution', '', time() - 3600, COOKIEPATH, COOKIE_DOMAIN );

            if ( 7 === count( $parts ) ) {
                $challenge  = sanitize_text_field( $parts[0] );
                $expires    = (int) $parts[1];
                $difficulty = (int) $parts[2];
                $version    = (int) $parts[3];
                $algorithm  = sanitize_text_field( $parts[4] );
                $sig        = sanitize_text_field( $parts[5] );
                $solution   = $parts[6];

                if ( PoW_Captcha_Challenge::VERSION === $version && ctype_digit( $solution ) ) {
                    if ( $this->challenge->verify( $challenge, $expires, $difficulty, $sig, $solution, $version, $algorithm ) ) {
                        // Clearance cannot outlive the original signed challenge
                        // and is valid only from the IP that received that challenge.
                        $nonce            = bin2hex( random_bytes( 16 ) );
                        $clearance_payload = implode( ':', array( $version, 'cleared', $expires, $nonce, PoW_Captcha_Challenge::client_ip() ) );
                        $cleared_hmac      = hash_hmac( 'sha256', $clearance_payload, $secret_key );
                        $cleared_value     = implode( ':', array( $version, $expires, $nonce, $cleared_hmac ) );

                        setcookie( 'pow_cleared', $cleared_value, array(
                            'expires'  => $expires,
                            'path'     => COOKIEPATH,
                            'domain'   => COOKIE_DOMAIN,
                            'secure'   => is_ssl(),
                            'httponly' => true,
                            'samesite' => 'Strict',
                        ) );

                        // Allow WordPress to handle the request normally (200 response).
                        return;
                    }
                }
            }

            // Verification failed — show challenge page with error.
            $this->show_challenge( true );
            return;
        }

        // No solution cookie and no valid cleared cookie — show fresh challenge.
        $this->show_challenge( false );
    }

    /** Return the raw query string length in bytes. */
    private function query_string_length( string $request_uri ): int {
        if ( isset( $_SERVER['QUERY_STRING'] ) ) {
            return strlen( sanitize_text_field( wp_unslash( $_SERVER['QUERY_STRING'] ) ) );
        }

        $separator = strpos( $request_uri, '?' );
        return false === $separator ? 0 : strlen( substr( $request_uri, $separator + 1 ) );
    }

    /** Reject an oversized query without issuing or accepting a challenge. */
    private function block_long_query(): void {
        nocache_headers();
        status_header( 414 );
        header( 'Content-Type: text/plain; charset=UTF-8' );
        header( 'X-Robots-Tag: noindex, nofollow', true );
        echo esc_html__( 'Request blocked: query string is too long.', 'proof-of-work-captcha' );
        exit;
    }

    /**
     * Show the challenge page.
     *
     * @param bool $error Whether the previous solution failed.
     */
    private function show_challenge( bool $error ) {
        $difficulty = (int) get_option( 'pow_url_difficulty', PoW_Captcha_Challenge::DEFAULT_DIFFICULTY );
        $difficulty = PoW_Captcha_Challenge::clamp_difficulty( $difficulty );
        $challenge  = $this->challenge->generate( $difficulty );
        $interaction_mode = (string) get_option( 'pow_interaction_mode', 'automatic' );
        if ( ! in_array( $interaction_mode, array( 'automatic', 'mouse', 'checkbox' ), true ) ) {
            $interaction_mode = 'automatic';
        }

        $is_secure = is_ssl();

        $plugin_url = plugin_dir_url( dirname( __FILE__ ) );
        wp_enqueue_style( 'pow-captcha-challenge', $plugin_url . 'assets/pow-challenge.css', array(), POW_CAPTCHA_VERSION );
        if ( pow_captcha_is_persian() ) {
            wp_enqueue_style( 'pow-captcha-vazirmatn', 'https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700&display=swap', array(), POW_CAPTCHA_VERSION );
        }
        wp_enqueue_script( 'pow-solver', $plugin_url . 'assets/pow-solver.js', array(), POW_CAPTCHA_VERSION, true );
        wp_add_inline_script(
            'pow-solver',
            'window.powChallenge=' . wp_json_encode( $challenge['challenge'] ) . ';' .
            'window.powExpires=' . absint( $challenge['expires'] ) . ';' .
            'window.powDifficulty=' . absint( $challenge['difficulty'] ) . ';' .
            'window.powVersion=' . absint( $challenge['version'] ) . ';' .
            'window.powAlgorithm=' . wp_json_encode( $challenge['algorithm'] ) . ';' .
            'window.powSig=' . wp_json_encode( $challenge['signature'] ) . ';' .
            'window.powInteractionMode=' . wp_json_encode( $interaction_mode ) . ';' .
            'window.powDebugProgress=' . wp_json_encode( (bool) get_option( 'pow_debug_progress', false ) ) . ';' .
            'window.powI18n=' . wp_json_encode( pow_captcha_frontend_translations() ) . ';' .
            'window.powWorkerUrl=' . wp_json_encode( add_query_arg( 'ver', POW_CAPTCHA_VERSION, $plugin_url . 'assets/pow-worker.js' ) ) . ';',
            'before'
        );

        nocache_headers();
        header( 'Cache-Control: private, no-store, no-cache, must-revalidate, max-age=0' );
        header( 'Pragma: no-cache' );
        status_header( 403 );

        include plugin_dir_path( dirname( __FILE__ ) ) . 'templates/challenge-page.php';

        exit;
    }
}
