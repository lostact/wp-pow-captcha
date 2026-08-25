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
        $patterns = get_option( 'pow_url_patterns', array() );

        if ( empty( $patterns ) || ! is_array( $patterns ) ) {
            return;
        }

        $request_uri = $_SERVER['REQUEST_URI'] ?? '';
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

        $secret_key = get_option( 'pow_secret_key', '' );

        // Check for cleared cookie.
        if ( isset( $_COOKIE['pow_cleared'] ) ) {
            $cookie_value = sanitize_text_field( wp_unslash( $_COOKIE['pow_cleared'] ) );
            $parts        = explode( ':', $cookie_value, 2 );

            if ( count( $parts ) === 2 ) {
                list( $nonce, $hmac ) = $parts;
                $expected_hmac = hash_hmac( 'sha256', $nonce . ':cleared', $secret_key );

                if ( hash_equals( $expected_hmac, $hmac ) ) {
                    // Valid cleared cookie — allow request.
                    return;
                }
            }
        }

        // Check for solution cookie.
        if ( isset( $_COOKIE['pow_solution'] ) ) {
            $cookie_value = sanitize_text_field( wp_unslash( $_COOKIE['pow_solution'] ) );
            $parts        = explode( ':', $cookie_value, 5 );

            // Delete the pow_solution cookie immediately regardless of outcome.
            setcookie( 'pow_solution', '', time() - 3600, COOKIEPATH, COOKIE_DOMAIN );

            if ( count( $parts ) === 5 ) {
                $challenge  = sanitize_text_field( $parts[0] );
                $expires    = (int) $parts[1];
                $difficulty = (int) $parts[2];
                $sig        = sanitize_text_field( $parts[3] );
                $solution   = $parts[4];

                // Validate solution with ctype_digit before passing to verify.
                if ( ctype_digit( $solution ) ) {
                    if ( $this->challenge->verify( $challenge, $expires, $difficulty, $sig, $solution ) ) {
                        // Verification passed — issue cleared cookie.
                        $nonce         = bin2hex( random_bytes( 8 ) );
                        $cleared_hmac  = hash_hmac( 'sha256', $nonce . ':cleared', $secret_key );
                        $cleared_value = $nonce . ':' . $cleared_hmac;

                        setcookie( 'pow_cleared', $cleared_value, array(
                            'expires'  => time() + HOUR_IN_SECONDS,
                            'path'     => COOKIEPATH,
                            'domain'   => COOKIE_DOMAIN,
                            'secure'   => is_ssl(),
                            'httponly'  => true,
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

    /**
     * Show the challenge page.
     *
     * @param bool $error Whether the previous solution failed.
     */
    private function show_challenge( bool $error ) {
        $difficulty = (int) get_option( 'pow_url_difficulty', 4 );
        $difficulty = max( 1, min( 8, $difficulty ) );
        $challenge  = $this->challenge->generate( $difficulty );

        $is_secure = is_ssl();

        status_header( 403 );

        include plugin_dir_path( dirname( __FILE__ ) ) . 'templates/challenge-page.php';

        exit;
    }
}
