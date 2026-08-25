<?php
/**
 * Challenge class: stateless proof-of-work challenge generation and verification.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class PoW_Captcha_Challenge {

    /**
     * @var string The secret key used for HMAC signing.
     */
    private $secret_key;

    /**
     * Constructor: retrieve the secret key from wp_options.
     */
    public function __construct() {
        $this->secret_key = get_option( 'pow_secret_key', '' );
    }

    /**
     * Generate a new proof-of-work challenge.
     *
     * @param int $difficulty Number of leading zero hex characters required.
     * @return array Associative array with keys: challenge, expires, difficulty, algorithm, signature.
     */
    public function generate( int $difficulty ): array {
        $challenge  = bin2hex( random_bytes( 16 ) );
        $expiry_time = (int) get_option( 'pow_expiry_time', 300 );
        $expires     = time() + $expiry_time;
        $algorithm = 'sha256';

        $signature = hash_hmac( 'sha256', "{$challenge}:{$expires}:{$difficulty}", $this->secret_key );

        return array(
            'challenge'  => $challenge,
            'expires'    => $expires,
            'difficulty' => $difficulty,
            'algorithm'  => $algorithm,
            'signature'  => $signature,
        );
    }

    /**
     * Verify a proof-of-work solution.
     *
     * @param string $challenge  The challenge hex string.
     * @param int    $expires    The expiration Unix timestamp.
     * @param int    $difficulty The required number of leading zeros.
     * @param string $signature  The HMAC signature.
     * @param string $solution   The numeric solution (counter).
     * @return bool True if the solution is valid, false otherwise.
     */
    public function verify( string $challenge, int $expires, int $difficulty, string $signature, string $solution ): bool {
        // 1. Check expiration.
        if ( time() > $expires ) {
            return false;
        }

        // 2. Verify the HMAC signature.
        $expected_signature = hash_hmac( 'sha256', "{$challenge}:{$expires}:{$difficulty}", $this->secret_key );
        if ( ! hash_equals( $expected_signature, $signature ) ) {
            return false;
        }

        // 3. Check that the solution is a numeric string.
        if ( ! ctype_digit( $solution ) ) {
            return false;
        }

        // 4. Verify the proof of work.
        $hash = hash( 'sha256', $challenge . $solution );
        $prefix = str_repeat( '0', $difficulty );

        return substr( $hash, 0, $difficulty ) === $prefix;
    }
}
