<?php
/**
 * Challenge class: stateless proof-of-work challenge generation and verification.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class PoW_Captcha_Challenge {

    /** Current challenge protocol version. */
    public const VERSION = 2;

    /** Minimum supported fine-grained difficulty. */
    public const MIN_DIFFICULTY = 0;

    /** Maximum supported fine-grained difficulty. */
    public const MAX_DIFFICULTY = 140;

    /** Difficulty whose expected work matches the old default (four hex zeros). */
    public const DEFAULT_DIFFICULTY = 60;

    /** Current proof-of-work algorithm identifier. */
    public const ALGORITHM = 'sha256-fine-v2';

    /**
     * Byte thresholds for fractional tenths of a bit.
     *
     * Index n approximates 256 * 2^(-n/10). Index zero is unused because a
     * whole-bit target does not need an additional byte comparison.
     */
    private const FRACTION_THRESHOLDS = array( 256, 239, 223, 208, 194, 181, 169, 158, 147, 137 );

    /** @var string The secret key used for HMAC signing. */
    private $secret_key;

    /** Constructor: retrieve the secret key from wp_options. */
    public function __construct() {
        $this->secret_key = get_option( 'pow_secret_key', '' );
    }

    /**
     * Generate a new proof-of-work challenge.
     *
     * Difficulty maps to expected hashes as 2^(10 + difficulty / 10), making
     * each one-point increase approximately 7.2% harder.
     *
     * @param int $difficulty Fine-grained difficulty from 0 through 140.
     * @return array Associative challenge payload.
     */
    public function generate( int $difficulty ): array {
        $difficulty  = self::clamp_difficulty( $difficulty );
        $challenge   = bin2hex( random_bytes( 16 ) );
        $expiry_time = (int) get_option( 'pow_expiry_time', 300 );
        $expires     = time() + $expiry_time;
        $version     = self::VERSION;
        $algorithm   = self::ALGORITHM;
        $signature   = hash_hmac(
            'sha256',
            self::signature_payload( $challenge, $expires, $difficulty, $version, $algorithm ),
            $this->secret_key
        );

        return array(
            'challenge'  => $challenge,
            'expires'    => $expires,
            'difficulty' => $difficulty,
            'version'    => $version,
            'algorithm'  => $algorithm,
            'signature'  => $signature,
        );
    }

    /**
     * Verify a proof-of-work solution.
     *
     * Version 1 remains accepted for already-rendered forms and challenge
     * pages until their signed expiry time. New challenges always use v2.
     *
     * @param string $challenge  Challenge hex string.
     * @param int    $expires    Expiration Unix timestamp.
     * @param int    $difficulty Signed difficulty value.
     * @param string $signature  HMAC signature.
     * @param string $solution   Numeric counter.
     * @param int    $version    Challenge protocol version.
     * @param string $algorithm  Signed algorithm identifier for v2.
     * @return bool True if valid.
     */
    public function verify(
        string $challenge,
        int $expires,
        int $difficulty,
        string $signature,
        string $solution,
        int $version = 1,
        string $algorithm = 'sha256'
    ): bool {
        if ( time() > $expires || ! ctype_xdigit( $challenge ) || 32 !== strlen( $challenge ) ) {
            return false;
        }

        if ( ! ctype_digit( $solution ) || strlen( $solution ) > 20 ) {
            return false;
        }

        if ( 1 === $version ) {
            return $this->verify_legacy( $challenge, $expires, $difficulty, $signature, $solution );
        }

        if (
            self::VERSION !== $version ||
            self::ALGORITHM !== $algorithm ||
            $difficulty < self::MIN_DIFFICULTY ||
            $difficulty > self::MAX_DIFFICULTY
        ) {
            return false;
        }

        $expected_signature = hash_hmac(
            'sha256',
            self::signature_payload( $challenge, $expires, $difficulty, $version, $algorithm ),
            $this->secret_key
        );

        if ( ! hash_equals( $expected_signature, $signature ) ) {
            return false;
        }

        $hash = hash( 'sha256', $challenge . $solution, true );
        return self::hash_meets_difficulty( $hash, $difficulty );
    }

    /** Clamp a v2 difficulty to its supported range. */
    public static function clamp_difficulty( int $difficulty ): int {
        return max( self::MIN_DIFFICULTY, min( self::MAX_DIFFICULTY, $difficulty ) );
    }

    /** Return the approximate expected number of hashes for a difficulty. */
    public static function expected_hashes( int $difficulty ): float {
        return pow( 2, 10 + self::clamp_difficulty( $difficulty ) / 10 );
    }

    /** Build the unambiguous signed v2 payload. */
    private static function signature_payload( string $challenge, int $expires, int $difficulty, int $version, string $algorithm ): string {
        return implode( ':', array( $version, $algorithm, $challenge, $expires, $difficulty ) );
    }

    /** Check the v2 whole-bit and fractional-bit target. */
    private static function hash_meets_difficulty( string $hash, int $difficulty ): bool {
        $whole_bits = 10 + intdiv( $difficulty, 10 );
        $fraction   = $difficulty % 10;
        $bytes      = array_values( unpack( 'C*', $hash ) );
        $full_bytes = intdiv( $whole_bits, 8 );
        $remaining  = $whole_bits % 8;

        for ( $i = 0; $i < $full_bytes; $i++ ) {
            if ( 0 !== $bytes[ $i ] ) {
                return false;
            }
        }

        $bit_offset = $full_bytes * 8;
        if ( $remaining > 0 ) {
            $mask = ( 0xff << ( 8 - $remaining ) ) & 0xff;
            if ( 0 !== ( $bytes[ $full_bytes ] & $mask ) ) {
                return false;
            }
            $bit_offset += $remaining;
        }

        if ( 0 === $fraction ) {
            return true;
        }

        $next_byte = self::extract_eight_bits( $bytes, $bit_offset );
        return $next_byte < self::FRACTION_THRESHOLDS[ $fraction ];
    }

    /** Extract eight bits from a byte array at an arbitrary bit offset. */
    private static function extract_eight_bits( array $bytes, int $bit_offset ): int {
        $byte_index = intdiv( $bit_offset, 8 );
        $shift      = $bit_offset % 8;

        if ( 0 === $shift ) {
            return $bytes[ $byte_index ];
        }

        return ( ( $bytes[ $byte_index ] << $shift ) & 0xff ) |
            ( $bytes[ $byte_index + 1 ] >> ( 8 - $shift ) );
    }

    /** Verify a legacy leading-hex-zero challenge. */
    private function verify_legacy( string $challenge, int $expires, int $difficulty, string $signature, string $solution ): bool {
        if ( $difficulty < 1 || $difficulty > 8 ) {
            return false;
        }

        $expected_signature = hash_hmac( 'sha256', "{$challenge}:{$expires}:{$difficulty}", $this->secret_key );
        if ( ! hash_equals( $expected_signature, $signature ) ) {
            return false;
        }

        $hash = hash( 'sha256', $challenge . $solution );
        return substr( $hash, 0, $difficulty ) === str_repeat( '0', $difficulty );
    }
}
