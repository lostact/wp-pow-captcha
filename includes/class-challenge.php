<?php
/**
 * Challenge class: stateless proof-of-work challenge generation and verification.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class PoW_Captcha_Challenge {

    /** Current IP-bound challenge protocol version. */
    public const VERSION = 3;

    /** Minimum supported fine-grained difficulty. */
    public const MIN_DIFFICULTY = 0;

    /** Maximum supported fine-grained difficulty. */
    public const MAX_DIFFICULTY = 140;

    /** Difficulty whose expected work matches the old default (four hex zeros). */
    public const DEFAULT_DIFFICULTY = 60;

    /** Current proof-of-work algorithm identifier. */
    public const ALGORITHM = 'sha256-fine-v3';

    /** Official Cloudflare HTTP proxy ranges from https://www.cloudflare.com/ips/. */
    private const CLOUDFLARE_RANGES = array(
        '103.21.244.0/22',
        '103.22.200.0/22',
        '103.31.4.0/22',
        '104.16.0.0/13',
        '104.24.0.0/14',
        '108.162.192.0/18',
        '131.0.72.0/22',
        '141.101.64.0/18',
        '162.158.0.0/15',
        '172.64.0.0/13',
        '173.245.48.0/20',
        '188.114.96.0/20',
        '190.93.240.0/20',
        '197.234.240.0/22',
        '198.41.128.0/17',
        '2400:cb00::/32',
        '2606:4700::/32',
        '2803:f800::/32',
        '2405:b500::/32',
        '2405:8100::/32',
        '2a06:98c0::/29',
        '2c0f:f248::/32',
    );

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
        $client_ip   = self::client_ip();
        $signature   = hash_hmac(
            'sha256',
            self::signature_payload( $challenge, $expires, $difficulty, $version, $algorithm, $client_ip ),
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
     * Only the current IP-bound protocol is accepted. Challenges rendered by
     * older versions are intentionally invalidated by this security upgrade.
     *
     * @param string $challenge  Challenge hex string.
     * @param int    $expires    Expiration Unix timestamp.
     * @param int    $difficulty Signed difficulty value.
     * @param string $signature  HMAC signature.
     * @param string $solution   Numeric counter.
     * @param int    $version    Challenge protocol version.
     * @param string $algorithm  Signed algorithm identifier.
     * @return bool True if valid.
     */
    public function verify(
        string $challenge,
        int $expires,
        int $difficulty,
        string $signature,
        string $solution,
        int $version = 0,
        string $algorithm = ''
    ): bool {
        if ( time() > $expires || ! ctype_xdigit( $challenge ) || 32 !== strlen( $challenge ) ) {
            return false;
        }

        if ( ! ctype_digit( $solution ) || strlen( $solution ) > 20 ) {
            return false;
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
            self::signature_payload( $challenge, $expires, $difficulty, $version, $algorithm, self::client_ip() ),
            $this->secret_key
        );

        if ( ! hash_equals( $expected_signature, $signature ) ) {
            return false;
        }

        $hash = hash( 'sha256', $challenge . $solution, true );
        return self::hash_meets_difficulty( $hash, $difficulty );
    }

    /** Clamp a fine-grained difficulty to its supported range. */
    public static function clamp_difficulty( int $difficulty ): int {
        return max( self::MIN_DIFFICULTY, min( self::MAX_DIFFICULTY, $difficulty ) );
    }

    /** Return the approximate expected number of hashes for a difficulty. */
    public static function expected_hashes( int $difficulty ): float {
        return pow( 2, 10 + self::clamp_difficulty( $difficulty ) / 10 );
    }

    /**
     * Return the normalized visitor IP, trusting Cloudflare headers only when
     * the direct peer belongs to a trusted proxy range.
     *
     * Extra proxy CIDRs (for example a Cloudflare Tunnel local peer) may be
     * supplied with the pow_captcha_trusted_proxy_ranges filter.
     */
    public static function client_ip(): string {
        $remote_ip = self::normalize_ip( $_SERVER['REMOTE_ADDR'] ?? '' );
        if ( '' === $remote_ip ) {
            return 'unknown';
        }

        $trusted_ranges = apply_filters( 'pow_captcha_trusted_proxy_ranges', self::CLOUDFLARE_RANGES );
        if ( is_array( $trusted_ranges ) && self::ip_in_ranges( $remote_ip, $trusted_ranges ) ) {
            // Pseudo IPv4 overwrite mode preserves the real IPv6 address here.
            $connecting_ipv6 = self::normalize_ip( $_SERVER['HTTP_CF_CONNECTING_IPV6'] ?? '' );
            if ( '' !== $connecting_ipv6 && false !== strpos( $connecting_ipv6, ':' ) ) {
                return $connecting_ipv6;
            }

            $connecting_ip = self::normalize_ip( $_SERVER['HTTP_CF_CONNECTING_IP'] ?? '' );
            if ( '' !== $connecting_ip ) {
                return $connecting_ip;
            }
        }

        return $remote_ip;
    }

    /** Build the unambiguous signed, IP-bound v3 payload. */
    private static function signature_payload( string $challenge, int $expires, int $difficulty, int $version, string $algorithm, string $client_ip ): string {
        return implode( ':', array( $version, $algorithm, $challenge, $expires, $difficulty, $client_ip ) );
    }

    /** Normalize valid IPv4 and IPv6 representations for stable signatures. */
    private static function normalize_ip( $ip ): string {
        $packed = @inet_pton( trim( (string) $ip ) );
        return false === $packed ? '' : inet_ntop( $packed );
    }

    /** Return whether an IP belongs to any supplied IPv4 or IPv6 CIDR. */
    private static function ip_in_ranges( string $ip, array $ranges ): bool {
        $ip_binary = @inet_pton( $ip );
        if ( false === $ip_binary ) {
            return false;
        }

        foreach ( $ranges as $range ) {
            $parts = explode( '/', (string) $range, 2 );
            if ( 2 !== count( $parts ) ) {
                continue;
            }

            $network_binary = @inet_pton( trim( $parts[0] ) );
            $prefix_length  = (int) $parts[1];
            if ( false === $network_binary || strlen( $network_binary ) !== strlen( $ip_binary ) ) {
                continue;
            }

            $maximum_bits = 8 * strlen( $ip_binary );
            if ( $prefix_length < 0 || $prefix_length > $maximum_bits ) {
                continue;
            }

            $full_bytes = intdiv( $prefix_length, 8 );
            $extra_bits = $prefix_length % 8;
            if ( substr( $ip_binary, 0, $full_bytes ) !== substr( $network_binary, 0, $full_bytes ) ) {
                continue;
            }

            if ( $extra_bits > 0 ) {
                $mask = ( 0xff << ( 8 - $extra_bits ) ) & 0xff;
                if ( ( ord( $ip_binary[ $full_bytes ] ) & $mask ) !== ( ord( $network_binary[ $full_bytes ] ) & $mask ) ) {
                    continue;
                }
            }

            return true;
        }

        return false;
    }

    /** Check the whole-bit and fractional-bit target. */
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

}
