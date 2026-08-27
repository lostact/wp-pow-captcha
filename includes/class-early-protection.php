<?php
/**
 * Manages optional advanced-cache.php early protection.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class PoW_Captcha_Early_Protection {

    public const OPTION_ENABLED = 'pow_early_protection_enabled';
    public const OPTION_STATUS  = 'pow_early_protection_status';
    public const MARKER         = 'WP PoW Captcha managed advanced-cache drop-in';

    /** Official Cloudflare HTTP proxy ranges. */
    private const CLOUDFLARE_RANGES = array(
        '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '104.16.0.0/13',
        '104.24.0.0/14', '108.162.192.0/18', '131.0.72.0/22', '141.101.64.0/18',
        '162.158.0.0/15', '172.64.0.0/13', '173.245.48.0/20', '188.114.96.0/20',
        '190.93.240.0/20', '197.234.240.0/22', '198.41.128.0/17', '2400:cb00::/32',
        '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32',
        '2a06:98c0::/29', '2c0f:f248::/32',
    );

    /** Register synchronization hooks. */
    public function __construct() {
        add_action( 'update_option_pow_url_patterns', array( __CLASS__, 'synchronize_if_enabled' ), 10, 0 );
        add_action( 'update_option_pow_url_difficulty', array( __CLASS__, 'synchronize_if_enabled' ), 10, 0 );
        add_action( 'update_option_pow_expiry_time', array( __CLASS__, 'synchronize_if_enabled' ), 10, 0 );
        add_action( 'update_option_blogname', array( __CLASS__, 'synchronize_if_enabled' ), 10, 0 );
        add_action( 'update_option_pow_secret_key', array( __CLASS__, 'synchronize_if_enabled' ), 10, 0 );
    }

    /** Enable or disable early protection from a sanitized setting value. */
    public static function apply_setting( bool $enabled ): bool {
        // This method is a Settings API sanitizer. It must return the value and
        // must not update its own option, which would recursively invoke it.
        if ( $enabled ) {
            return self::install();
        }

        self::uninstall();
        return false;
    }

    /** Install the managed drop-in and generated configuration. */
    public static function install(): bool {
        $dropin = self::dropin_path();
        if ( file_exists( $dropin ) && ! self::owns_dropin() ) {
            self::set_status( 'error', __( 'Early protection was not enabled because another advanced-cache.php drop-in already exists. It was not modified.', 'wp-pow-captcha' ) );
            return false;
        }

        if ( ! self::write_config( true ) ) {
            self::set_status( 'error', __( 'Early protection could not write its runtime configuration. Check wp-content permissions.', 'wp-pow-captcha' ) );
            return false;
        }

        if ( ! self::atomic_write( $dropin, self::dropin_contents() ) ) {
            self::delete_owned_config();
            self::set_status( 'error', __( 'Early protection could not create advanced-cache.php. Check wp-content permissions.', 'wp-pow-captcha' ) );
            return false;
        }

        if ( ! self::enable_wp_cache() ) {
            self::set_status( 'warning', __( 'The drop-in was installed, but WP_CACHE is not enabled. Add define( \'WP_CACHE\', true ); to wp-config.php to activate early protection.', 'wp-pow-captcha' ) );
            return true;
        }

        self::set_status( 'success', __( 'Early protection is active. Unsolved protected URL requests exit before normal plugins and the theme load.', 'wp-pow-captcha' ) );
        return true;
    }

    /** Remove only files owned by this plugin. */
    public static function uninstall(): void {
        if ( self::owns_dropin() ) {
            @unlink( self::dropin_path() );
        }
        self::delete_owned_config();
        self::set_status( 'info', __( 'Early protection is disabled. Standard URL protection remains active.', 'wp-pow-captcha' ) );
    }

    /** Refresh generated configuration after settings change. */
    public static function synchronize_if_enabled(): void {
        if ( get_option( self::OPTION_ENABLED, false ) ) {
            self::write_config( true );
        }
    }

    /** Return status information for the admin UI. */
    public static function status(): array {
        $enabled      = (bool) get_option( self::OPTION_ENABLED, false );
        $dropin       = file_exists( self::dropin_path() );
        $owned        = $dropin && self::owns_dropin();
        $foreign      = $dropin && ! $owned;
        $wp_cache     = defined( 'WP_CACHE' ) && WP_CACHE;
        $saved_status = get_option( self::OPTION_STATUS, array() );

        return array(
            'enabled'  => $enabled,
            'dropin'   => $dropin,
            'owned'    => $owned,
            'foreign'  => $foreign,
            'wp_cache' => $wp_cache,
            'level'    => isset( $saved_status['level'] ) ? $saved_status['level'] : 'info',
            'message'  => isset( $saved_status['message'] ) ? $saved_status['message'] : '',
            'active'   => $enabled && $owned && $wp_cache,
        );
    }

    /** Whether the current advanced-cache file belongs to this plugin. */
    private static function owns_dropin(): bool {
        $path = self::dropin_path();
        if ( ! is_readable( $path ) || filesize( $path ) > 16384 ) {
            return false;
        }
        $contents = file_get_contents( $path );
        return is_string( $contents ) && false !== strpos( $contents, self::MARKER );
    }

    /** Write the standalone PHP configuration. */
    private static function write_config( bool $enabled ): bool {
        $config = array(
            'schema'               => 1,
            'enabled'              => $enabled,
            'secret_key'           => (string) get_option( 'pow_secret_key', '' ),
            'url_patterns'          => array_values( (array) get_option( 'pow_url_patterns', array() ) ),
            'url_difficulty'        => PoW_Captcha_Challenge::clamp_difficulty( (int) get_option( 'pow_url_difficulty', PoW_Captcha_Challenge::DEFAULT_DIFFICULTY ) ),
            'expiry_time'           => max( 30, min( 3600, (int) get_option( 'pow_expiry_time', 300 ) ) ),
            'site_name'             => wp_strip_all_tags( get_bloginfo( 'name' ) ),
            'asset_url'             => plugin_dir_url( dirname( __FILE__ ) ) . 'assets',
            'plugin_version'        => defined( 'POW_CAPTCHA_VERSION' ) ? POW_CAPTCHA_VERSION : '2.3.0',
            'trusted_proxy_ranges'  => array_values( (array) apply_filters( 'pow_captcha_trusted_proxy_ranges', self::CLOUDFLARE_RANGES ) ),
        );

        $contents = "<?php\n// WP PoW Captcha generated runtime configuration. Direct access returns data only.\nreturn " . var_export( $config, true ) . ";\n";
        return self::atomic_write( self::config_path(), $contents );
    }

    /** Build a stable loader that fails open during updates or missing files. */
    private static function dropin_contents(): string {
        $runtime = wp_normalize_path( plugin_dir_path( dirname( __FILE__ ) ) . 'includes/runtime/class-early-runtime.php' );
        $config  = wp_normalize_path( self::config_path() );

        return "<?php\n/** " . self::MARKER . " */\n" .
            "if ( ! defined( 'ABSPATH' ) ) { return; }\n" .
            '$pow_runtime = ' . var_export( $runtime, true ) . ";\n" .
            '$pow_config_file = ' . var_export( $config, true ) . ";\n" .
            "if ( ! is_readable( \$pow_runtime ) || ! is_readable( \$pow_config_file ) ) { return; }\n" .
            "\$pow_config = include \$pow_config_file;\n" .
            "if ( ! is_array( \$pow_config ) ) { return; }\n" .
            "require_once \$pow_runtime;\n" .
            "if ( class_exists( 'PoW_Captcha_Early_Runtime', false ) ) { PoW_Captcha_Early_Runtime::run( \$pow_config ); }\n";
    }

    /** Try to enable WP_CACHE without creating duplicate definitions. */
    private static function enable_wp_cache(): bool {
        if ( defined( 'WP_CACHE' ) && WP_CACHE ) {
            return true;
        }

        $path = self::wp_config_path();
        if ( '' === $path || ! is_readable( $path ) || ! is_writable( $path ) ) {
            return false;
        }

        $contents = file_get_contents( $path );
        if ( ! is_string( $contents ) ) {
            return false;
        }

        $updated = $contents;
        if ( preg_match( '/define\s*\(\s*([\'\"])WP_CACHE\1\s*,\s*false\s*\)\s*;/i', $contents ) ) {
            $updated = preg_replace( '/define\s*\(\s*([\'\"])WP_CACHE\1\s*,\s*false\s*\)\s*;/i', "define( 'WP_CACHE', true );", $contents, 1 );
        } elseif ( ! preg_match( '/define\s*\(\s*([\'\"])WP_CACHE\1\s*,/i', $contents ) ) {
            $line = "\n/** Enabled by WP PoW Captcha for early protection. */\ndefine( 'WP_CACHE', true );\n";
            $needle = "/* That's all, stop editing!";
            $position = strpos( $contents, $needle );
            if ( false === $position ) {
                $needle   = "require_once ABSPATH . 'wp-settings.php';";
                $position = strpos( $contents, $needle );
            }
            if ( false === $position ) {
                return false;
            }
            $updated = substr( $contents, 0, $position ) . $line . substr( $contents, $position );
        }

        if ( $updated === $contents ) {
            return false;
        }

        return self::atomic_write( $path, $updated );
    }

    /** Locate wp-config.php in either supported WordPress location. */
    private static function wp_config_path(): string {
        $root = ABSPATH . 'wp-config.php';
        if ( file_exists( $root ) ) {
            return $root;
        }
        $parent = dirname( ABSPATH ) . '/wp-config.php';
        return file_exists( $parent ) && ! file_exists( dirname( ABSPATH ) . '/wp-settings.php' ) ? $parent : '';
    }

    /** Atomically write a file when its directory is writable. */
    private static function atomic_write( string $path, string $contents ): bool {
        $directory = dirname( $path );
        if ( ! is_dir( $directory ) || ! is_writable( $directory ) || ( file_exists( $path ) && ! is_writable( $path ) ) ) {
            return false;
        }

        $temporary = tempnam( $directory, '.pow-' );
        if ( false === $temporary ) {
            return false;
        }

        $written = file_put_contents( $temporary, $contents, LOCK_EX );
        if ( false === $written ) {
            @unlink( $temporary );
            return false;
        }
        @chmod( $temporary, 0644 );
        if ( ! @rename( $temporary, $path ) ) {
            @unlink( $temporary );
            return false;
        }
        return true;
    }

    /** Save an admin-readable state. */
    private static function set_status( string $level, string $message ): void {
        update_option( self::OPTION_STATUS, array( 'level' => $level, 'message' => $message ), false );
    }

    private static function dropin_path(): string {
        return WP_CONTENT_DIR . '/advanced-cache.php';
    }

    private static function config_path(): string {
        return WP_CONTENT_DIR . '/pow-captcha-runtime.php';
    }

    private static function delete_owned_config(): void {
        $path = self::config_path();
        if ( is_readable( $path ) ) {
            $contents = file_get_contents( $path, false, null, 0, 128 );
            if ( is_string( $contents ) && false !== strpos( $contents, 'WP PoW Captcha generated runtime configuration' ) ) {
                @unlink( $path );
            }
        }
    }
}
