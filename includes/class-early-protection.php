<?php
/**
 * Manages optional advanced-cache.php early protection.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class PoW_Firewall_Early_Protection {

    public const OPTION_ENABLED = 'pow_firewall_early_protection_enabled';
    public const OPTION_STATUS  = 'pow_firewall_early_protection_status';
    public const OPTION_CONFIG_VERSION = 'pow_firewall_early_protection_config_version';
    public const MARKER         = 'Proof-of-Work Firewall managed advanced-cache drop-in';
    private const LEGACY_MARKER = 'Proof of Work Captcha managed advanced-cache drop-in';

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
        add_action( 'update_option_pow_firewall_firewall_url_patterns', array( __CLASS__, 'synchronize_if_enabled' ), 10, 0 );
        add_action( 'update_option_pow_firewall_firewall_url_difficulty', array( __CLASS__, 'synchronize_if_enabled' ), 10, 0 );
        add_action( 'update_option_pow_firewall_firewall_max_query_length', array( __CLASS__, 'synchronize_if_enabled' ), 10, 0 );
        add_action( 'update_option_pow_firewall_firewall_interaction_mode', array( __CLASS__, 'synchronize_if_enabled' ), 10, 0 );
        add_action( 'update_option_pow_firewall_firewall_debug_progress', array( __CLASS__, 'synchronize_if_enabled' ), 10, 0 );
        add_action( 'update_option_pow_firewall_firewall_expiry_time', array( __CLASS__, 'synchronize_if_enabled' ), 10, 0 );
        add_action( 'update_option_blogname', array( __CLASS__, 'synchronize_if_enabled' ), 10, 0 );
        add_action( 'update_option_WPLANG', array( __CLASS__, 'synchronize_if_enabled' ), 10, 0 );
        add_action( 'update_option_pow_firewall_firewall_secret_key', array( __CLASS__, 'synchronize_if_enabled' ), 10, 0 );

        // Refresh generated translations and runtime data once after upgrades.
        if ( get_option( self::OPTION_ENABLED, false ) && defined( 'POW_FIREWALL_VERSION' ) && POW_FIREWALL_VERSION !== get_option( self::OPTION_CONFIG_VERSION, '' ) ) {
            self::write_config( true );
        }
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
            self::set_status( 'error', __( 'Early protection was not enabled because another advanced-cache.php drop-in already exists. It was not modified.', 'proof-of-work-firewall' ) );
            return false;
        }

        if ( ! self::write_config( true ) ) {
            self::set_status( 'error', __( 'Early protection could not write its runtime configuration. Check wp-content permissions.', 'proof-of-work-firewall' ) );
            return false;
        }

        if ( ! self::atomic_write( $dropin, self::dropin_contents() ) ) {
            self::delete_owned_config();
            self::set_status( 'error', __( 'Early protection could not create advanced-cache.php. Check wp-content permissions.', 'proof-of-work-firewall' ) );
            return false;
        }

        if ( ! self::enable_wp_cache() ) {
            self::set_status( 'warning', __( 'The drop-in was installed, but WP_CACHE is not enabled. Add define( \'WP_CACHE\', true ); to wp-config.php to activate early protection.', 'proof-of-work-firewall' ) );
            return true;
        }

        self::set_status( 'success', __( 'Early protection is active. Unsolved protected URL requests exit before normal plugins and the theme load.', 'proof-of-work-firewall' ) );
        return true;
    }

    /** Remove only files owned by this plugin. */
    public static function uninstall(): void {
        if ( self::owns_dropin() ) {
            wp_delete_file( self::dropin_path() );
        }
        self::delete_owned_config();
        self::set_status( 'info', __( 'Early protection is disabled. Standard URL protection remains active.', 'proof-of-work-firewall' ) );
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
        $filesystem = self::filesystem();
        if ( ! $filesystem || ! $filesystem->is_readable( $path ) || $filesystem->size( $path ) > 16384 ) {
            return false;
        }
        $contents = $filesystem->get_contents( $path );
        return is_string( $contents ) && (
            false !== strpos( $contents, self::MARKER ) ||
            false !== strpos( $contents, self::LEGACY_MARKER )
        );
    }

    /** Write the standalone PHP configuration. */
    private static function write_config( bool $enabled ): bool {
        $interaction_mode = (string) get_option( 'pow_firewall_interaction_mode', 'automatic' );
        if ( ! in_array( $interaction_mode, array( 'automatic', 'mouse', 'checkbox' ), true ) ) {
            $interaction_mode = 'automatic';
        }

        $config = array(
            'schema'               => 1,
            'enabled'              => $enabled,
            'secret_key'           => (string) get_option( 'pow_firewall_secret_key', '' ),
            'url_patterns'          => array_values( (array) get_option( 'pow_firewall_url_patterns', array() ) ),
            'url_difficulty'        => PoW_Firewall_Challenge::clamp_difficulty( (int) get_option( 'pow_firewall_url_difficulty', PoW_Firewall_Challenge::DEFAULT_DIFFICULTY ) ),
            'max_query_length'      => max( 0, min( 65535, (int) get_option( 'pow_firewall_max_query_length', 0 ) ) ),
            'interaction_mode'      => $interaction_mode,
            'debug_progress'        => (bool) get_option( 'pow_firewall_debug_progress', false ),
            'expiry_time'           => max( 30, min( 3600, (int) get_option( 'pow_firewall_expiry_time', 300 ) ) ),
            'site_name'             => wp_strip_all_tags( get_bloginfo( 'name' ) ),
            'locale'                => get_locale(),
            'text_direction'        => pow_firewall_text_direction(),
            'asset_url'             => plugin_dir_url( dirname( __FILE__ ) ) . 'assets',
            'plugin_version'        => defined( 'POW_FIREWALL_VERSION' ) ? POW_FIREWALL_VERSION : '2.5.11',
            'frontend_strings'      => pow_firewall_frontend_translations(),
            'page_strings'          => array(
                /* translators: %s: site name. */
                'title'       => __( '%s — Security Check', 'proof-of-work-firewall' ),
                'heading'     => __( 'Checking your browser…', 'proof-of-work-firewall' ),
                'retry'       => __( 'The previous security check failed. Complete the new check to try again.', 'proof-of-work-firewall' ),
                'progress'    => __( 'Security check in progress', 'proof-of-work-firewall' ),
                'please_wait' => __( 'Please wait while we verify your browser…', 'proof-of-work-firewall' ),
                'starting'    => __( 'Starting secure worker…', 'proof-of-work-firewall' ),
                'long_query'  => __( 'Request blocked: query string is too long.', 'proof-of-work-firewall' ),
            ),
            'trusted_proxy_ranges'  => array_values( (array) apply_filters( 'pow_firewall_trusted_proxy_ranges', self::CLOUDFLARE_RANGES ) ),
        );

        $json = wp_json_encode( $config, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
        if ( false === $json ) {
            return false;
        }
        $contents = "<?php\n// Proof-of-Work Firewall generated runtime configuration. Direct access returns data only.\nreturn json_decode( " . self::php_string_literal( $json ) . ", true );\n";
        $written  = self::atomic_write( self::config_path(), $contents );
        if ( $written && defined( 'POW_FIREWALL_VERSION' ) ) {
            update_option( self::OPTION_CONFIG_VERSION, POW_FIREWALL_VERSION, false );
        }
        return $written;
    }

    /** Build a stable loader that fails open during updates or missing files. */
    private static function dropin_contents(): string {
        $runtime = wp_normalize_path( plugin_dir_path( dirname( __FILE__ ) ) . 'includes/runtime/class-early-runtime.php' );
        $config  = wp_normalize_path( self::config_path() );

        return "<?php\n/** " . self::MARKER . " */\n" .
            "if ( ! defined( 'ABSPATH' ) ) { return; }\n" .
            '$pow_firewall_runtime = ' . self::php_string_literal( $runtime ) . ";\n" .
            '$pow_firewall_config_file = ' . self::php_string_literal( $config ) . ";\n" .
            "if ( ! is_readable( \$pow_firewall_runtime ) || ! is_readable( \$pow_firewall_config_file ) ) { return; }\n" .
            "\$pow_firewall_config = include \$pow_firewall_config_file;\n" .
            "if ( ! is_array( \$pow_firewall_config ) ) { return; }\n" .
            "require_once \$pow_firewall_runtime;\n" .
            "if ( class_exists( 'PoW_Firewall_Early_Runtime', false ) ) { PoW_Firewall_Early_Runtime::run( \$pow_firewall_config ); }\n";
    }

    /** Try to enable WP_CACHE without creating duplicate definitions. */
    private static function enable_wp_cache(): bool {
        if ( defined( 'WP_CACHE' ) && WP_CACHE ) {
            return true;
        }

        $path = self::wp_config_path();
        $filesystem = self::filesystem();
        if ( '' === $path || ! $filesystem || ! $filesystem->is_readable( $path ) || ! $filesystem->is_writable( $path ) ) {
            return false;
        }

        $contents = $filesystem->get_contents( $path );
        if ( ! is_string( $contents ) ) {
            return false;
        }

        $updated = $contents;
        if ( preg_match( '/define\s*\(\s*([\'\"])WP_CACHE\1\s*,\s*false\s*\)\s*;/i', $contents ) ) {
            $updated = preg_replace( '/define\s*\(\s*([\'\"])WP_CACHE\1\s*,\s*false\s*\)\s*;/i', "define( 'WP_CACHE', true );", $contents, 1 );
        } elseif ( ! preg_match( '/define\s*\(\s*([\'\"])WP_CACHE\1\s*,/i', $contents ) ) {
            $line = "\n/** Enabled by Proof-of-Work Firewall for early protection. */\ndefine( 'WP_CACHE', true );\n";
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
        $filesystem = self::filesystem();
        if ( ! $filesystem || ! $filesystem->is_dir( $directory ) || ! $filesystem->is_writable( $directory ) || ( $filesystem->exists( $path ) && ! $filesystem->is_writable( $path ) ) ) {
            return false;
        }

        $temporary = trailingslashit( $directory ) . '.pow-' . wp_generate_password( 12, false, false ) . '.tmp';
        if ( ! $filesystem->put_contents( $temporary, $contents, FS_CHMOD_FILE ) ) {
            wp_delete_file( $temporary );
            return false;
        }
        if ( ! $filesystem->move( $temporary, $path, true ) ) {
            wp_delete_file( $temporary );
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
        return WP_CONTENT_DIR . '/pow-firewall-runtime.php';
    }

    private static function delete_owned_config(): void {
        $filesystem = self::filesystem();
        $paths = array(
            self::config_path(),
            WP_CONTENT_DIR . '/pow-captcha-runtime.php',
        );
        foreach ( $paths as $path ) {
            if ( $filesystem && $filesystem->is_readable( $path ) ) {
                $contents = $filesystem->get_contents( $path );
                if (
                    is_string( $contents ) &&
                    (
                        false !== strpos( $contents, 'Proof-of-Work Firewall generated runtime configuration' ) ||
                        false !== strpos( $contents, 'Proof of Work Captcha generated runtime configuration' )
                    )
                ) {
                    wp_delete_file( $path );
                }
            }
        }
    }

    /** Return an initialized WordPress filesystem instance. */
    private static function filesystem() {
        global $wp_filesystem;

        if ( ! function_exists( 'WP_Filesystem' ) ) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
        if ( ! $wp_filesystem && ! WP_Filesystem() ) {
            return null;
        }
        return $wp_filesystem;
    }

    /** Encode a value as a safe single-quoted PHP string literal. */
    private static function php_string_literal( string $value ): string {
        return "'" . str_replace( array( '\\', "'" ), array( '\\\\', "\\'" ), $value ) . "'";
    }
}
