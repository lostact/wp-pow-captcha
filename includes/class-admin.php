<?php
/**
 * Admin class: settings page for Proof of Work Captcha.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class PoW_Captcha_Admin {

    /**
     * Constructor: register admin hooks.
     */
    public function __construct() {
        add_action( 'admin_menu', array( $this, 'add_settings_page' ) );
        add_action( 'admin_init', array( $this, 'register_settings' ) );
        add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_assets' ) );
        add_action( 'wp_ajax_pow_reset_secret_key', array( $this, 'ajax_reset_secret_key' ) );
    }

    /**
     * Add the settings page under the Settings menu.
     */
    public function add_settings_page() {
        add_options_page(
            __( 'PoW Captcha', 'proof-of-work-captcha' ),
            __( 'PoW Captcha', 'proof-of-work-captcha' ),
            'manage_options',
            'pow-captcha',
            array( $this, 'render_settings_page' )
        );
    }

    /**
     * Register all settings with the Settings API.
     */
    public function register_settings() {
        // Option group.
        register_setting( 'pow_captcha_group', 'pow_expiry_time', array(
            'type'              => 'integer',
            'sanitize_callback' => array( $this, 'sanitize_expiry_time' ),
        ) );

        register_setting( 'pow_captcha_group', 'pow_protected_forms', array(
            'type'              => 'array',
            'sanitize_callback' => array( $this, 'sanitize_protected_forms' ),
        ) );

        register_setting( 'pow_captcha_group', 'pow_url_patterns', array(
            'type'              => 'array',
            'sanitize_callback' => array( $this, 'sanitize_url_patterns' ),
        ) );

        register_setting( 'pow_captcha_group', 'pow_form_difficulty', array(
            'type'              => 'integer',
            'sanitize_callback' => array( $this, 'sanitize_difficulty' ),
        ) );

        register_setting( 'pow_captcha_group', 'pow_url_difficulty', array(
            'type'              => 'integer',
            'sanitize_callback' => array( $this, 'sanitize_difficulty' ),
        ) );

        register_setting( 'pow_captcha_group', 'pow_max_query_length', array(
            'type'              => 'integer',
            'sanitize_callback' => array( $this, 'sanitize_max_query_length' ),
            'default'           => 0,
        ) );

        register_setting( 'pow_captcha_group', 'pow_interaction_mode', array(
            'type'              => 'string',
            'sanitize_callback' => array( $this, 'sanitize_interaction_mode' ),
            'default'           => 'automatic',
        ) );

        register_setting( 'pow_captcha_group', 'pow_debug_progress', array(
            'type'              => 'boolean',
            'sanitize_callback' => array( $this, 'sanitize_debug_progress' ),
            'default'           => false,
        ) );

        register_setting( 'pow_captcha_group', PoW_Captcha_Early_Protection::OPTION_ENABLED, array(
            'type'              => 'boolean',
            'sanitize_callback' => array( $this, 'sanitize_early_protection' ),
            'default'           => false,
        ) );

        // Section: Form Protection.
        add_settings_section(
            'pow_form_section',
            __( 'Form Protection', 'proof-of-work-captcha' ),
            array( $this, 'render_form_section' ),
            'pow-captcha'
        );

        add_settings_field(
            'pow_protected_forms',
            __( 'Protected Forms', 'proof-of-work-captcha' ),
            array( $this, 'render_protected_forms_field' ),
            'pow-captcha',
            'pow_form_section'
        );

        add_settings_field(
            'pow_form_difficulty',
            __( 'Form Difficulty', 'proof-of-work-captcha' ),
            array( $this, 'render_form_difficulty_field' ),
            'pow-captcha',
            'pow_form_section'
        );

        // Section: URL Protection.
        add_settings_section(
            'pow_url_section',
            __( 'URL Protection', 'proof-of-work-captcha' ),
            array( $this, 'render_url_section' ),
            'pow-captcha'
        );

        add_settings_field(
            'pow_url_patterns',
            __( 'URL Patterns', 'proof-of-work-captcha' ),
            array( $this, 'render_url_patterns_field' ),
            'pow-captcha',
            'pow_url_section'
        );

        add_settings_field(
            'pow_url_difficulty',
            __( 'URL Difficulty', 'proof-of-work-captcha' ),
            array( $this, 'render_url_difficulty_field' ),
            'pow-captcha',
            'pow_url_section'
        );

        add_settings_field(
            'pow_max_query_length',
            __( 'Maximum Query String Length', 'proof-of-work-captcha' ),
            array( $this, 'render_max_query_length_field' ),
            'pow-captcha',
            'pow_url_section'
        );

        // Section: General Settings.
        add_settings_section(
            'pow_general_section',
            __( 'General Settings', 'proof-of-work-captcha' ),
            array( $this, 'render_general_section' ),
            'pow-captcha'
        );

        add_settings_field(
            'pow_expiry_time',
            __( 'Challenge Expiry Time', 'proof-of-work-captcha' ),
            array( $this, 'render_expiry_time_field' ),
            'pow-captcha',
            'pow_general_section'
        );

        add_settings_field(
            'pow_interaction_mode',
            __( 'Challenge Trigger', 'proof-of-work-captcha' ),
            array( $this, 'render_interaction_mode_field' ),
            'pow-captcha',
            'pow_general_section'
        );

        add_settings_field(
            'pow_debug_progress',
            __( 'Debug Progress Report', 'proof-of-work-captcha' ),
            array( $this, 'render_debug_progress_field' ),
            'pow-captcha',
            'pow_general_section'
        );

        add_settings_field(
            PoW_Captcha_Early_Protection::OPTION_ENABLED,
            __( 'Lowest-resource URL Protection', 'proof-of-work-captcha' ),
            array( $this, 'render_early_protection_field' ),
            'pow-captcha',
            'pow_general_section'
        );

        // Section: Benchmark and calculator.
        add_settings_section(
            'pow_benchmark_section',
            __( 'Proof-of-Work Benchmark', 'proof-of-work-captcha' ),
            array( $this, 'render_benchmark_section' ),
            'pow-captcha'
        );

        // Section: Security Info.
        add_settings_section(
            'pow_security_section',
            __( 'Security Information', 'proof-of-work-captcha' ),
            '__return_false',
            'pow-captcha'
        );

        add_settings_field(
            'pow_secret_key_display',
            __( 'Secret Key', 'proof-of-work-captcha' ),
            array( $this, 'render_secret_key_field' ),
            'pow-captcha',
            'pow_security_section'
        );
    }

    /**
     * Sanitize protected forms option.
     *
     * @param mixed $input The input value.
     * @return array Sanitized array of allowed form types.
     */
    public function sanitize_protected_forms( $input ): array {
        $allowed = array( 'login', 'comment', 'register', 'woocommerce_login', 'woocommerce_register' );

        if ( ! is_array( $input ) ) {
            return array();
        }

        return array_values( array_intersect( $input, $allowed ) );
    }

    /** Enable/disable and install/remove the optional early gateway. */
    public function sanitize_early_protection( $input ): bool {
        return PoW_Captcha_Early_Protection::apply_setting( ! empty( $input ) );
    }

    /**
     * Sanitize URL patterns option.
     *
     * @param mixed $input The input value.
     * @return array Sanitized array of regex patterns.
     */
    public function sanitize_url_patterns( $input ): array {
        if ( is_array( $input ) ) {
            $patterns = $input;
        } elseif ( is_string( $input ) ) {
            $patterns = explode( "\n", $input );
        } else {
            return array();
        }

        $sanitized    = array();
        $invalid_rows = array();
        foreach ( $patterns as $index => $pattern ) {
            $pattern = trim( sanitize_text_field( $pattern ) );
            if ( '' !== $pattern ) {
                $error = null;
                if ( null === PoW_Captcha_URL_Protection::compile_pattern( $pattern, $error ) ) {
                    $invalid_rows[] = sprintf(
                        /* translators: 1: textarea line number, 2: regex compilation error. */
                        __( 'Line %1$d: %2$s', 'proof-of-work-captcha' ),
                        (int) $index + 1,
                        (string) $error
                    );
                    continue;
                }
                $sanitized[] = $pattern;
            }
        }

        if ( ! empty( $invalid_rows ) ) {
            add_settings_error(
                'pow_url_patterns',
                'pow_url_patterns_invalid',
                sprintf(
                    /* translators: %s: line-specific regular-expression errors. */
                    __( 'Invalid URL patterns were not saved: %s', 'proof-of-work-captcha' ),
                    implode( ' ', $invalid_rows )
                ),
                'warning'
            );
        }

        return $sanitized;
    }

    /**
     * Sanitize fine-grained difficulty value (0–140 inclusive).
     *
     * @param mixed $input The input value.
     * @return int Clamped difficulty.
     */
    public function sanitize_difficulty( $input ): int {
        $value = absint( $input );
        return max( PoW_Captcha_Challenge::MIN_DIFFICULTY, min( PoW_Captcha_Challenge::MAX_DIFFICULTY, $value ) );
    }

    /**
     * Sanitize expiry time value (30–3600 seconds inclusive).
     *
     * @param mixed $input The input value.
     * @return int Clamped expiry time in seconds.
     */
    public function sanitize_expiry_time( $input ): int {
        $value = absint( $input );
        return max( 30, min( 3600, $value ) );
    }

    /**
     * Sanitize the protected-URL query string limit.
     *
     * Zero disables blocking; enabled limits are kept within a practical range.
     *
     * @param mixed $input The input value.
     * @return int Query string byte limit.
     */
    public function sanitize_max_query_length( $input ): int {
        $value = absint( $input );
        return 0 === $value ? 0 : max( 128, min( 65535, $value ) );
    }

    /** Sanitize the browser interaction required before solving starts. */
    public function sanitize_interaction_mode( $input ): string {
        $allowed = array( 'automatic', 'mouse', 'checkbox' );
        $value   = sanitize_key( (string) $input );
        return in_array( $value, $allowed, true ) ? $value : 'automatic';
    }

    /** Sanitize the optional browser progress diagnostics setting. */
    public function sanitize_debug_progress( $input ): bool {
        return ! empty( $input );
    }

    /**
     * Render the general settings section description.
     */
    public function render_general_section() {
        echo '<p>' . esc_html__( 'General settings for the proof-of-work challenge system. Challenges and URL clearance are bound to the visitor IP.', 'proof-of-work-captcha' ) . '</p>';
        echo '<p>' . esc_html__( 'Cloudflare is detected securely from its official proxy ranges. If Cloudflare Tunnel or another trusted proxy hides the Cloudflare peer address, add that proxy CIDR with the pow_captcha_trusted_proxy_ranges filter.', 'proof-of-work-captcha' ) . '</p>';
    }

    /**
     * Render the expiry time field.
     */
    public function render_expiry_time_field() {
        $value = (int) get_option( 'pow_expiry_time', 300 );
        printf(
            '<input type="number" name="pow_expiry_time" value="%d" min="30" max="3600" step="10" class="small-text">',
            esc_attr( $value )
        );
        echo '<p class="description">' . esc_html__( 'Time in seconds before a challenge expires (30–3600). Default: 300 (5 minutes).', 'proof-of-work-captcha' ) . '</p>';
    }

    /** Render the challenge interaction mode selector. */
    public function render_interaction_mode_field() {
        $value = (string) get_option( 'pow_interaction_mode', 'automatic' );
        $modes = array(
            'automatic' => __( 'Automatic (no interaction required)', 'proof-of-work-captcha' ),
            'mouse'     => __( 'Mouse movement', 'proof-of-work-captcha' ),
            'checkbox'  => __( 'Click a verification checkbox', 'proof-of-work-captcha' ),
        );

        echo '<select name="pow_interaction_mode">';
        foreach ( $modes as $mode => $label ) {
            printf( '<option value="%1$s" %2$s>%3$s</option>', esc_attr( $mode ), selected( $value, $mode, false ), esc_html( $label ) );
        }
        echo '</select>';
        echo '<p class="description">' . esc_html__( 'Choose what must happen before proof-of-work begins. Mouse and checkbox modes accept only genuine browser-generated interaction events.', 'proof-of-work-captcha' ) . '</p>';
    }

    /** Render the optional live browser progress diagnostics setting. */
    public function render_debug_progress_field() {
        $enabled = (bool) get_option( 'pow_debug_progress', false );
        printf(
            '<label><input type="checkbox" name="pow_debug_progress" value="1" %1$s> %2$s</label>',
            esc_attr( checked( $enabled, true, false ) ),
            esc_html__( 'Show live attempts, hash rate, and elapsed time while solving', 'proof-of-work-captcha' )
        );
        echo '<p class="description">' . esc_html__( 'Disabled by default. Enable only when troubleshooting or benchmarking browser solves.', 'proof-of-work-captcha' ) . '</p>';
    }

    /** Render the optional advanced-cache gateway control and diagnostics. */
    public function render_early_protection_field() {
        $status  = PoW_Captcha_Early_Protection::status();
        $checked = $status['enabled'] ? 'checked' : '';
        $disabled = $status['foreign'] ? 'disabled' : '';

        printf(
            '<label><input type="checkbox" name="%1$s" value="1" %2$s %3$s> %4$s</label>',
            esc_attr( PoW_Captcha_Early_Protection::OPTION_ENABLED ),
            esc_attr( $checked ),
            esc_attr( $disabled ),
            esc_html__( 'Enable the advanced-cache gateway for protected URLs', 'proof-of-work-captcha' )
        );

        if ( $status['foreign'] ) {
            echo '<input type="hidden" name="' . esc_attr( PoW_Captcha_Early_Protection::OPTION_ENABLED ) . '" value="0">';
            echo '<p class="notice notice-warning inline"><strong>' . esc_html__( 'Unavailable:', 'proof-of-work-captcha' ) . '</strong> ' . esc_html__( 'Another advanced-cache.php drop-in already exists. Proof of Work Captcha will not overwrite it.', 'proof-of-work-captcha' ) . '</p>';
        } elseif ( $status['active'] ) {
            echo '<p class="notice notice-success inline"><strong>' . esc_html__( 'Active:', 'proof-of-work-captcha' ) . '</strong> ' . esc_html__( 'Unsolved protected URL requests are rejected before normal plugins and the theme load.', 'proof-of-work-captcha' ) . '</p>';
        } elseif ( $status['enabled'] && ! $status['wp_cache'] ) {
            echo '<p class="notice notice-warning inline"><strong>' . esc_html__( 'Setup incomplete:', 'proof-of-work-captcha' ) . '</strong> ' . esc_html__( 'The managed drop-in exists, but WP_CACHE must be set to true in wp-config.php.', 'proof-of-work-captcha' ) . '</p>';
        } elseif ( ! empty( $status['message'] ) ) {
            echo '<p class="description">' . esc_html( $status['message'] ) . '</p>';
        }

        echo '<p class="description">' . esc_html__( 'Optional. Uses WordPress advanced-cache.php to perform stateless URL challenge checks before ordinary plugins, the theme, routing, and the main query. Existing foreign cache drop-ins are never replaced.', 'proof-of-work-captcha' ) . '</p>';
    }

    /**
     * Render the form protection section description.
     */
    public function render_form_section() {
        echo '<p>' . esc_html__( 'Configure which forms should be protected by the proof-of-work challenge.', 'proof-of-work-captcha' ) . '</p>';
    }

    /**
     * Render the protected forms checkboxes.
     */
    public function render_protected_forms_field() {
        $current = get_option( 'pow_protected_forms', array() );
        if ( ! is_array( $current ) ) {
            $current = array();
        }

        $forms = array(
            'login'                => __( 'WordPress Login Form', 'proof-of-work-captcha' ),
            'comment'              => __( 'Comment Form', 'proof-of-work-captcha' ),
            'register'             => __( 'WordPress Registration Form', 'proof-of-work-captcha' ),
            'woocommerce_login'    => __( 'WooCommerce My Account Login', 'proof-of-work-captcha' ),
            'woocommerce_register' => __( 'WooCommerce My Account Registration', 'proof-of-work-captcha' ),
        );

        foreach ( $forms as $value => $label ) {
            $checked = in_array( $value, $current, true ) ? 'checked' : '';
            printf(
                '<label><input type="checkbox" name="pow_protected_forms[]" value="%s" %s> %s</label><br>',
                esc_attr( $value ),
                esc_attr( $checked ),
                esc_html( $label )
            );
        }
    }

    /**
     * Render the form difficulty field.
     */
    public function render_form_difficulty_field() {
        $value = (int) get_option( 'pow_form_difficulty', PoW_Captcha_Challenge::DEFAULT_DIFFICULTY );
        $this->render_difficulty_control( 'pow_form_difficulty', $value );
    }

    /**
     * Render the URL protection section description.
     */
    public function render_url_section() {
        echo '<p>' . esc_html__( 'Configure URL patterns to protect. Visitors must solve a proof-of-work challenge before accessing matching URLs.', 'proof-of-work-captcha' ) . '</p>';
    }

    /**
     * Render the URL patterns textarea field.
     */
    public function render_url_patterns_field() {
        $patterns = get_option( 'pow_url_patterns', array() );
        if ( ! is_array( $patterns ) ) {
            $patterns = array();
        }

        $value = implode( "\n", $patterns );

        printf(
            '<textarea name="pow_url_patterns" rows="6" cols="50" class="large-text">%s</textarea>',
            esc_textarea( $value )
        );
        echo '<p class="description">' . esc_html__( 'Enter one regular expression per line without regex delimiters. The plugin adds them automatically. Invalid lines are rejected with a warning when settings are saved.', 'proof-of-work-captcha' ) . '</p>';
        echo '<p class="description"><strong>' . esc_html__( 'Example:', 'proof-of-work-captcha' ) . '</strong> <code>^/\\?s=</code> ' . esc_html__( 'protects the WordPress search page.', 'proof-of-work-captcha' ) . '</p>';
    }

    /**
     * Render the URL difficulty field.
     */
    public function render_url_difficulty_field() {
        $value = (int) get_option( 'pow_url_difficulty', PoW_Captcha_Challenge::DEFAULT_DIFFICULTY );
        $this->render_difficulty_control( 'pow_url_difficulty', $value );
    }

    /** Render the maximum protected-URL query string length field. */
    public function render_max_query_length_field() {
        $value = (int) get_option( 'pow_max_query_length', 0 );
        printf(
            '<input type="number" name="pow_max_query_length" value="%d" min="0" max="65535" step="1" class="small-text">',
            esc_attr( $value )
        );
        echo '<p class="description">' . esc_html__( 'Block matching URLs with an HTTP 414 response when their raw query string exceeds this many bytes. Use 0 to disable. This applies only to URLs matching the patterns above and is checked before accepting a CAPTCHA clearance.', 'proof-of-work-captcha' ) . '</p>';
    }

    /** Render a synchronized slider/number difficulty control. */
    private function render_difficulty_control( string $name, int $value ) {
        $value = PoW_Captcha_Challenge::clamp_difficulty( $value );
        printf(
            '<div class="pow-difficulty-control" data-pow-difficulty-control><input type="range" value="%1$d" min="0" max="140" step="1" aria-label="%2$s"><input type="number" name="%3$s" value="%1$d" min="0" max="140" step="1" class="small-text" aria-label="%2$s"><strong class="pow-work-preview"></strong></div>',
            esc_attr( $value ),
            esc_attr__( 'Proof-of-work difficulty', 'proof-of-work-captcha' ),
            esc_attr( $name )
        );
        echo '<p class="description">' . esc_html__( 'Each step adds about 7.2 percent expected work. Difficulty 60 averages 65,536 attempts; use the benchmark below to estimate visitor wait times.', 'proof-of-work-captcha' ) . '</p>';
    }

    /** Render the interactive benchmark and processor estimate workspace. */
    public function render_benchmark_section() {
        ?>
        <p><?php esc_html_e( 'Measure the same JavaScript SHA-256 worker used by visitors, then test real solves. Results stay in this browser.', 'proof-of-work-captcha' ); ?></p>
        <div id="pow-benchmark" class="pow-benchmark-card" data-worker-url="<?php echo esc_url( add_query_arg( 'ver', POW_CAPTCHA_VERSION, plugin_dir_url( dirname( __FILE__ ) ) . 'assets/pow-worker.js' ) ); ?>">
            <div class="pow-benchmark-actions">
                <button type="button" class="button button-primary" id="pow-run-benchmark"><?php esc_html_e( 'Benchmark This Device', 'proof-of-work-captcha' ); ?></button>
                <label for="pow-test-difficulty"><?php esc_html_e( 'Test difficulty', 'proof-of-work-captcha' ); ?></label>
                <input type="number" id="pow-test-difficulty" value="60" min="0" max="140" step="1" class="small-text">
                <label for="pow-test-runs"><?php esc_html_e( 'Runs', 'proof-of-work-captcha' ); ?></label>
                <input type="number" id="pow-test-runs" value="3" min="1" max="10" step="1" class="small-text">
                <button type="button" class="button" id="pow-run-solves"><?php esc_html_e( 'Run Solve Test', 'proof-of-work-captcha' ); ?></button>
                <button type="button" class="button" id="pow-cancel-test" disabled><?php esc_html_e( 'Cancel', 'proof-of-work-captcha' ); ?></button>
            </div>
            <div class="pow-admin-progress" aria-hidden="true"><span></span></div>
            <p id="pow-benchmark-status" role="status" aria-live="polite"><?php esc_html_e( 'No benchmark has been run in this browser yet.', 'proof-of-work-captcha' ); ?></p>
            <div id="pow-solve-results"></div>
            <h3><?php esc_html_e( 'Estimated Solve Times by Processor Profile', 'proof-of-work-captcha' ); ?></h3>
            <p class="description"><?php esc_html_e( 'Profiles are JavaScript hash-rate references, not guarantees. Browser, power mode, temperature, and device load affect actual performance.', 'proof-of-work-captcha' ); ?></p>
            <div class="pow-table-scroll">
                <table class="widefat striped" id="pow-estimate-table">
                    <thead><tr><th><?php esc_html_e( 'Processor profile', 'proof-of-work-captcha' ); ?></th><th><?php esc_html_e( 'Hash rate', 'proof-of-work-captcha' ); ?></th><th><?php esc_html_e( 'Expected hashes', 'proof-of-work-captcha' ); ?></th><th><?php esc_html_e( 'Median', 'proof-of-work-captcha' ); ?></th><th><?php esc_html_e( 'Expected', 'proof-of-work-captcha' ); ?></th><th><?php esc_html_e( '95th percentile', 'proof-of-work-captcha' ); ?></th></tr></thead>
                    <tbody></tbody>
                </table>
            </div>
        </div>
        <?php
    }

    /**
     * Render the read-only secret key display.
     */
    public function render_secret_key_field() {
        $key = get_option( 'pow_secret_key', '' );
        if ( strlen( $key ) > 8 ) {
            $display = substr( $key, 0, 8 ) . '...';
        } else {
            $display = $key;
        }

        printf(
            '<code id="pow-secret-key-display">%s</code>',
            esc_html( $display )
        );
        echo ' <button type="button" id="pow-reset-secret-key" class="button button-secondary">' . esc_html__( 'Reset Secret Key', 'proof-of-work-captcha' ) . '</button>';
        echo '<p class="description">' . esc_html__( 'This key is generated on plugin activation and is used to sign challenges. Resetting the key will invalidate all existing challenges.', 'proof-of-work-captcha' ) . '</p>';
        ?>
        <script>
        jQuery(document).ready(function($) {
            $('#pow-reset-secret-key').on('click', function(e) {
                e.preventDefault();
                if (!confirm('<?php echo esc_js( __( 'Are you sure you want to reset the secret key? This will invalidate all existing challenges.', 'proof-of-work-captcha' ) ); ?>')) {
                    return;
                }
                var $btn = $(this);
                $btn.prop('disabled', true).text('<?php echo esc_js( __( 'Resetting…', 'proof-of-work-captcha' ) ); ?>');
                $.post(ajaxurl, {
                    action: 'pow_reset_secret_key',
                    _ajax_nonce: '<?php echo esc_js( wp_create_nonce( 'pow_reset_secret_key' ) ); ?>'
                }, function(response) {
                    if (response.success) {
                        $('#pow-secret-key-display').text(response.data.display_key);
                        alert('<?php echo esc_js( __( 'Secret key has been reset successfully.', 'proof-of-work-captcha' ) ); ?>');
                    } else {
                        alert(response.data.message || '<?php echo esc_js( __( 'Failed to reset secret key.', 'proof-of-work-captcha' ) ); ?>');
                    }
                }).fail(function() {
                    alert('<?php echo esc_js( __( 'An error occurred while resetting the secret key.', 'proof-of-work-captcha' ) ); ?>');
                }).always(function() {
                    $btn.prop('disabled', false).text('<?php echo esc_js( __( 'Reset Secret Key', 'proof-of-work-captcha' ) ); ?>');
                });
            });
        });
        </script>
        <?php
    }

    /** Load admin benchmark assets only on this settings screen. */
    public function enqueue_admin_assets( string $hook_suffix ) {
        if ( 'settings_page_pow-captcha' !== $hook_suffix ) {
            return;
        }

        $plugin_url = plugin_dir_url( dirname( __FILE__ ) );
        wp_enqueue_style( 'pow-captcha-admin', $plugin_url . 'assets/pow-admin.css', array(), POW_CAPTCHA_VERSION );
        wp_enqueue_script( 'pow-captcha-admin', $plugin_url . 'assets/pow-admin.js', array(), POW_CAPTCHA_VERSION, true );
        wp_localize_script( 'pow-captcha-admin', 'powAdminI18n', array(
            'notMeasured'           => __( 'Not measured', 'proof-of-work-captcha' ),
            /* translators: %1$s: approximate number of hashes. */
            'expectedHashesPreview' => __( '≈ %1$s expected hashes', 'proof-of-work-captcha' ),
            /* translators: %1$s: estimated duration. */
            'onThisBrowser'         => __( '%1$s on this browser', 'proof-of-work-captcha' ),
            'thisBrowser'           => __( 'This browser (measured)', 'proof-of-work-captcha' ),
            'lowEndMobile'          => __( 'Low-end mobile', 'proof-of-work-captcha' ),
            'typicalMobile'         => __( 'Typical mobile', 'proof-of-work-captcha' ),
            'typicalLaptop'         => __( 'Typical laptop', 'proof-of-work-captcha' ),
            'fastDesktop'           => __( 'Fast desktop', 'proof-of-work-captcha' ),
            'benchmarkingThroughput'=> __( 'Benchmarking SHA-256 throughput…', 'proof-of-work-captcha' ),
            /* translators: %1$s: number of hashes sampled. */
            'benchmarkingHashes'    => __( 'Benchmarking… %1$s hashes sampled', 'proof-of-work-captcha' ),
            /* translators: 1: measured hash rate, 2: number of sampled hashes. */
            'browserMeasured'       => __( 'This browser measured %1$s across %2$s hashes.', 'proof-of-work-captcha' ),
            'benchmarkFailed'       => __( 'Benchmark worker failed. Check browser worker support and try again.', 'proof-of-work-captcha' ),
            'solveWorkerFailed'     => __( 'Solve worker failed.', 'proof-of-work-captcha' ),
            'testCancelled'         => __( 'Test cancelled.', 'proof-of-work-captcha' ),
            /* translators: 1: current solve number, 2: total solves, 3: difficulty. */
            'solveAtDifficulty'     => __( 'Solve %1$s of %2$s at difficulty %3$s…', 'proof-of-work-captcha' ),
            /* translators: 1: current solve number, 2: total solves, 3: attempts, 4: elapsed time. */
            'solveProgress'         => __( 'Solve %1$s of %2$s: %3$s attempts · %4$s', 'proof-of-work-captcha' ),
            /* translators: 1: number of completed solves, 2: difficulty. */
            'completedSolves'       => __( 'Completed %1$s real solves at difficulty %2$s.', 'proof-of-work-captcha' ),
            'statistic'             => __( 'Statistic', 'proof-of-work-captcha' ),
            'solveTime'             => __( 'Solve time', 'proof-of-work-captcha' ),
            'minimum'               => __( 'Minimum', 'proof-of-work-captcha' ),
            'median'                => __( 'Median', 'proof-of-work-captcha' ),
            'average'               => __( 'Average', 'proof-of-work-captcha' ),
            'maximum'               => __( 'Maximum', 'proof-of-work-captcha' ),
            'totalAttempts'         => __( 'Total attempts', 'proof-of-work-captcha' ),
            'observedHashRate'      => __( 'Observed hash rate', 'proof-of-work-captcha' ),
            'solveTestFailed'       => __( 'Solve test failed.', 'proof-of-work-captcha' ),
            /* translators: %1$s: previously measured browser hash rate. */
            'savedBenchmark'        => __( 'Saved browser benchmark: %1$s. Run again to refresh it.', 'proof-of-work-captcha' ),
        ) );
    }

    /**
     * AJAX handler to reset the secret key.
     */
    public function ajax_reset_secret_key() {
        check_ajax_referer( 'pow_reset_secret_key' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array( 'message' => __( 'You do not have permission to perform this action.', 'proof-of-work-captcha' ) ) );
        }

        $new_key = bin2hex( random_bytes( 32 ) );
        update_option( 'pow_secret_key', $new_key );

        if ( strlen( $new_key ) > 8 ) {
            $display = substr( $new_key, 0, 8 ) . '...';
        } else {
            $display = $new_key;
        }

        wp_send_json_success( array( 'display_key' => $display ) );
    }

    /**
     * Render the settings page.
     */
    public function render_settings_page() {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        ?>
        <div class="wrap">
            <h1><?php echo esc_html( get_admin_page_title() ); ?></h1>
            <form method="post" action="options.php">
                <?php
                settings_fields( 'pow_captcha_group' );
                do_settings_sections( 'pow-captcha' );
                submit_button();
                ?>
            </form>
        </div>
        <?php
    }
}
