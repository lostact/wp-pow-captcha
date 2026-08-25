<?php
/**
 * Admin class: settings page for WP PoW Captcha.
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
            __( 'PoW Captcha', 'wp-pow-captcha' ),
            __( 'PoW Captcha', 'wp-pow-captcha' ),
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

        // Section: Form Protection.
        add_settings_section(
            'pow_form_section',
            __( 'Form Protection', 'wp-pow-captcha' ),
            array( $this, 'render_form_section' ),
            'pow-captcha'
        );

        add_settings_field(
            'pow_protected_forms',
            __( 'Protected Forms', 'wp-pow-captcha' ),
            array( $this, 'render_protected_forms_field' ),
            'pow-captcha',
            'pow_form_section'
        );

        add_settings_field(
            'pow_form_difficulty',
            __( 'Form Difficulty', 'wp-pow-captcha' ),
            array( $this, 'render_form_difficulty_field' ),
            'pow-captcha',
            'pow_form_section'
        );

        // Section: URL Protection.
        add_settings_section(
            'pow_url_section',
            __( 'URL Protection', 'wp-pow-captcha' ),
            array( $this, 'render_url_section' ),
            'pow-captcha'
        );

        add_settings_field(
            'pow_url_patterns',
            __( 'URL Patterns', 'wp-pow-captcha' ),
            array( $this, 'render_url_patterns_field' ),
            'pow-captcha',
            'pow_url_section'
        );

        add_settings_field(
            'pow_url_difficulty',
            __( 'URL Difficulty', 'wp-pow-captcha' ),
            array( $this, 'render_url_difficulty_field' ),
            'pow-captcha',
            'pow_url_section'
        );

        // Section: General Settings.
        add_settings_section(
            'pow_general_section',
            __( 'General Settings', 'wp-pow-captcha' ),
            array( $this, 'render_general_section' ),
            'pow-captcha'
        );

        add_settings_field(
            'pow_expiry_time',
            __( 'Challenge Expiry Time', 'wp-pow-captcha' ),
            array( $this, 'render_expiry_time_field' ),
            'pow-captcha',
            'pow_general_section'
        );

        // Section: Benchmark and calculator.
        add_settings_section(
            'pow_benchmark_section',
            __( 'Proof-of-Work Benchmark', 'wp-pow-captcha' ),
            array( $this, 'render_benchmark_section' ),
            'pow-captcha'
        );

        // Section: Security Info.
        add_settings_section(
            'pow_security_section',
            __( 'Security Information', 'wp-pow-captcha' ),
            '__return_false',
            'pow-captcha'
        );

        add_settings_field(
            'pow_secret_key_display',
            __( 'Secret Key', 'wp-pow-captcha' ),
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
        $allowed = array( 'login', 'comment', 'register' );

        if ( ! is_array( $input ) ) {
            return array();
        }

        return array_values( array_intersect( $input, $allowed ) );
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

        $sanitized = array();
        foreach ( $patterns as $pattern ) {
            $pattern = trim( sanitize_text_field( $pattern ) );
            if ( '' !== $pattern ) {
                $sanitized[] = $pattern;
            }
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
     * Render the general settings section description.
     */
    public function render_general_section() {
        echo '<p>' . esc_html__( 'General settings for the proof-of-work challenge system.', 'wp-pow-captcha' ) . '</p>';
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
        echo '<p class="description">' . esc_html__( 'Time in seconds before a challenge expires (30–3600). Default: 300 (5 minutes).', 'wp-pow-captcha' ) . '</p>';
    }

    /**
     * Render the form protection section description.
     */
    public function render_form_section() {
        echo '<p>' . esc_html__( 'Configure which forms should be protected by the proof-of-work challenge.', 'wp-pow-captcha' ) . '</p>';
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
            'login'    => __( 'Login Form', 'wp-pow-captcha' ),
            'comment'  => __( 'Comment Form', 'wp-pow-captcha' ),
            'register' => __( 'Registration Form', 'wp-pow-captcha' ),
        );

        foreach ( $forms as $value => $label ) {
            $checked = in_array( $value, $current, true ) ? 'checked' : '';
            printf(
                '<label><input type="checkbox" name="pow_protected_forms[]" value="%s" %s> %s</label><br>',
                esc_attr( $value ),
                $checked,
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
        echo '<p>' . esc_html__( 'Configure URL patterns to protect. Visitors must solve a proof-of-work challenge before accessing matching URLs.', 'wp-pow-captcha' ) . '</p>';
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
        echo '<p class="description">' . esc_html__( 'Enter one PHP-compatible regex pattern per line. These patterns are tested against the request URI using preg_match().', 'wp-pow-captcha' ) . '</p>';
        echo '<p class="description"><strong>' . esc_html__( 'Example:', 'wp-pow-captcha' ) . '</strong> <code>/\\?s=/</code> ' . esc_html__( 'protects the WordPress search page.', 'wp-pow-captcha' ) . '</p>';
    }

    /**
     * Render the URL difficulty field.
     */
    public function render_url_difficulty_field() {
        $value = (int) get_option( 'pow_url_difficulty', PoW_Captcha_Challenge::DEFAULT_DIFFICULTY );
        $this->render_difficulty_control( 'pow_url_difficulty', $value );
    }

    /** Render a synchronized slider/number difficulty control. */
    private function render_difficulty_control( string $name, int $value ) {
        $value = PoW_Captcha_Challenge::clamp_difficulty( $value );
        printf(
            '<div class="pow-difficulty-control" data-pow-difficulty-control><input type="range" value="%1$d" min="0" max="140" step="1" aria-label="%2$s"><input type="number" name="%3$s" value="%1$d" min="0" max="140" step="1" class="small-text" aria-label="%2$s"><strong class="pow-work-preview"></strong></div>',
            esc_attr( $value ),
            esc_attr__( 'Proof-of-work difficulty', 'wp-pow-captcha' ),
            esc_attr( $name )
        );
        echo '<p class="description">' . esc_html__( 'Each step adds about 7.2% expected work. Difficulty 60 averages 65,536 attempts; use the benchmark below to estimate visitor wait times.', 'wp-pow-captcha' ) . '</p>';
    }

    /** Render the interactive benchmark and processor estimate workspace. */
    public function render_benchmark_section() {
        ?>
        <p><?php esc_html_e( 'Measure the same JavaScript SHA-256 worker used by visitors, then test real solves. Results stay in this browser.', 'wp-pow-captcha' ); ?></p>
        <div id="pow-benchmark" class="pow-benchmark-card" data-worker-url="<?php echo esc_url( add_query_arg( 'ver', '2.0.0', plugin_dir_url( dirname( __FILE__ ) ) . 'assets/pow-worker.js' ) ); ?>">
            <div class="pow-benchmark-actions">
                <button type="button" class="button button-primary" id="pow-run-benchmark"><?php esc_html_e( 'Benchmark This Device', 'wp-pow-captcha' ); ?></button>
                <label for="pow-test-difficulty"><?php esc_html_e( 'Test difficulty', 'wp-pow-captcha' ); ?></label>
                <input type="number" id="pow-test-difficulty" value="60" min="0" max="140" step="1" class="small-text">
                <label for="pow-test-runs"><?php esc_html_e( 'Runs', 'wp-pow-captcha' ); ?></label>
                <input type="number" id="pow-test-runs" value="3" min="1" max="10" step="1" class="small-text">
                <button type="button" class="button" id="pow-run-solves"><?php esc_html_e( 'Run Solve Test', 'wp-pow-captcha' ); ?></button>
                <button type="button" class="button" id="pow-cancel-test" disabled><?php esc_html_e( 'Cancel', 'wp-pow-captcha' ); ?></button>
            </div>
            <div class="pow-admin-progress" aria-hidden="true"><span></span></div>
            <p id="pow-benchmark-status" role="status" aria-live="polite"><?php esc_html_e( 'No benchmark has been run in this browser yet.', 'wp-pow-captcha' ); ?></p>
            <div id="pow-solve-results"></div>
            <h3><?php esc_html_e( 'Estimated Solve Times by Processor Profile', 'wp-pow-captcha' ); ?></h3>
            <p class="description"><?php esc_html_e( 'Profiles are JavaScript hash-rate references, not guarantees. Browser, power mode, temperature, and device load affect actual performance.', 'wp-pow-captcha' ); ?></p>
            <div class="pow-table-scroll">
                <table class="widefat striped" id="pow-estimate-table">
                    <thead><tr><th><?php esc_html_e( 'Processor profile', 'wp-pow-captcha' ); ?></th><th><?php esc_html_e( 'Hash rate', 'wp-pow-captcha' ); ?></th><th><?php esc_html_e( 'Expected hashes', 'wp-pow-captcha' ); ?></th><th><?php esc_html_e( 'Median', 'wp-pow-captcha' ); ?></th><th><?php esc_html_e( 'Expected', 'wp-pow-captcha' ); ?></th><th><?php esc_html_e( '95th percentile', 'wp-pow-captcha' ); ?></th></tr></thead>
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
        echo ' <button type="button" id="pow-reset-secret-key" class="button button-secondary">' . esc_html__( 'Reset Secret Key', 'wp-pow-captcha' ) . '</button>';
        echo '<p class="description">' . esc_html__( 'This key is generated on plugin activation and is used to sign challenges. Resetting the key will invalidate all existing challenges.', 'wp-pow-captcha' ) . '</p>';
        ?>
        <script>
        jQuery(document).ready(function($) {
            $('#pow-reset-secret-key').on('click', function(e) {
                e.preventDefault();
                if (!confirm('<?php echo esc_js( __( 'Are you sure you want to reset the secret key? This will invalidate all existing challenges.', 'wp-pow-captcha' ) ); ?>')) {
                    return;
                }
                var $btn = $(this);
                $btn.prop('disabled', true).text('<?php echo esc_js( __( 'Resetting…', 'wp-pow-captcha' ) ); ?>');
                $.post(ajaxurl, {
                    action: 'pow_reset_secret_key',
                    _ajax_nonce: '<?php echo esc_js( wp_create_nonce( 'pow_reset_secret_key' ) ); ?>'
                }, function(response) {
                    if (response.success) {
                        $('#pow-secret-key-display').text(response.data.display_key);
                        alert('<?php echo esc_js( __( 'Secret key has been reset successfully.', 'wp-pow-captcha' ) ); ?>');
                    } else {
                        alert(response.data.message || '<?php echo esc_js( __( 'Failed to reset secret key.', 'wp-pow-captcha' ) ); ?>');
                    }
                }).fail(function() {
                    alert('<?php echo esc_js( __( 'An error occurred while resetting the secret key.', 'wp-pow-captcha' ) ); ?>');
                }).always(function() {
                    $btn.prop('disabled', false).text('<?php echo esc_js( __( 'Reset Secret Key', 'wp-pow-captcha' ) ); ?>');
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
        wp_enqueue_style( 'pow-captcha-admin', $plugin_url . 'assets/pow-admin.css', array(), '2.0.0' );
        wp_enqueue_script( 'pow-captcha-admin', $plugin_url . 'assets/pow-admin.js', array(), '2.0.0', true );
    }

    /**
     * AJAX handler to reset the secret key.
     */
    public function ajax_reset_secret_key() {
        check_ajax_referer( 'pow_reset_secret_key' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array( 'message' => __( 'You do not have permission to perform this action.', 'wp-pow-captcha' ) ) );
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
