<?php
/**
 * Form Protection class: injects PoW challenge fields into forms and verifies submissions.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class PoW_Captcha_Form_Protection {

    /**
     * @var PoW_Captcha_Challenge
     */
    private $challenge;

    /** @var WP_Error|null Cached fail-fast login PoW error for this request. */
    private $login_pow_error = null;

    /**
     * Constructor.
     *
     * @param PoW_Captcha_Challenge $challenge Challenge instance.
     */
    public function __construct( PoW_Captcha_Challenge $challenge ) {
        $this->challenge = $challenge;

        $protected_forms = get_option( 'pow_protected_forms', array() );

        if ( ! is_array( $protected_forms ) ) {
            $protected_forms = array();
        }

        if ( in_array( 'login', $protected_forms, true ) ) {
            add_action( 'login_form', array( $this, 'inject_hidden_fields' ) );
            add_filter( 'authenticate', array( $this, 'verify_login_early' ), 5, 3 );
            add_filter( 'authenticate', array( $this, 'enforce_login_pow_result' ), PHP_INT_MAX, 3 );
            add_action( 'login_enqueue_scripts', array( $this, 'enqueue_assets' ) );
        }

        if ( in_array( 'comment', $protected_forms, true ) ) {
            add_action( 'comment_form', array( $this, 'inject_hidden_fields' ) );
            add_filter( 'preprocess_comment', array( $this, 'verify_comment' ) );
        }

        if ( in_array( 'register', $protected_forms, true ) ) {
            add_action( 'register_form', array( $this, 'inject_hidden_fields' ) );
            add_filter( 'registration_errors', array( $this, 'verify_registration' ), 10, 3 );
            add_action( 'login_enqueue_scripts', array( $this, 'enqueue_assets' ) );
        }

        // Enqueue front-end assets and expose a deliberately uncached challenge
        // endpoint when any form protection is active.
        if ( ! empty( $protected_forms ) ) {
            add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_assets' ) );
            add_action( 'wp_ajax_nopriv_pow_captcha_challenge', array( $this, 'ajax_generate_challenge' ) );
            add_action( 'wp_ajax_pow_captcha_challenge', array( $this, 'ajax_generate_challenge' ) );
        }
    }

    /**
     * Enqueue solver scripts on front-end and login pages.
     */
    public function enqueue_assets() {
        $plugin_url = plugin_dir_url( dirname( __FILE__ ) );

        if ( pow_captcha_is_persian() ) {
            wp_enqueue_style(
                'pow-captcha-vazirmatn',
                'https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700&display=swap',
                array(),
                POW_CAPTCHA_VERSION
            );
        }

        wp_enqueue_style(
            'pow-captcha',
            $plugin_url . 'assets/pow-captcha.css',
            array(),
            POW_CAPTCHA_VERSION
        );

        wp_enqueue_script(
            'pow-solver',
            $plugin_url . 'assets/pow-solver.js',
            array(),
            POW_CAPTCHA_VERSION,
            true
        );

        wp_localize_script( 'pow-solver', 'powConfig', array(
            'workerUrl'       => add_query_arg( 'ver', POW_CAPTCHA_VERSION, $plugin_url . 'assets/pow-worker.js' ),
            'challengeUrl'    => admin_url( 'admin-ajax.php?action=pow_captcha_challenge' ),
            'interactionMode' => (string) get_option( 'pow_interaction_mode', 'automatic' ),
            'debugProgress'   => (bool) get_option( 'pow_debug_progress', false ),
        ) );
        wp_localize_script( 'pow-solver', 'powI18n', pow_captcha_frontend_translations() );
    }

    /**
     * Inject hidden PoW challenge fields into a form.
     */
    public function inject_hidden_fields() {
        ?>
        <div class="pow-captcha" data-pow-state="loading" dir="<?php echo esc_attr( pow_captcha_text_direction() ); ?>">
            <input type="hidden" name="_pow_challenge" value="">
            <input type="hidden" name="_pow_expires" value="">
            <input type="hidden" name="_pow_difficulty" value="">
            <input type="hidden" name="_pow_version" value="">
            <input type="hidden" name="_pow_algorithm" value="">
            <input type="hidden" name="_pow_sig" value="">
            <input type="hidden" name="_pow_solution" value="">
            <?php wp_nonce_field( 'pow_captcha_form', '_pow_nonce', false ); ?>
            <div class="pow-progress" role="progressbar" aria-label="<?php esc_attr_e( 'Security check in progress', 'proof-of-work-captcha' ); ?>" aria-busy="true"><span></span></div>
            <p class="pow-status" role="status" aria-live="polite"><?php esc_html_e( 'Preparing security check…', 'proof-of-work-captcha' ); ?></p>
            <p class="pow-details" hidden><?php esc_html_e( 'Requesting a fresh challenge…', 'proof-of-work-captcha' ); ?></p>
        </div>
        <?php
    }

    /**
     * Verify PoW fields from POST data.
     *
     * @return bool True if verification passes, false otherwise.
     */
    public function verify_from_post(): bool {
        if ( ! isset( $_POST['_pow_nonce'], $_POST['_pow_challenge'], $_POST['_pow_expires'], $_POST['_pow_difficulty'], $_POST['_pow_version'], $_POST['_pow_algorithm'], $_POST['_pow_sig'], $_POST['_pow_solution'] ) ) {
            return false;
        }

        $nonce = sanitize_text_field( wp_unslash( $_POST['_pow_nonce'] ) );
        if ( ! wp_verify_nonce( $nonce, 'pow_captcha_form' ) ) {
            return false;
        }

        $challenge  = sanitize_text_field( wp_unslash( $_POST['_pow_challenge'] ) );
        $expires    = absint( wp_unslash( $_POST['_pow_expires'] ) );
        $difficulty = absint( wp_unslash( $_POST['_pow_difficulty'] ) );
        $version    = absint( wp_unslash( $_POST['_pow_version'] ) );
        $algorithm  = sanitize_text_field( wp_unslash( $_POST['_pow_algorithm'] ) );
        $sig        = sanitize_text_field( wp_unslash( $_POST['_pow_sig'] ) );
        $solution   = sanitize_text_field( wp_unslash( $_POST['_pow_solution'] ) );

        if ( PoW_Captcha_Challenge::VERSION !== $version || ! ctype_digit( $solution ) ) {
            return false;
        }

        return $this->challenge->verify( $challenge, $expires, $difficulty, $sig, $solution, $version, $algorithm );
    }

    /** Generate a fresh, explicitly non-cacheable form challenge. */
    public function ajax_generate_challenge() {
        nocache_headers();
        header( 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0' );
        header( 'Pragma: no-cache' );

        $difficulty = (int) get_option( 'pow_form_difficulty', PoW_Captcha_Challenge::DEFAULT_DIFFICULTY );
        $challenge  = $this->challenge->generate( PoW_Captcha_Challenge::clamp_difficulty( $difficulty ) );

        wp_send_json_success( $challenge );
    }

    /**
     * Reject invalid PoW before WordPress performs password hashing.
     *
     * Core's priority-20 callbacks do not preserve a prior WP_Error for a
     * non-empty username, so they are removed only for this failed request.
     *
     * @param WP_Error|WP_User|null $user     Current authentication result.
     * @param string                 $username Login name or email.
     * @param string                 $password Password.
     * @return WP_Error|WP_User|null
     */
    public function verify_login_early( $user, string $username, string $password ) {
        if ( empty( $username ) || empty( $password ) || $this->verify_from_post() ) {
            return $user;
        }

        $this->login_pow_error = new WP_Error( 'pow_failed', __( 'Security check failed. Please go back and try again.', 'proof-of-work-captcha' ) );

        remove_filter( 'authenticate', 'wp_authenticate_username_password', 20 );
        remove_filter( 'authenticate', 'wp_authenticate_email_password', 20 );

        return $this->login_pow_error;
    }

    /** Ensure no later authentication provider can overwrite a PoW failure. */
    public function enforce_login_pow_result( $user, string $username, string $password ) {
        return $this->login_pow_error instanceof WP_Error ? $this->login_pow_error : $user;
    }

    /**
     * Verify comment form submission.
     *
     * @param array $commentdata The comment data array.
     * @return array
     */
    public function verify_comment( array $commentdata ): array {
        if ( ! $this->verify_from_post() ) {
            wp_die(
                esc_html__( 'Security check failed. Please go back and try again.', 'proof-of-work-captcha' ),
                esc_html__( 'Security Check Failed', 'proof-of-work-captcha' ),
                array( 'back_link' => true )
            );
        }

        return $commentdata;
    }

    /**
     * Verify registration form submission.
     *
     * @param WP_Error $errors   Registration errors.
     * @param string   $login    The login name.
     * @param string   $email    The email address.
     * @return WP_Error
     */
    public function verify_registration( WP_Error $errors, string $login, string $email ): WP_Error {
        if ( ! $this->verify_from_post() ) {
            $errors->add( 'pow_failed', __( 'Security check failed. Please go back and try again.', 'proof-of-work-captcha' ) );
        }

        return $errors;
    }
}
