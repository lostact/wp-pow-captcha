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
            add_filter( 'authenticate', array( $this, 'verify_login' ), 30, 3 );
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

        // Enqueue front-end assets when any form protection is active.
        if ( ! empty( $protected_forms ) ) {
            add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_assets' ) );
        }
    }

    /**
     * Enqueue solver scripts on front-end and login pages.
     */
    public function enqueue_assets() {
        $plugin_url = plugin_dir_url( dirname( __FILE__ ) );

        wp_enqueue_script(
            'pow-solver',
            $plugin_url . 'assets/pow-solver.js',
            array(),
            '1.0.0',
            true
        );

        wp_localize_script( 'pow-solver', 'powConfig', array(
            'workerUrl' => $plugin_url . 'assets/pow-worker.js',
        ) );
    }

    /**
     * Inject hidden PoW challenge fields into a form.
     */
    public function inject_hidden_fields() {
        $difficulty     = (int) get_option( 'pow_form_difficulty', 4 );
        $difficulty     = max( 1, min( 8, $difficulty ) );
        $challenge_data = $this->challenge->generate( $difficulty );
        ?>
        <div class="pow-captcha"
             data-challenge="<?php echo esc_attr( $challenge_data['challenge'] ); ?>"
             data-expires="<?php echo esc_attr( $challenge_data['expires'] ); ?>"
             data-difficulty="<?php echo esc_attr( $challenge_data['difficulty'] ); ?>"
             data-sig="<?php echo esc_attr( $challenge_data['signature'] ); ?>">
            <input type="hidden" name="_pow_challenge" value="<?php echo esc_attr( $challenge_data['challenge'] ); ?>">
            <input type="hidden" name="_pow_expires" value="<?php echo esc_attr( $challenge_data['expires'] ); ?>">
            <input type="hidden" name="_pow_difficulty" value="<?php echo esc_attr( $challenge_data['difficulty'] ); ?>">
            <input type="hidden" name="_pow_sig" value="<?php echo esc_attr( $challenge_data['signature'] ); ?>">
            <input type="hidden" name="_pow_solution" id="pow_solution_field" value="">
            <p class="pow-status">Running security check…</p>
        </div>
        <?php
    }

    /**
     * Verify PoW fields from POST data.
     *
     * @return bool True if verification passes, false otherwise.
     */
    public function verify_from_post(): bool {
        if ( ! isset( $_POST['_pow_challenge'], $_POST['_pow_expires'], $_POST['_pow_difficulty'], $_POST['_pow_sig'], $_POST['_pow_solution'] ) ) {
            return false;
        }

        $challenge  = sanitize_text_field( wp_unslash( $_POST['_pow_challenge'] ) );
        $expires    = (int) $_POST['_pow_expires'];
        $difficulty = (int) $_POST['_pow_difficulty'];
        $sig        = sanitize_text_field( wp_unslash( $_POST['_pow_sig'] ) );
        $solution   = sanitize_text_field( wp_unslash( $_POST['_pow_solution'] ) );

        if ( ! ctype_digit( $solution ) ) {
            return false;
        }

        return $this->challenge->verify( $challenge, $expires, $difficulty, $sig, $solution );
    }

    /**
     * Verify login form submission.
     *
     * @param WP_Error|WP_User|null $user     The authenticated user or error.
     * @param string                 $username The username.
     * @param string                 $password The password.
     * @return WP_Error|WP_User|null
     */
    public function verify_login( $user, string $username, string $password ) {
        if ( empty( $username ) ) {
            return $user;
        }

        if ( ! $this->verify_from_post() ) {
            return new WP_Error( 'pow_failed', __( 'Security check failed. Please go back and try again.', 'wp-pow-captcha' ) );
        }

        return $user;
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
                __( 'Security check failed. Please go back and try again.', 'wp-pow-captcha' ),
                __( 'Security Check Failed', 'wp-pow-captcha' ),
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
            $errors->add( 'pow_failed', __( 'Security check failed. Please go back and try again.', 'wp-pow-captcha' ) );
        }

        return $errors;
    }
}
