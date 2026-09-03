<?php
/**
 * Plugin Name: Proof-of-Work Firewall
 * Description: Protects configurable URLs and forms using a proof-of-work challenge system. No external dependencies, no third-party CAPTCHA services.
 * Version: 2.5.13
 * Author: lostact
 * License: GPL-2.0-or-later
 * Text Domain: proof-of-work-firewall
 * Requires at least: 5.8
 * Requires PHP: 7.4
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

define( 'POW_FIREWALL_VERSION', '2.5.13' );

/** Migrate legacy option names without losing existing settings. */
function pow_firewall_migrate_legacy_options(): void {
    $legacy_options = array(
        'pow_secret_key'                      => 'pow_firewall_secret_key',
        'pow_protected_forms'                 => 'pow_firewall_protected_forms',
        'pow_url_patterns'                    => 'pow_firewall_url_patterns',
        'pow_form_difficulty'                 => 'pow_firewall_form_difficulty',
        'pow_url_difficulty'                  => 'pow_firewall_url_difficulty',
        'pow_max_query_length'                => 'pow_firewall_max_query_length',
        'pow_interaction_mode'                => 'pow_firewall_interaction_mode',
        'pow_debug_progress'                  => 'pow_firewall_debug_progress',
        'pow_difficulty_schema'               => 'pow_firewall_difficulty_schema',
        'pow_expiry_time'                     => 'pow_firewall_expiry_time',
        'pow_early_protection_enabled'        => 'pow_firewall_early_protection_enabled',
        'pow_early_protection_status'         => 'pow_firewall_early_protection_status',
        'pow_early_protection_config_version' => 'pow_firewall_early_protection_config_version',
    );
    $missing = new stdClass();

    foreach ( $legacy_options as $legacy_name => $new_name ) {
        $legacy_value = get_option( $legacy_name, $missing );
        if ( $missing !== $legacy_value && $missing === get_option( $new_name, $missing ) ) {
            add_option( $new_name, $legacy_value, '', 'no' );
        }
        if ( $missing !== $legacy_value ) {
            delete_option( $legacy_name );
        }
    }
}
add_action( 'plugins_loaded', 'pow_firewall_migrate_legacy_options', 1 );

/** Return the correct writing direction, with an explicit Persian fallback. */
function pow_firewall_text_direction(): string {
    $locale = function_exists( 'determine_locale' ) ? determine_locale() : get_locale();
    return is_rtl() || 1 === preg_match( '/^(fa|ar|he|ur)(?:_|-)/i', (string) $locale ) ? 'rtl' : 'ltr';
}

/** Whether the active request locale is Persian. */
function pow_firewall_is_persian(): bool {
    $locale = function_exists( 'determine_locale' ) ? determine_locale() : get_locale();
    return 1 === preg_match( '/^fa(?:_|-)/i', (string) $locale );
}

/** Return translated strings shared by standard and early browser solvers. */
function pow_firewall_frontend_translations(): array {
    return array(
        'measuring'               => __( 'measuring…', 'proof-of-work-firewall' ),
        'workerStartError'        => __( 'Unable to start the security worker.', 'proof-of-work-firewall' ),
        'checkRunError'           => __( 'The security check could not run.', 'proof-of-work-firewall' ),
        'browserError'            => __( 'The security check encountered a browser error. Please reload and try again.', 'proof-of-work-firewall' ),
        'inProgress'              => __( 'Security check in progress…', 'proof-of-work-firewall' ),
        'moveMouse'               => __( 'Move your mouse to begin the security check.', 'proof-of-work-firewall' ),
        'waitingInteraction'      => __( 'Waiting for genuine user interaction…', 'proof-of-work-firewall' ),
        'startsAfterConfirmation' => __( 'The proof-of-work check starts after confirmation.', 'proof-of-work-firewall' ),
        'verifyHuman'             => __( 'Verify you are human', 'proof-of-work-firewall' ),
        'workerNotConfigured'     => __( 'Error: security worker is not configured.', 'proof-of-work-firewall' ),
        'startingCheck'           => __( 'Starting security check…', 'proof-of-work-firewall' ),
        'startingWorker'          => __( 'Starting secure worker…', 'proof-of-work-firewall' ),
        'completeRedirecting'     => __( 'Security check complete. Redirecting…', 'proof-of-work-firewall' ),
        'passed'                  => __( 'Security check passed', 'proof-of-work-firewall' ),
        'preparing'               => __( 'Preparing security check…', 'proof-of-work-firewall' ),
        'requestingChallenge'     => __( 'Requesting a fresh challenge…', 'proof-of-work-firewall' ),
        'unableToStart'           => __( 'Unable to start the security check. Reload the page and try again.', 'proof-of-work-firewall' ),
        'challengeRequestFailed'  => __( 'The fresh challenge request failed.', 'proof-of-work-firewall' ),
        'serviceNotConfigured'    => __( 'Security challenge service is not configured.', 'proof-of-work-firewall' ),
        'failedReload'            => __( 'Security check failed. Reload the page and try again.', 'proof-of-work-firewall' ),
        'stillPreparing'          => __( 'Please wait; the security check is still preparing or running…', 'proof-of-work-firewall' ),
    );
}

register_activation_hook( __FILE__, 'pow_firewall_activate' );
register_deactivation_hook( __FILE__, 'pow_firewall_deactivate' );

/**
 * Activation hook: generate and store the secret key if it doesn't exist.
 */
function pow_firewall_activate() {
    pow_firewall_migrate_legacy_options();
    if ( false === get_option( 'pow_firewall_secret_key' ) ) {
        $key = bin2hex( random_bytes( 32 ) );
        add_option( 'pow_firewall_secret_key', $key );
    }
    // Set defaults for options if they don't exist.
    if ( false === get_option( 'pow_firewall_protected_forms' ) ) {
        add_option( 'pow_firewall_protected_forms', array() );
    }
    if ( false === get_option( 'pow_firewall_url_patterns' ) ) {
        add_option( 'pow_firewall_url_patterns', array() );
    }
    if ( false === get_option( 'pow_firewall_form_difficulty' ) ) {
        add_option( 'pow_firewall_form_difficulty', 60 );
    }
    if ( false === get_option( 'pow_firewall_url_difficulty' ) ) {
        add_option( 'pow_firewall_url_difficulty', 60 );
    }
    if ( false === get_option( 'pow_firewall_max_query_length' ) ) {
        add_option( 'pow_firewall_max_query_length', 0 );
    }
    if ( false === get_option( 'pow_firewall_interaction_mode' ) ) {
        add_option( 'pow_firewall_interaction_mode', 'automatic' );
    }
    if ( false === get_option( 'pow_firewall_debug_progress' ) ) {
        add_option( 'pow_firewall_debug_progress', false );
    }
    if ( false === get_option( 'pow_firewall_difficulty_schema' ) ) {
        add_option( 'pow_firewall_difficulty_schema', 2 );
    }
    if ( false === get_option( 'pow_firewall_expiry_time' ) ) {
        add_option( 'pow_firewall_expiry_time', 300 );
    }
    if ( false === get_option( 'pow_firewall_early_protection_enabled' ) ) {
        add_option( 'pow_firewall_early_protection_enabled', false, '', false );
    }

    // Restore the optional early gateway after a plugin reactivation.
    if ( get_option( 'pow_firewall_early_protection_enabled', false ) ) {
        require_once plugin_dir_path( __FILE__ ) . 'includes/class-challenge.php';
        require_once plugin_dir_path( __FILE__ ) . 'includes/class-early-protection.php';
        PoW_Firewall_Early_Protection::install();
    }
}

/**
 * Deactivation hook: do nothing so settings persist.
 */
function pow_firewall_deactivate() {
    // The preference persists, but executable bootstrap files must not remain
    // active while the normal plugin is deactivated.
    require_once plugin_dir_path( __FILE__ ) . 'includes/class-challenge.php';
    require_once plugin_dir_path( __FILE__ ) . 'includes/class-early-protection.php';
    PoW_Firewall_Early_Protection::uninstall();
}

/**
 * Instantiate all plugin classes after plugins_loaded.
 */
add_action( 'plugins_loaded', 'pow_firewall_init' );

function pow_firewall_init() {
    require_once plugin_dir_path( __FILE__ ) . 'includes/class-challenge.php';

    // Migrate legacy 1–8 hexadecimal-zero settings exactly once. The approved
    // mapping keeps old level 4 at the new default while compressing the old
    // scale's impractically large 16x jumps into useful fine-grained values.
    if ( 2 !== (int) get_option( 'pow_firewall_difficulty_schema', 1 ) ) {
        foreach ( array( 'pow_firewall_form_difficulty', 'pow_firewall_url_difficulty' ) as $option_name ) {
            $legacy = (int) get_option( $option_name, 4 );
            if ( $legacy >= 1 && $legacy <= 8 ) {
                update_option( $option_name, ( $legacy - 1 ) * 20 );
            }
        }
        update_option( 'pow_firewall_difficulty_schema', 2 );
    }
    require_once plugin_dir_path( __FILE__ ) . 'includes/class-url-protection.php';
    require_once plugin_dir_path( __FILE__ ) . 'includes/class-form-protection.php';
    require_once plugin_dir_path( __FILE__ ) . 'includes/class-early-protection.php';

    $challenge       = new PoW_Firewall_Challenge();
    $url_protection  = new PoW_Firewall_URL_Protection( $challenge );
    $form_protection = new PoW_Firewall_Form_Protection( $challenge );
    $early_protection = new PoW_Firewall_Early_Protection();

    if ( is_admin() ) {
        require_once plugin_dir_path( __FILE__ ) . 'includes/class-admin.php';
        $admin = new PoW_Firewall_Admin();
    }
}
