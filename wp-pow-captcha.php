<?php
/**
 * Plugin Name: WP PoW Captcha
 * Description: Protects configurable URLs and forms using a proof-of-work challenge system. No external dependencies, no third-party CAPTCHA services.
 * Version: 1.0.0
 * Author: WP PoW Captcha
 * License: GPL-2.0-or-later
 * Text Domain: wp-pow-captcha
 * Requires at least: 5.8
 * Requires PHP: 7.4
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

register_activation_hook( __FILE__, 'pow_captcha_activate' );
register_deactivation_hook( __FILE__, 'pow_captcha_deactivate' );

/**
 * Activation hook: generate and store the secret key if it doesn't exist.
 */
function pow_captcha_activate() {
    if ( false === get_option( 'pow_secret_key' ) ) {
        $key = bin2hex( random_bytes( 32 ) );
        add_option( 'pow_secret_key', $key );
    }
    // Set defaults for options if they don't exist.
    if ( false === get_option( 'pow_protected_forms' ) ) {
        add_option( 'pow_protected_forms', array() );
    }
    if ( false === get_option( 'pow_url_patterns' ) ) {
        add_option( 'pow_url_patterns', array() );
    }
    if ( false === get_option( 'pow_form_difficulty' ) ) {
        add_option( 'pow_form_difficulty', 4 );
    }
    if ( false === get_option( 'pow_url_difficulty' ) ) {
        add_option( 'pow_url_difficulty', 4 );
    }
    if ( false === get_option( 'pow_expiry_time' ) ) {
        add_option( 'pow_expiry_time', 300 );
    }
}

/**
 * Deactivation hook: do nothing so settings persist.
 */
function pow_captcha_deactivate() {
    // Intentionally empty — settings persist across deactivation.
}

/**
 * Instantiate all plugin classes after plugins_loaded.
 */
add_action( 'plugins_loaded', 'pow_captcha_init' );

function pow_captcha_init() {
    require_once plugin_dir_path( __FILE__ ) . 'includes/class-challenge.php';
    require_once plugin_dir_path( __FILE__ ) . 'includes/class-url-protection.php';
    require_once plugin_dir_path( __FILE__ ) . 'includes/class-form-protection.php';
    require_once plugin_dir_path( __FILE__ ) . 'includes/class-admin.php';

    $challenge      = new PoW_Captcha_Challenge();
    $url_protection = new PoW_Captcha_URL_Protection( $challenge );
    $form_protection = new PoW_Captcha_Form_Protection( $challenge );
    $admin          = new PoW_Captcha_Admin();
}
