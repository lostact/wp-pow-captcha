<?php
/**
 * Uninstall script: removes all plugin options from the database.
 *
 * This file is executed when the plugin is deleted via the WordPress admin.
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    exit;
}

$pow_dropin = WP_CONTENT_DIR . '/advanced-cache.php';
if ( is_readable( $pow_dropin ) && filesize( $pow_dropin ) <= 16384 ) {
    $pow_dropin_contents = file_get_contents( $pow_dropin );
    if ( is_string( $pow_dropin_contents ) && false !== strpos( $pow_dropin_contents, 'WP PoW Captcha managed advanced-cache drop-in' ) ) {
        @unlink( $pow_dropin );
    }
}

$pow_runtime_config = WP_CONTENT_DIR . '/pow-captcha-runtime.php';
if ( is_readable( $pow_runtime_config ) ) {
    $pow_config_contents = file_get_contents( $pow_runtime_config, false, null, 0, 128 );
    if ( is_string( $pow_config_contents ) && false !== strpos( $pow_config_contents, 'WP PoW Captcha generated runtime configuration' ) ) {
        @unlink( $pow_runtime_config );
    }
}

delete_option( 'pow_secret_key' );
delete_option( 'pow_protected_forms' );
delete_option( 'pow_url_patterns' );
delete_option( 'pow_form_difficulty' );
delete_option( 'pow_url_difficulty' );
delete_option( 'pow_max_query_length' );
delete_option( 'pow_expiry_time' );
delete_option( 'pow_difficulty_schema' );
delete_option( 'pow_early_protection_enabled' );
delete_option( 'pow_early_protection_status' );
