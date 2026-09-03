<?php
/**
 * Uninstall script: removes all plugin options from the database.
 *
 * This file is executed when the plugin is deleted via the WordPress admin.
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    exit;
}

$pow_firewall_dropin = WP_CONTENT_DIR . '/advanced-cache.php';
if ( is_readable( $pow_firewall_dropin ) && filesize( $pow_firewall_dropin ) <= 16384 ) {
    $pow_firewall_dropin_contents = file_get_contents( $pow_firewall_dropin );
    if (
        is_string( $pow_firewall_dropin_contents ) &&
        (
            false !== strpos( $pow_firewall_dropin_contents, 'Proof-of-Work Firewall managed advanced-cache drop-in' ) ||
            false !== strpos( $pow_firewall_dropin_contents, 'Proof of Work Captcha managed advanced-cache drop-in' )
        )
    ) {
        wp_delete_file( $pow_firewall_dropin );
    }
}

$pow_firewall_runtime_configs = array(
    WP_CONTENT_DIR . '/pow-firewall-runtime.php',
    WP_CONTENT_DIR . '/pow-captcha-runtime.php',
);
foreach ( $pow_firewall_runtime_configs as $pow_firewall_runtime_config ) {
    if ( is_readable( $pow_firewall_runtime_config ) ) {
        $pow_firewall_config_contents = file_get_contents( $pow_firewall_runtime_config, false, null, 0, 128 );
        if (
            is_string( $pow_firewall_config_contents ) &&
            (
                false !== strpos( $pow_firewall_config_contents, 'Proof-of-Work Firewall generated runtime configuration' ) ||
                false !== strpos( $pow_firewall_config_contents, 'Proof of Work Captcha generated runtime configuration' )
            )
        ) {
            wp_delete_file( $pow_firewall_runtime_config );
        }
    }
}

delete_option( 'pow_firewall_secret_key' );
delete_option( 'pow_firewall_protected_forms' );
delete_option( 'pow_firewall_url_patterns' );
delete_option( 'pow_firewall_form_difficulty' );
delete_option( 'pow_firewall_url_difficulty' );
delete_option( 'pow_firewall_max_query_length' );
delete_option( 'pow_firewall_interaction_mode' );
delete_option( 'pow_firewall_debug_progress' );
delete_option( 'pow_firewall_expiry_time' );
delete_option( 'pow_firewall_difficulty_schema' );
delete_option( 'pow_firewall_early_protection_enabled' );
delete_option( 'pow_firewall_early_protection_status' );
delete_option( 'pow_firewall_early_protection_config_version' );
