<?php
/**
 * Uninstall script: removes all plugin options from the database.
 *
 * This file is executed when the plugin is deleted via the WordPress admin.
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    exit;
}

delete_option( 'pow_secret_key' );
delete_option( 'pow_protected_forms' );
delete_option( 'pow_url_patterns' );
delete_option( 'pow_form_difficulty' );
delete_option( 'pow_url_difficulty' );
