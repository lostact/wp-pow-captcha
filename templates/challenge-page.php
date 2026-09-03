<?php
/**
 * Challenge page template.
 *
 * This template is included by URL protection and followed by exit.
 * It receives $challenge (array) and $error (bool) from the including code.
 *
 * @var array $challenge Challenge data array.
 * @var bool  $error     Whether the previous solution failed.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}
?>
<!DOCTYPE html>
<html <?php language_attributes(); ?>>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <?php /* translators: %s: site name. */ ?>
    <title><?php echo esc_html( sprintf( __( '%s — Security Check', 'proof-of-work-firewall' ), get_bloginfo( 'name' ) ) ); ?></title>
    <?php
    $challenge_style_handles = array( 'pow-firewall-challenge' );
    if ( pow_firewall_is_persian() ) {
        $challenge_style_handles[] = 'pow-firewall-vazirmatn';
    }
    wp_print_styles( $challenge_style_handles );
    ?>
</head>
<body>
    <div class="pow-container" data-pow-state="solving" dir="<?php echo esc_attr( pow_firewall_text_direction() ); ?>">
        <div class="pow-icon">🔒</div>
        <h1><?php esc_html_e( 'Checking your browser…', 'proof-of-work-firewall' ); ?></h1>

        <?php if ( ! empty( $error ) ) : ?>
            <div class="pow-error">
                <?php esc_html_e( 'The previous security check failed. Complete the new check to try again.', 'proof-of-work-firewall' ); ?>
            </div>
        <?php endif; ?>

        <div class="pow-progress" role="progressbar" aria-label="<?php esc_attr_e( 'Security check in progress', 'proof-of-work-firewall' ); ?>" aria-busy="true" hidden><span></span></div>
        <p id="pow-status" role="status" aria-live="polite"><?php esc_html_e( 'Please wait while we verify your browser…', 'proof-of-work-firewall' ); ?></p>
        <p id="pow-details" hidden><?php esc_html_e( 'Starting secure worker…', 'proof-of-work-firewall' ); ?></p>
    </div>

    <?php wp_print_footer_scripts(); ?>
</body>
</html>
