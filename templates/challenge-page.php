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
    <title><?php echo esc_html( sprintf( __( '%s — Security Check', 'wp-pow-captcha' ), get_bloginfo( 'name' ) ) ); ?></title>
    <?php if ( pow_captcha_is_persian() ) : ?>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700&display=swap">
    <?php endif; ?>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
            background-color: #f0f0f1;
            color: #1d2327;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 20px;
        }
        html[lang^="fa"] body {
            font-family: "Vazirmatn", Tahoma, sans-serif;
        }
        .pow-container {
            background: #fff;
            border: 1px solid #c3c4c7;
            border-radius: 4px;
            padding: 40px;
            max-width: 500px;
            width: 100%;
            text-align: center;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .pow-container h1 {
            font-size: 1.3em;
            margin-bottom: 8px;
            color: #1d2327;
        }
        .pow-container .site-name {
            font-size: 0.9em;
            color: #646970;
            margin-bottom: 24px;
        }
        .pow-container .pow-icon {
            font-size: 48px;
            margin-bottom: 16px;
        }
        #pow-status {
            font-size: 0.95em;
            color: #50575e;
            margin-top: 16px;
            line-height: 1.5;
            font-weight: 600;
        }
        #pow-details {
            min-height: 1.5em;
            margin-top: 6px;
            color: #646970;
            font-size: 0.8em;
            font-variant-numeric: tabular-nums;
        }
        .pow-progress {
            position: relative;
            height: 8px;
            margin-top: 22px;
            overflow: hidden;
            border-radius: 999px;
            background: #dcdcde;
        }
        .pow-progress span {
            position: absolute;
            top: 0;
            bottom: 0;
            left: -35%;
            width: 35%;
            border-radius: inherit;
            background: #2271b1;
            animation: pow-progress 1.15s ease-in-out infinite;
        }
        [data-pow-state="solved"] .pow-progress span {
            left: 0;
            width: 100%;
            background: #00a32a;
            animation: none;
        }
        [data-pow-state="error"] .pow-progress span {
            left: 0;
            width: 100%;
            background: #d63638;
            animation: none;
        }
        [data-pow-state="waiting"] .pow-progress span {
            left: 0;
            width: 0;
            animation: none;
        }
        .pow-interaction-check {
            display: flex;
            align-items: center;
            gap: 12px;
            margin: 20px auto 0;
            padding: 14px 16px;
            border: 1px solid #8c8f94;
            border-radius: 4px;
            cursor: pointer;
            text-align: start;
        }
        .pow-interaction-check input { width: 20px; height: 20px; margin: 0; }
        @keyframes pow-progress {
            from { left: -35%; }
            to { left: 100%; }
        }
        @media (prefers-reduced-motion: reduce) {
            .pow-progress span { left: 0; width: 45%; animation: none; }
        }
        .pow-error {
            background: #fcf0f1;
            border: 1px solid #cc1818;
            border-radius: 4px;
            padding: 12px 16px;
            margin-bottom: 20px;
            color: #cc1818;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="pow-container" data-pow-state="solving" dir="<?php echo esc_attr( pow_captcha_text_direction() ); ?>">
        <div class="pow-icon">🔒</div>
        <div class="site-name"><?php echo esc_html( get_bloginfo( 'name' ) ); ?></div>
        <h1><?php esc_html_e( 'Checking your browser…', 'wp-pow-captcha' ); ?></h1>

        <?php if ( ! empty( $error ) ) : ?>
            <div class="pow-error">
                <?php esc_html_e( 'The previous security check failed. Complete the new check to try again.', 'wp-pow-captcha' ); ?>
            </div>
        <?php endif; ?>

        <div class="pow-progress" role="progressbar" aria-label="<?php esc_attr_e( 'Security check in progress', 'wp-pow-captcha' ); ?>" aria-busy="true"><span></span></div>
        <p id="pow-status" role="status" aria-live="polite"><?php esc_html_e( 'Please wait while we verify your browser…', 'wp-pow-captcha' ); ?></p>
        <p id="pow-details"><?php esc_html_e( 'Starting secure worker…', 'wp-pow-captcha' ); ?></p>
    </div>

    <script>
        window.powChallenge  = <?php echo wp_json_encode( $challenge['challenge'] ); ?>;
        window.powExpires    = <?php echo intval( $challenge['expires'] ); ?>;
        window.powDifficulty = <?php echo intval( $challenge['difficulty'] ); ?>;
        window.powVersion    = <?php echo intval( $challenge['version'] ); ?>;
        window.powAlgorithm  = <?php echo wp_json_encode( $challenge['algorithm'] ); ?>;
        window.powSig        = <?php echo wp_json_encode( $challenge['signature'] ); ?>;
        window.powInteractionMode = <?php echo wp_json_encode( $interaction_mode ); ?>;
        window.powI18n       = <?php echo wp_json_encode( pow_captcha_frontend_translations() ); ?>;
        window.powWorkerUrl  = <?php echo wp_json_encode( add_query_arg( 'ver', POW_CAPTCHA_VERSION, plugin_dir_url( dirname( __FILE__ ) ) . 'assets/pow-worker.js' ) ); ?>;
    </script>
    <script src="<?php echo esc_url( add_query_arg( 'ver', POW_CAPTCHA_VERSION, plugin_dir_url( dirname( __FILE__ ) ) . 'assets/pow-solver.js' ) ); ?>"></script>
</body>
</html>
