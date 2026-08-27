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
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo esc_html( get_bloginfo( 'name' ) ); ?> — Security Check</title>
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
    <div class="pow-container" data-pow-state="solving">
        <div class="pow-icon">🔒</div>
        <div class="site-name"><?php echo esc_html( get_bloginfo( 'name' ) ); ?></div>
        <h1>Checking your browser…</h1>

        <?php if ( ! empty( $error ) ) : ?>
            <div class="pow-error">
                <?php esc_html_e( 'The previous security check failed. A new check is running automatically.', 'wp-pow-captcha' ); ?>
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
        window.powWorkerUrl  = <?php echo wp_json_encode( add_query_arg( 'ver', POW_CAPTCHA_VERSION, plugin_dir_url( dirname( __FILE__ ) ) . 'assets/pow-worker.js' ) ); ?>;
    </script>
    <script src="<?php echo esc_url( add_query_arg( 'ver', POW_CAPTCHA_VERSION, plugin_dir_url( dirname( __FILE__ ) ) . 'assets/pow-solver.js' ) ); ?>"></script>
</body>
</html>
