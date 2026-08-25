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
    <div class="pow-container">
        <div class="pow-icon">🔒</div>
        <div class="site-name"><?php echo esc_html( get_bloginfo( 'name' ) ); ?></div>
        <h1>Checking your browser…</h1>

        <?php if ( ! empty( $error ) ) : ?>
            <div class="pow-error">
                <?php esc_html_e( 'The previous security check failed. A new check is running automatically.', 'wp-pow-captcha' ); ?>
            </div>
        <?php endif; ?>

        <p id="pow-status">Please wait while we verify your browser…</p>
    </div>

    <script>
        const powChallenge  = <?php echo json_encode( $challenge['challenge'] ); ?>;
        const powExpires    = <?php echo intval( $challenge['expires'] ); ?>;
        const powDifficulty = <?php echo intval( $challenge['difficulty'] ); ?>;
        const powSig        = <?php echo json_encode( $challenge['signature'] ); ?>;
        const powWorkerUrl  = <?php echo json_encode( plugin_dir_url( dirname( __FILE__ ) ) . 'assets/pow-worker.js' ); ?>;
    </script>
    <script src="<?php echo esc_url( plugin_dir_url( dirname( __FILE__ ) ) . 'assets/pow-solver.js' ); ?>"></script>
</body>
</html>
