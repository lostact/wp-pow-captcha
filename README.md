# WP PoW Captcha

The main goal of WP PoW Captcha is to protect resource-consuming website pages from automated bots. It also provides an additional layer of protection against login brute forcing, automated registrations, and comment spam.

The plugin requires a visitor's browser to complete a configurable proof-of-work challenge before a protected request is accepted. Verification is inexpensive for the server, while automated traffic must spend computational effort.

## Main features

- Protect WordPress login, registration, and comment forms.
- Protect URLs selected with regular-expression patterns.
- Fine-grained difficulty control with small, predictable increments.
- Browser progress indicator with attempts, hash rate, and elapsed time.
- Admin benchmark and estimated solve-time table.
- Stateless HMAC-signed challenges with server-enforced expiration.
- Challenges and URL clearance are bound to the visitor IP.
- Cloudflare-aware visitor IP detection with trusted proxy validation.
- Fresh, non-cacheable challenges for forms and protected URL pages.
- Optional early URL gateway that rejects unsolved requests before ordinary plugins and the theme load.
- No external CAPTCHA service or third-party dependency.

## Design choices

- **SHA-256 proof of work:** simple, widely supported, and inexpensive to verify server-side.
- **Fine-grained targets:** each difficulty step adds approximately 7.2% expected work instead of multiplying work by 16.
- **Web Worker solving:** computation runs outside the browser's main UI thread.
- **Signed challenge data:** difficulty, expiry, algorithm, protocol version, random nonce, and visitor IP are protected by HMAC-SHA-256.
- **IP-bound clearance:** a solved URL challenge cannot be copied to a different visitor IP, and clearance cannot outlive the original challenge.
- **No cached form puzzles:** pages contain placeholders; each browser requests a fresh challenge after page load.
- **Fail-fast login checks:** invalid proof of work is rejected before WordPress performs password hashing.
- **Optional lowest-resource mode:** a managed `advanced-cache.php` gateway performs protected URL checks early in bootstrap. It never overwrites another product's existing drop-in and falls back to standard protection when unavailable.

## How lowest-resource mode works

- WordPress settings are compiled into a generated `wp-content/pow-captcha-runtime.php` configuration whenever relevant options change.
- The early `wp-content/advanced-cache.php` gateway reads this PHP configuration directly, so an unsolved request normally performs zero database queries.
- Unsolved protected requests receive the standalone challenge before ordinary plugins, the theme, routing, and the main query load; cleared requests continue into WordPress normally.
- Configuration writes are atomic, missing files fail open to standard protection, and an existing foreign `advanced-cache.php` is never overwritten.

## Installation

1. Download the installer from the [latest GitHub release](https://github.com/lostact/wp-pow-captcha/releases/latest).
2. In WordPress, open **Plugins → Add New Plugin → Upload Plugin**.
3. Upload the ZIP and activate it.
4. Open **Settings → PoW Captcha** to configure forms, URL patterns, difficulty, and expiry.
5. Optionally enable **Lowest-resource URL Protection**. Automatic setup requires writable WordPress configuration/content files and an unused `advanced-cache.php` slot.

## Important limitations

Proof of work increases attacker cost but is not a complete DDoS solution. It cannot stop volumetric attacks, prevent a powerful remote machine from solving separate challenges for bots, or protect requests handled before WordPress loads. Use it together with a CDN/WAF, reverse-proxy rate limiting, and origin firewall rules.

When using Cloudflare, restrict direct access to the origin. The plugin trusts `CF-Connecting-IP` only when the direct peer is in Cloudflare's official proxy ranges. Custom trusted proxies can be added with the `pow_captcha_trusted_proxy_ranges` WordPress filter.

## Requirements

- WordPress 5.8 or newer
- PHP 7.4 or newer
- A browser with Web Worker support

## License

GPL-2.0-or-later
