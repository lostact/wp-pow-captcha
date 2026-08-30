=== Proof of Work Captcha ===
Contributors: lostact
Tags: captcha, proof of work, anti-spam, security, login
Requires at least: 5.8
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 2.5.4
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Protect configurable URLs and WordPress forms with private, self-hosted proof-of-work challenges.

== Description ==

Proof of Work Captcha protects resource-intensive pages and common WordPress forms from automated bots. A visitor's browser completes a configurable SHA-256 proof-of-work challenge before the protected request is accepted.

Challenge generation and verification run on your site. No CAPTCHA account, API key, or external CAPTCHA provider is required.

= Features =

* Protect login, registration, and comment forms.
* Protect URLs selected with regular-expression patterns.
* Choose automatic, mouse-movement, or verification-checkbox challenge triggers.
* Configure separate proof-of-work difficulty for forms and URLs.
* Optionally reject oversized query strings on matching protected URLs.
* Use stateless, HMAC-signed, expiring challenges bound to the visitor IP.
* Recognize Cloudflare visitor addresses only through validated official proxy ranges.
* Optionally challenge protected URLs early through a managed advanced-cache gateway.
* Benchmark the current browser and estimate solve times from the settings page.
* Display progress, attempts, hash rate, and elapsed time while solving.
* Includes complete Persian translation and RTL support.

= Privacy =

The plugin does not collect analytics, track visitors, create remote accounts, or send challenge data to an external CAPTCHA service.

For Persian pages only, the plugin loads the Vazirmatn font from Google Fonts. This request may disclose the visitor's IP address, user agent, and standard HTTP request information to Google. Google Fonts is provided under Google's terms and privacy policy:

* Google Fonts FAQ and privacy: https://developers.google.com/fonts/faq/privacy
* Google Privacy Policy: https://policies.google.com/privacy

All other JavaScript and CSS used by the CAPTCHA is included with the plugin and served from the WordPress site.

= Important limitation =

Proof of work increases the cost of automated requests but is not a complete DDoS solution. It cannot stop volumetric attacks or requests blocked before reaching WordPress. Use it together with appropriate CDN, reverse-proxy, rate-limiting, and firewall controls.

== Installation ==

1. Install Proof of Work Captcha from the WordPress plugin directory, or upload its ZIP from Plugins > Add New Plugin > Upload Plugin.
2. Activate the plugin.
3. Open Settings > PoW Captcha.
4. Select the forms to protect and configure their difficulty.
5. Add one PHP-compatible regular expression per line for URLs that should be protected.
6. Select the challenge trigger and adjust expiry and query-length settings as needed.
7. Optionally enable Lowest-resource URL Protection after reviewing its status and diagnostics.

== Frequently Asked Questions ==

= Does this plugin use an external CAPTCHA service? =

No. Challenges are generated and verified locally by WordPress, and proof-of-work is solved in the visitor's browser. Persian pages load the Vazirmatn font from Google Fonts as disclosed in the Privacy section.

= What does the difficulty value mean? =

Each difficulty step adds approximately 7.2 percent expected work. Use the built-in browser benchmark to select a value appropriate for your visitors and hardware targets.

= What URL patterns can I use? =

Enter one PHP-compatible regular expression per line. Patterns are tested against the complete request URI. Test patterns carefully before enabling them on a production site.

= What is Lowest-resource URL Protection? =

It is an optional advanced-cache gateway that can reject unsolved protected URL requests before normal plugins, the theme, routing, and the main query load. It requires an available advanced-cache.php drop-in slot and WP_CACHE support. The plugin does not overwrite a drop-in owned by another plugin or product.

= Does the plugin work behind Cloudflare? =

Yes. It trusts Cloudflare forwarding headers only when the direct peer belongs to an official Cloudflare proxy range. Other trusted proxy ranges can be provided with the pow_captcha_trusted_proxy_ranges filter.

= Why is a visitor asked to solve another challenge? =

URL clearance expires, is bound to the visitor IP, and cannot outlive the signed challenge. A changed address, expired clearance, deleted cookie, or invalid solution requires a new challenge.

== Changelog ==

= 2.5.4 =

* Added automatic, genuine mouse-movement, and verification-checkbox challenge triggers.
* Added configurable long-query blocking for regex-matched protected URLs.
* Added complete Persian translation and explicit RTL support.
* Added Vazirmatn from Google Fonts for Persian CAPTCHA interfaces.
* Added automatic early-runtime refresh after plugin upgrades and language changes.
* Improved standalone early-gateway localization and visitor-facing messages.

== Upgrade Notice ==

= 2.5.4 =

Adds interaction-based challenge triggers, long-query protection, Persian localization, and RTL support.
