<?php
/**
 * Plugin Name: Cloudflare Turnstile
 * Plugin URI: https://developers.cloudflare.com/turnstile/
 * Description: Turnstile untuk login pustakawan, anggota, dan lupa password melalui provider CAPTCHA resmi SLiMS.
 * Version: 1.0.8
 * Author: Agung PW
 * Author URI: https://agungprasetyo.net/
 */

defined('INDEX_AUTH') or die('Direct access is not allowed!');

require_once __DIR__ . '/src/Settings.php';
require_once __DIR__ . '/src/RuntimeConfig.php';
require_once __DIR__ . '/src/Turnstile.php';

use SLiMS\Captcha\Factory;
use SLiMS\Config;
use SLiMS\Plugins;
use SLiMS\Turnstile\Turnstile;

Plugins::getInstance()->registerMenu('system', 'Cloudflare Turnstile', __DIR__ . '/settings.php');

// Recovery switch controlled by the server operator, never by a request parameter.
if (is_file(__DIR__ . '/DISABLED')) return;

try {
    $options = \SLiMS\Turnstile\Settings::load();
} catch (\Throwable $e) {
    // Keep OPAC available, but require a provider that rejects protected submissions.
    // Do not silently disable CAPTCHA because its settings cannot be read.
    $options = ['enabled' => true, 'librarian' => true, 'memberarea' => true, 'forgot' => true];
    error_log('[SLiMS Turnstile] Settings unavailable; protected submissions are blocked.');
}
if (!is_array($options) || empty($options['enabled'])) return;

// Must run before Factory::operate() in sysconfig.inc.php, not in SYSCONFIG_ALL_INIT.
$captchaConfig = config('captcha', []);
$captchaConfig = is_array($captchaConfig) ? $captchaConfig : [];
$captchaConfig['default'] = 'Turnstile';
$captchaConfig['providers']['Turnstile'] = ['class' => Turnstile::class];
foreach (['librarian', 'memberarea', 'forgot'] as $section) {
    $captchaConfig['sections'][$section]['active'] = !empty($options[$section]);
}
// Configure only the runtime CAPTCHA root; never reload unrelated database rows.
\SLiMS\Turnstile\RuntimeConfig::captcha($captchaConfig);
Factory::getInstance()->registerProvider('Turnstile', Turnstile::class);
Factory::getInstance()->setProvider('Turnstile');

// Merge existing directives, rather than add duplicate CSP directives.
// Apply to the loaded Config during plugin bootstrap; 9.7.2 lacks the later hook constant.
(static function () {
    $policy = config('csp', []);
    if (!is_array($policy) || !$policy) return;
    foreach (['script-src', 'script-src-elem', 'frame-src'] as $directive) {
        $found = false;
        foreach ($policy as &$entry) {
            $parts = preg_split('/\s+/', trim($entry));
            if (($parts[0] ?? '') !== $directive) continue;
            $found = true;
            $parts = array_values(array_diff($parts, ["'none'"]));
            if (!in_array('https://challenges.cloudflare.com', $parts, true)) {
                $parts[] = 'https://challenges.cloudflare.com';
            }
            $entry = implode(' ', $parts);
        }
        unset($entry);
        if (!$found && $directive !== 'script-src-elem') {
            // Preserve the original fallback restrictions when making a directive explicit.
            $fallback = "'self'";
            foreach ($policy as $entry) {
                if (strpos(trim($entry), 'default-src ') === 0) {
                    $fallback = substr(trim($entry), 12);
                    break;
                }
            }
            $fallback = trim(str_replace("'none'", '', $fallback));
            $policy[] = $directive . ' ' . $fallback . ' https://challenges.cloudflare.com';
        }
    }
    // In 9.7.2 replace(root, numeric-array) appends instead of replacing.
    // Replace existing entries by index; append only newly introduced directives.
    if (defined('SENAYAN_VERSION_TAG') && version_compare(ltrim(SENAYAN_VERSION_TAG, 'v'), '9.8.0', '>=')) {
        Config::getInstance()->replace('csp', $policy);
        return;
    }
    $current = config('csp', []);
    foreach ($current as $index => $entry) {
        Config::getInstance()->change('csp.' . $index, $policy[$index], 'replace');
    }
    $additional = array_slice($policy, count($current));
    if ($additional) Config::getInstance()->append('csp', $additional);
})();
