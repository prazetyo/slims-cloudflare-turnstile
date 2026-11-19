<?php
// Isolated tests: actual SLiMS Config/Factory/Contract, no database or live Cloudflare calls.
namespace SLiMS {
    // In-memory adapter only; production Settings uses SLiMS PDO with prepared statements.
    class DB {
        public static $raw = false;
        public static bool $fail = false;
        public function query($sql) { throw new \RuntimeException('Regression: full setting reload is forbidden'); }
        public static function getInstance($driver = 'pdo') { return new self; }
        public function prepare($sql) {
            return new class {
                public function execute(array $data): bool {
                    if (DB::$fail) return false;
                    if (isset($data['value'])) DB::$raw = $data['value'];
                    return true;
                }
                public function fetchColumn() { return DB::$raw; }
            };
        }
    }
    class Plugins {
        public static array $callbacks = [];
        public static function getInstance() { return new self; }
        public function registerMenu(...$args) {}
        public static function hook($hook, $callback) { self::$callbacks[] = $callback; }
    }
}
namespace {
    if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
    define('INDEX_AUTH', 1);
    $cryptoScratch = sys_get_temp_dir() . '/slims-turnstile-suite-' . bin2hex(random_bytes(6));
    define('SLIMS_TURNSTILE_KEY_DIRECTORY', $cryptoScratch);
    register_shutdown_function(function () use ($cryptoScratch) {
        if (!is_dir($cryptoScratch)) return;
        foreach (scandir($cryptoScratch) as $name) {
            if ($name !== '.' && $name !== '..') unlink($cryptoScratch . '/' . $name);
        }
        rmdir($cryptoScratch);
    });
    define('SENAYAN_VERSION_TAG', isset($argv[1]) ? 'v9.7.2' : 'v9.8.0');
    $root = dirname(__DIR__, 3);
    define('SB', $root . '/');
    define('DS', DIRECTORY_SEPARATOR);
    require $argv[1] ?? $root . '/lib/Config.php';
    require $root . '/lib/autoload.php';
    require $root . '/lib/Captcha/Providers/Contract.php';
    require $argv[2] ?? $root . '/lib/Captcha/Factory.php';
    require dirname(__DIR__) . '/src/Settings.php';
    require dirname(__DIR__) . '/src/Turnstile.php';
    function config($key, $default = null) { return \SLiMS\Config::getInstance()->get($key, $default); }
    $checks = 0;
    function check($condition, $label) {
        global $checks;
        if (!$condition) throw new \RuntimeException('FAIL: ' . $label);
        $checks++;
    }
    function setup(array $values) {
        \SLiMS\DB::$fail = false;
        \SLiMS\DB::$raw = isset($values['cloudflare_turnstile']) ? serialize($values['cloudflare_turnstile']) : false;
        // Reproduce the server symptom: record exists, but Config has no plugin preferences.
        unset($values['cloudflare_turnstile']);
        $reflection = new \ReflectionClass(\SLiMS\Config::class);
        $instance = $reflection->newInstanceWithoutConstructor();
        $reflection->getProperty('configs')->setValue($instance, $values);
        $reflection->getProperty('instance')->setValue(null, $instance);
        foreach (['instance', 'providerInstance'] as $name) {
            (new \ReflectionProperty(\SLiMS\Captcha\Factory::class, $name))->setValue(null, null);
        }
        $GLOBALS['sysconf'] = [];
        \SLiMS\Plugins::$callbacks = [];
    }
    class ReloadTrapConfig extends \SLiMS\Config {
        public int $reloads = 0;
        public function __construct() {}
        public function loadFromDatabase(): void {
            $this->reloads++;
            throw new \RuntimeException('Regression: unrelated serialized setting fails on reload');
        }
    }
    class TestTurnstile extends \SLiMS\Turnstile\Turnstile {
        public array $response = [];
        public bool $throw = false;
        public int $calls = 0;
        protected function verifyToken(string $secret, string $token): array {
            $this->calls++;
            if ($this->throw) throw new \RuntimeException('network');
            return $this->response;
        }
    }
    check(!defined('SLiMS\\Plugins::SYSCONFIG_ALL_INIT'), 'bootstrap supports Plugins without new hook constant');
    $options = ['enabled' => true, 'sitekey' => 'site', 'secret' => 'secret', 'hostnames' => ['opac.example.org'], 'librarian' => true, 'memberarea' => true, 'forgot' => true];
    foreach ([false, true] as $existingConfig) {
        $values = ['cloudflare_turnstile' => $options, 'csp' => ["default-src 'self'", "script-src 'self'", "script-src-elem 'self'", "frame-src 'none'"]];
        if ($existingConfig) $values['captcha'] = ['default' => 'ReCaptcha', 'sections' => []];
        setup($values);
        require dirname(__DIR__) . '/turnstile.plugin.php';
        \SLiMS\Captcha\Factory::operate();
        check(\SLiMS\Captcha\Factory::getInstance()->getProviderName() === 'Turnstile', 'provider before operate');
        foreach (['librarian', 'memberarea', 'forgot'] as $section) {
            $factory = \SLiMS\Captcha\Factory::section($section);
            check($factory->isSectionActive() === true, 'active section ' . $section);
            check(strpos($factory->getCaptcha(), 'data-action="slims_' . $section . '"') !== false, 'widget section');
        }
        foreach (\SLiMS\Plugins::$callbacks as $callback) $callback($GLOBALS['sysconf']);
        $csp = implode(';', config('csp'));
        check(substr_count($csp, 'https://challenges.cloudflare.com') === 3, 'CSP directives merged');
        check(strpos($csp, "frame-src 'none'") === false, 'CSP none removed');
    }
    setup(['cloudflare_turnstile' => $options, 'csp' => ["default-src 'self'"]]);
    require dirname(__DIR__) . '/turnstile.plugin.php';
    \SLiMS\Captcha\Factory::operate();
    foreach (\SLiMS\Plugins::$callbacks as $callback) $callback($GLOBALS['sysconf']);
    check(count(config('csp')) === 3, 'missing directives appended once');
    check(strpos(implode(';', config('csp')), "script-src 'self' https://challenges.cloudflare.com") !== false, 'CSP fallback preserved');
    $factory = \SLiMS\Captcha\Factory::section('librarian');
    $provider = new TestTurnstile($factory);
    foreach (['', ['invalid'], str_repeat('x', 2049)] as $token) {
        $_POST = ['cf-turnstile-response' => $token];
        check($provider->validate() === false, 'reject malformed token');
    }
    check($provider->calls === 0, 'malformed token never sent');
    $_POST = ['cf-turnstile-response' => 'token'];
    foreach ([[], ['success' => 'true'], ['success' => false], ['success' => true, 'hostname' => 'evil.example.org', 'action' => 'slims_librarian'], ['success' => true, 'hostname' => 'opac.example.org', 'action' => 'slims_memberarea']] as $response) {
        $provider->response = $response;
        check($provider->validate() === false, 'reject bad verification');
    }
    foreach (['librarian', 'memberarea', 'forgot'] as $section) {
        \SLiMS\Captcha\Factory::section($section);
        $provider->response = ['success' => true, 'hostname' => 'opac.example.org', 'action' => 'slims_' . $section];
        check($provider->validate() === true, 'accept valid ' . $section);
    }
    $provider->throw = true;
    check($provider->validate() === false, 'network failure closed');
    check(strpos($provider->getError(), 'secret') === false, 'no secret exposed');
    setup(['cloudflare_turnstile' => ['enabled' => false]]);
    require dirname(__DIR__) . '/turnstile.plugin.php';
    check(\SLiMS\Captcha\Factory::getInstance()->getProviderName() === 'ReCaptcha', 'disabled retains native provider');
    setup([]);
    check(\SLiMS\Turnstile\Settings::load() === [], 'missing record');
    $saved = ['enabled' => true, 'sitekey' => 'site', 'secret' => 'secret', 'hostnames' => ['opac.example.org'], 'librarian' => true, 'memberarea' => true, 'forgot' => true];
    $saved['secret'] = "secret'with\\slashes";
    $saved['enabled'] = false;
    \SLiMS\Turnstile\Settings::save($saved);
    check(config('cloudflare_turnstile', []) === [], 'Config still empty after database save');
    check(\SLiMS\Turnstile\Settings::load() === $saved, 'save and reload from storage preserves exact data');
    $saved['enabled'] = true;
    \SLiMS\Turnstile\Settings::save($saved);
    require dirname(__DIR__) . '/turnstile.plugin.php';
    \SLiMS\Captcha\Factory::operate();
    check(\SLiMS\Captcha\Factory::section('librarian')->isSectionActive() === true, 'database-only options activate login');
    foreach (['invalid', serialize(new \stdClass)] as $bad) {
        \SLiMS\DB::$raw = $bad;
        $rejected = false;
        try { \SLiMS\Turnstile\Settings::load(); } catch (\RuntimeException $e) { $rejected = true; }
        check($rejected, 'reject corrupt/non-array settings');
    }
    \SLiMS\DB::$fail = true;
    $rejected = false;
    try { \SLiMS\Turnstile\Settings::save($saved); } catch (\RuntimeException $e) { $rejected = true; }
    check($rejected, 'storage failure cannot report success');
    // Corrupt storage must not invoke SLiMS's global warning renderer or disable protection.
    setup([]);
    $globalWarnings = 0;
    set_error_handler(function () use (&$globalWarnings) { $globalWarnings++; });
    \SLiMS\DB::$raw = 'a:1:{broken';
    $rejected = false;
    try { \SLiMS\Turnstile\Settings::load(); } catch (\RuntimeException $e) { $rejected = true; }
    check($rejected && $globalWarnings === 0, 'parsing warning contained');
    trigger_error('handler restoration probe', E_USER_WARNING);
    check($globalWarnings === 1, 'original error handler restored');
    restore_error_handler();
    require dirname(__DIR__) . '/turnstile.plugin.php';
    \SLiMS\Captcha\Factory::operate();
    foreach (['librarian', 'memberarea', 'forgot'] as $section) {
        $factory = \SLiMS\Captcha\Factory::section($section);
        check($factory->isSectionActive() === true, 'corrupt storage keeps protection enabled');
        $_POST = ['cf-turnstile-response' => 'token'];
        check($factory->isValid() === false, 'corrupt storage blocks submission');
        check(strpos($factory->getCaptcha(), 'sitekey') === false, 'corrupt storage produces safe form message');
    }
    $valid = ['enabled' => true, 'sitekey' => 'site', 'secret' => 'secret', 'hostnames' => ['opac.example.org'], 'librarian' => true, 'memberarea' => true, 'forgot' => true];
    $badOptions = [];
    foreach (['enabled' => 'false', 'secret' => [], 'sitekey' => str_repeat('a', 256), 'hostnames' => ['https://evil.example.org'], 'librarian' => 'true'] as $key => $value) {
        $badOptions[] = array_replace($valid, [$key => $value]);
    }
    $missing = $valid; unset($missing['memberarea']); $badOptions[] = $missing;
    foreach ($badOptions as $bad) {
        \SLiMS\DB::$raw = serialize($bad);
        $rejected = false;
        try { \SLiMS\Turnstile\Settings::load(); } catch (\RuntimeException $e) { $rejected = true; }
        check($rejected, 'reject malformed configuration schema');
    }
    \SLiMS\DB::$raw = str_repeat('a', 8193);
    $rejected = false;
    try { \SLiMS\Turnstile\Settings::load(); } catch (\RuntimeException $e) { $rejected = true; }
    check($rejected, 'bound serialized configuration size');
    setup(['cloudflare_turnstile' => $valid]);
    $escaped = $valid; $escaped['sitekey'] = '\"><script>alert(1)</script>';
    \SLiMS\DB::$raw = serialize($escaped);
    $provider = new TestTurnstile(\SLiMS\Captcha\Factory::section('librarian'));
    check(strpos($provider->generateCaptcha(), '<script>alert') === false, 'sitekey cannot inject HTML');
    $provider->response = ['success' => true, 'hostname' => 'OPAC.EXAMPLE.ORG', 'action' => 'slims_librarian'];
    check($provider->validate() === true, 'DNS hostname is case insensitive');
    // Simulate an existing unrelated setting that must never be decoded by plugin bootstrap.
    setup(['cloudflare_turnstile' => $valid, 'unrelated' => 'a:not-serialized-data!']);
    $loader = file_get_contents(dirname(__DIR__) . '/turnstile.plugin.php');
    check(strpos($loader, "->load(") === false, 'bootstrap never calls Config::load');
    require dirname(__DIR__) . '/turnstile.plugin.php';
    \SLiMS\Captcha\Factory::operate();
    check(config('unrelated') === 'a:not-serialized-data!', 'unrelated setting remains untouched');
    check(\SLiMS\Captcha\Factory::section('librarian')->isSectionActive() === true, 'missing root registered without database reload');
    setup(['cloudflare_turnstile' => $valid]);
    $GLOBALS['sysconf']['captcha'] = ['default' => 'ReCaptcha'];
    require dirname(__DIR__) . '/turnstile.plugin.php';
    \SLiMS\Captcha\Factory::operate();
    check(\SLiMS\Captcha\Factory::section('memberarea')->isSectionActive() === true, 'legacy global root cannot break missing Config root');
    setup(['cloudflare_turnstile' => $valid]);
    $trap = new ReloadTrapConfig();
    (new \ReflectionProperty(\SLiMS\Config::class, 'configs'))->setValue($trap, ['unrelated' => 'a:invalid-storage']);
    (new \ReflectionProperty(\SLiMS\Config::class, 'instance'))->setValue(null, $trap);
    require dirname(__DIR__) . '/turnstile.plugin.php';
    \SLiMS\Captcha\Factory::operate();
    check($trap->reloads === 0, 'failing database reload never invoked by bootstrap');
    check(\SLiMS\Captcha\Factory::section('librarian')->isSectionActive() === true, 'provider works with reload trap');
    echo "PASS: $checks checks\n";
}
