<?php
// CLI harness for the real settings endpoint; session/IP bootstrap and DB are isolated stubs.
namespace SLiMS {
    class DB {
        public static $raw;
        public static function getInstance() { return new self; }
        public function prepare($sql) {
            return new class {
                public function execute($data) {
                    if (isset($data['value'])) DB::$raw = $data['value'];
                    return true;
                }
                public function fetchColumn() { return DB::$raw; }
            };
        }
    }
}
namespace {
    if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
    $scenario = $argv[1] ?? 'csrf-array';
    $root = dirname(__DIR__, 3);
    $scratch = sys_get_temp_dir() . '/slims-turnstile-endpoint-' . bin2hex(random_bytes(6)) . '/';
    mkdir($scratch . 'admin/default', 0700, true);
    mkdir($scratch . 'lib', 0700);
    $files = ['admin/default/session.inc.php', 'admin/default/session_check.inc.php', 'lib/ip_based_access.inc.php'];
    foreach ($files as $file) file_put_contents($scratch . $file, '<?php');
    register_shutdown_function(function () use ($scratch, $files) {
        if (is_dir($scratch . 'private')) {
            foreach (scandir($scratch . 'private') as $name) {
                if ($name !== '.' && $name !== '..') unlink($scratch . 'private/' . $name);
            }
            rmdir($scratch . 'private');
        }
        foreach ($files as $file) unlink($scratch . $file);
        rmdir($scratch . 'admin/default'); rmdir($scratch . 'admin'); rmdir($scratch . 'lib'); rmdir($scratch);
    });
    define('SLIMS_TURNSTILE_KEY_DIRECTORY', $scratch . 'private');
    define('INDEX_AUTH', 1);
    define('SB', $scratch);
    define('LIB', $scratch . 'lib/');
    function do_checkIP($section) {}
    class utility {
        public static function havePrivilege($section, $mode) { return $GLOBALS['scenario'] !== 'no-privilege'; }
    }
    function toastr($message) {
        return new class($message) {
            private string $message;
            public function __construct($message) { $this->message = $message; }
            public function success() { echo 'SUCCESS:' . $this->message . "\n"; }
            public function error() { echo 'REJECTED:' . $this->message . "\n"; }
        };
    }
    require $root . '/lib/csrf/src/CSRF.php';
    require dirname(__DIR__) . '/src/Settings.php';
    \SLiMS\DB::$raw = serialize(['enabled' => false]);
    $_SESSION = [];
    $_SERVER['REQUEST_METHOD'] = 'POST';
    $name = \Volnix\CSRF\CSRF::getTokenName();
    $token = \Volnix\CSRF\CSRF::getToken();
    $_POST = ['saveTurnstile' => '1', $name => $token];
    switch ($scenario) {
        case 'csrf-array': $_POST[$name] = ['invalid']; break;
        case 'csrf-missing': unset($_POST[$name]); break;
        case 'csrf-wrong': $_POST[$name] = 'wrong'; break;
        case 'csrf-oversized': $_POST[$name] = str_repeat('a', 257); break;
        case 'method-get': $_SERVER['REQUEST_METHOD'] = 'GET'; break;
        case 'hostname-url': $_POST['hostnames'] = 'https://example.org'; break;
        case 'hostname-multiple': $_POST['hostnames'] = 'a.example.org,b.example.org'; break;
        case 'valid-save':
            $_POST += ['sitekey' => 'site', 'secret' => 'secret', 'hostnames' => 'opac.example.org', 'librarian' => '1'];
            break;
    }
    require dirname(__DIR__) . '/settings.php';
}
