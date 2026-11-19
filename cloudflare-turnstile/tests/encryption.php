<?php
namespace SLiMS {
    class DB {
        public static $raw = false;
        public static bool $fail = false;
        public static function getInstance() { return new self; }
        public function prepare($sql) {
            return new class {
                public function execute($values) {
                    if (DB::$fail) return false;
                    if (isset($values['value'])) DB::$raw = $values['value'];
                    return true;
                }
                public function fetchColumn() { return DB::$raw; }
            };
        }
    }
}
namespace {
    if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
    $mode = $argv[1] ?? 'suite';
    $directory = $mode === 'suite' ? sys_get_temp_dir() . '/slims-encryption-' . bin2hex(random_bytes(8)) : ($argv[2] ?? '');
    define('SLIMS_TURNSTILE_KEY_DIRECTORY', $directory);
    require dirname(__DIR__) . '/src/Settings.php';
    use SLiMS\Turnstile\SecretCipher;
    use SLiMS\Turnstile\Settings;
    if ($mode === 'worker') { echo SecretCipher::encrypt('parallel-test-secret'); exit; }
    if ($mode === 'verify') {
        exit(SecretCipher::decrypt(stream_get_contents(STDIN)) === 'parallel-test-secret' ? 0 : 1);
    }
    register_shutdown_function(function () use ($directory) {
        $remove = function ($path) use (&$remove) {
            if (is_link($path) || is_file($path)) { unlink($path); return; }
            if (!is_dir($path)) return;
            foreach (scandir($path) as $name) if ($name !== '.' && $name !== '..') $remove($path . '/' . $name);
            rmdir($path);
        };
        $remove($directory);
    });
    $count = 0;
    function check($ok, $label) {
        global $count;
        if (!$ok) throw new \RuntimeException('FAIL: ' . $label);
        $count++;
    }
    function rejects(callable $callback, string $label) {
        $rejected = false;
        try { $callback(); } catch (\RuntimeException $e) { $rejected = true; }
        check($rejected, $label);
    }
    $options = ['enabled' => true, 'sitekey' => 'public-sitekey', 'secret' => 'private-test-secret',
        'hostnames' => ['opac.example.org'], 'librarian' => true, 'memberarea' => true, 'forgot' => true];
    \SLiMS\DB::$raw = serialize($options);
    check(Settings::load() === $options, 'legacy plaintext readable before migration');
    check(!is_dir($directory), 'reading legacy data does not create a key or write storage');
    Settings::save($options);
    $path = $directory . '/encryption-key.php';
    check((fileperms($path) & 0777) === 0600, 'key file permission is 0600');
    $guard = proc_open([PHP_BINARY, $path], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    fclose($pipes[0]);
    $output = stream_get_contents($pipes[1]); $errors = stream_get_contents($pipes[2]);
    fclose($pipes[1]); fclose($pipes[2]);
    check(proc_close($guard) === 0 && $output === '' && $errors === '', 'direct PHP access cannot disclose key');
    $stored = unserialize(\SLiMS\DB::$raw, ['allowed_classes' => false]);
    check($stored['secret'] !== $options['secret'] && strpos(\SLiMS\DB::$raw, $options['secret']) === false, 'plaintext secret absent from stored bytes');
    check($stored['sitekey'] === $options['sitekey'], 'public sitekey remains unchanged');
    check($stored['_secret_encryption'] === 'aes-256-gcm:v1', 'format version stored');
    check(Settings::load() === $options, 'roundtrip decrypts automatically');
    $path = $directory . '/encryption-key.php';
    $originalKey = file_get_contents($path);
    check((fileperms($path) & 0777) === 0600, 'key permission is owner-only');
    check(strpos($originalKey, 'exit;') !== false, 'key file has direct-access guard');
    Settings::save($options);
    $storedAgain = unserialize(\SLiMS\DB::$raw, ['allowed_classes' => false]);
    check($storedAgain['secret'] !== $stored['secret'], 'new random IV on every save');
    check(file_get_contents($path) === $originalKey, 'upgrade/resave preserves existing key');
    foreach ([1, 35, 255] as $length) {
        $plain = str_repeat('A', $length);
        check(SecretCipher::decrypt(SecretCipher::encrypt($plain)) === $plain, 'variable plaintext lengths');
    }
    $cipher = $stored['secret'];
    $payload = base64_decode(substr($cipher, 7), true);
    foreach ([0, 12, 28] as $offset) {
        $bad = $payload; $bad[$offset] = chr(ord($bad[$offset]) ^ 1);
        rejects(function () use ($bad) { SecretCipher::decrypt('enc:v1:' . base64_encode($bad)); }, 'tampered IV/tag/ciphertext rejected');
    }
    foreach (['enc:v2:AAA=', 'enc:v1:!!', 'enc:v1:' . base64_encode(substr($payload, 0, 20)), str_repeat('x', 1025)] as $bad) {
        rejects(function () use ($bad) { SecretCipher::decrypt($bad); }, 'invalid/truncated format rejected');
    }
    $bad = $stored; unset($bad['_secret_encryption']); \SLiMS\DB::$raw = serialize($bad);
    rejects(function () { Settings::load(); }, 'missing encryption metadata rejected');
    $bad = $stored; $bad['_secret_encryption'] = 'unknown'; \SLiMS\DB::$raw = serialize($bad);
    rejects(function () { Settings::load(); }, 'unknown encryption version rejected');
    $cipher = $stored['secret'];
    $originalKey = file_get_contents($path);
    $another = SecretCipher::encrypt($options['secret']);
    check($another !== $cipher, 'random IV changes ciphertext for same secret');
    foreach ([0, 12, 28] as $offset) {
        $bytes = base64_decode(substr($cipher, 7), true);
        $bytes[$offset] = chr(ord($bytes[$offset]) ^ 1);
        $tampered = 'enc:v1:' . base64_encode($bytes);
        rejects(function () use ($tampered) { SecretCipher::decrypt($tampered); }, 'GCM rejects altered IV/tag/ciphertext');
    }
    rejects(function () { SecretCipher::decrypt('enc:v1:' . base64_encode(str_repeat('x', 28))); }, 'truncated payload rejected');
    rejects(function () { SecretCipher::encrypt(''); }, 'empty secret rejected by cipher');
    $cipher = $stored['secret'];
    unlink($path);
    rejects(function () use ($cipher) { SecretCipher::decrypt($cipher); }, 'missing key cannot decrypt');
    check(!is_file($path), 'decrypt never generates replacement key');
    SecretCipher::encrypt('new-key-probe');
    rejects(function () use ($cipher) { SecretCipher::decrypt($cipher); }, 'wrong installation key rejected');
    file_put_contents($path, $originalKey);
    check(SecretCipher::decrypt($cipher) === $options['secret'], 'backup key restores decryption');
    file_put_contents($path, '<?php exit;');
    rejects(function () { SecretCipher::encrypt('probe'); }, 'corrupt key not silently overwritten');
    check(file_get_contents($path) === '<?php exit;', 'corrupt key preserved for operator recovery');
    file_put_contents($path, $originalKey);
    \SLiMS\DB::$raw = serialize($stored);
    $before = \SLiMS\DB::$raw; \SLiMS\DB::$fail = true;
    rejects(function () use ($options) { Settings::save($options); }, 'database save failure reported');
    check(\SLiMS\DB::$raw === $before, 'failed save retains stored record and key');
    \SLiMS\DB::$fail = false;
    $zero = $options; $zero['secret'] = '0';
    Settings::save($zero);
    check(unserialize(\SLiMS\DB::$raw, ['allowed_classes' => false])['secret'] !== '0', 'nonempty zero string is encrypted');
    check(Settings::load() === $zero, 'nonempty zero string round trip');
    // Simultaneous first saves: all worker ciphertexts must use one shared key.
    $processes = [];
    for ($i = 0; $i < 8; $i++) {
        $process = proc_open([PHP_BINARY, __FILE__, 'worker', $directory . '/parallel'],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        fclose($pipes[0]); $processes[] = [$process, $pipes];
    }
    foreach ($processes as [$process, $pipes]) {
        $encrypted = stream_get_contents($pipes[1]); $errors = stream_get_contents($pipes[2]);
        fclose($pipes[1]); fclose($pipes[2]);
        check(proc_close($process) === 0 && $errors === '', 'concurrent first key creation succeeds');
        $verify = proc_open([PHP_BINARY, __FILE__, 'verify', $directory . '/parallel'],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        fwrite($pipes[0], $encrypted); fclose($pipes[0]);
        stream_get_contents($pipes[1]); $errors = stream_get_contents($pipes[2]);
        fclose($pipes[1]); fclose($pipes[2]);
        check(proc_close($verify) === 0 && $errors === '', 'worker ciphertext decrypts using final shared key');
    }
    echo "PASS: $count encryption checks\n";
}
