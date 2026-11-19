<?php
namespace SLiMS\Turnstile;

final class SecretCipher
{
    private const PREFIX = 'enc:v1:';
    private const AAD = 'slims-cloudflare-turnstile:secret:v1';
    private const HEADER = "<?php\nhttp_response_code(404);\nexit;\n__halt_compiler();\n";

    public static function available(): bool
    {
        return function_exists('openssl_encrypt') && function_exists('openssl_decrypt')
            && in_array('aes-256-gcm', openssl_get_cipher_methods(), true);
    }

    public static function encrypt(string $secret): string
    {
        if ($secret === '' || strlen($secret) > 255) throw new \RuntimeException('Panjang Secret Key tidak valid.');
        if (!self::available()) throw new \RuntimeException('Ekstensi OpenSSL AES-GCM diperlukan.');
        $key = self::key(true);
        $iv = random_bytes(12);
        $tag = '';
        $encrypted = openssl_encrypt($secret, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, self::AAD, 16);
        if ($encrypted === false || strlen($tag) !== 16) throw new \RuntimeException('Enkripsi Secret Key gagal.');
        return self::PREFIX . base64_encode($iv . $tag . $encrypted);
    }

    public static function decrypt(string $encrypted): string
    {
        if (!self::available()) throw new \RuntimeException('Ekstensi OpenSSL AES-GCM diperlukan.');
        if (strpos($encrypted, self::PREFIX) !== 0 || strlen($encrypted) > 1024) {
            throw new \RuntimeException('Format enkripsi Secret Key tidak valid.');
        }
        $bytes = base64_decode(substr($encrypted, strlen(self::PREFIX)), true);
        // Fixed framing: 12-byte IV, 16-byte tag, 1..255-byte ciphertext.
        if (!is_string($bytes) || strlen($bytes) < 29 || strlen($bytes) > 283) {
            throw new \RuntimeException('Data enkripsi Secret Key tidak valid.');
        }
        $plain = openssl_decrypt(substr($bytes, 28), 'aes-256-gcm', self::key(false), OPENSSL_RAW_DATA,
            substr($bytes, 0, 12), substr($bytes, 12, 16), self::AAD);
        if ($plain === false) throw new \RuntimeException('Secret Key tidak dapat didekripsi.');
        return $plain;
    }

    private static function key(bool $create): string
    {
        $directory = defined('SLIMS_TURNSTILE_KEY_DIRECTORY')
            ? SLIMS_TURNSTILE_KEY_DIRECTORY : dirname(__DIR__) . '/private';
        if (!is_string($directory) || $directory === '') throw new \RuntimeException('Lokasi kunci tidak valid.');
        $path = rtrim($directory, '/\\') . '/encryption-key.php';
        // Contain filesystem warnings; never let a warning renderer receive key material.
        set_error_handler(static function () {
            throw new \RuntimeException('File kunci tidak dapat diakses. Periksa izin folder private plugin.');
        });
        try {
            if (is_link($directory) || is_link($path)) throw new \RuntimeException('Lokasi kunci tidak boleh symlink.');
            if (is_file($path)) return self::readKey($path);
            if (!$create) throw new \RuntimeException('File kunci enkripsi hilang. Pulihkan backup atau isi ulang Secret Key.');
            $oldMask = umask(0077);
            try {
                if (!is_dir($directory) && !mkdir($directory, 0700, true) && !is_dir($directory)) {
                    throw new \RuntimeException('Folder kunci tidak dapat dibuat.');
                }
                $lockPath = rtrim($directory, '/\\') . '/.key.lock';
                if (is_link($lockPath)) throw new \RuntimeException('File lock tidak valid.');
                $lock = fopen($lockPath, 'c+b');
                if ($lock === false) throw new \RuntimeException('File lock tidak dapat dibuat.');
                $temporary = null;
                try {
                    if (!flock($lock, LOCK_EX)) throw new \RuntimeException('Kunci tidak dapat dikunci.');
                    // Concurrent first saves must use the same key, never overwrite one another.
                    clearstatcache(true, $path);
                    if (is_link($path)) throw new \RuntimeException('File kunci tidak valid.');
                    if (is_file($path)) return self::readKey($path);
                    $key = random_bytes(32);
                    $temporary = rtrim($directory, '/\\') . '/key-' . bin2hex(random_bytes(12)) . '.php';
                    $handle = fopen($temporary, 'xb');
                    if ($handle === false) throw new \RuntimeException('File kunci tidak dapat dibuat.');
                    try {
                        if (!chmod($temporary, 0600)) throw new \RuntimeException('Izin file kunci gagal diatur.');
                        $data = self::HEADER . base64_encode($key) . "\n";
                        if (fwrite($handle, $data) !== strlen($data) || !fflush($handle)) {
                            throw new \RuntimeException('File kunci gagal ditulis.');
                        }
                    } finally {
                        fclose($handle);
                    }
                    if (!rename($temporary, $path)) throw new \RuntimeException('File kunci gagal disimpan.');
                    $temporary = null;
                    return $key;
                } finally {
                    try {
                        if ($temporary !== null && is_file($temporary)) unlink($temporary);
                    } finally {
                        flock($lock, LOCK_UN);
                        fclose($lock);
                    }
                }
            } finally {
                umask($oldMask);
            }
        } finally {
            restore_error_handler();
        }
    }

    private static function readKey(string $path): string
    {
        $data = file_get_contents($path, false, null, 0, 1024);
        if (!is_string($data) || strpos($data, self::HEADER) !== 0) {
            throw new \RuntimeException('File kunci enkripsi tidak valid.');
        }
        $key = base64_decode(trim(substr($data, strlen(self::HEADER))), true);
        if (!is_string($key) || strlen($key) !== 32) throw new \RuntimeException('Kunci enkripsi tidak valid.');
        return $key;
    }
}
