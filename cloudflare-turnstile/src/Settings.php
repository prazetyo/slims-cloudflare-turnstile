<?php
namespace SLiMS\Turnstile;

use SLiMS\DB;

require_once __DIR__ . '/SecretCipher.php';

/** Read plugin preferences independently of Config's file/global/default lookup. */
final class Settings
{
    public static function load(): array
    {
        $statement = DB::getInstance()->prepare(
            'SELECT setting_value FROM setting WHERE setting_name = :name LIMIT 1'
        );
        if (!$statement->execute(['name' => 'cloudflare_turnstile'])) {
            throw new \RuntimeException('Tidak dapat membaca pengaturan Turnstile.');
        }
        $raw = $statement->fetchColumn();
        if ($raw === false) return [];
        if (!is_string($raw) || strlen($raw) > 8192) {
            throw new \RuntimeException('Ukuran pengaturan Turnstile tidak valid.');
        }
        // SLiMS's global handler may render warnings even under @unserialize().
        // Contain parsing warnings here; never expose serialized keys in error pages.
        set_error_handler(static function () {
            throw new \RuntimeException('Format pengaturan Turnstile tidak valid.');
        });
        try {
            $value = unserialize($raw, ['allowed_classes' => false, 'max_depth' => 8]);
        } finally {
            restore_error_handler();
        }
        if (!is_array($value)) {
            throw new \RuntimeException('Format pengaturan Turnstile di database tidak valid.');
        }
        if (isset($value['_secret_encryption'])) {
            if ($value['_secret_encryption'] !== 'aes-256-gcm:v1' || !is_string($value['secret'] ?? null)) {
                throw new \RuntimeException('Versi enkripsi Secret Key tidak didukung.');
            }
            $value['secret'] = SecretCipher::decrypt($value['secret']);
            unset($value['_secret_encryption']);
        } elseif (is_string($value['secret'] ?? null) && strpos($value['secret'], 'enc:') === 0) {
            throw new \RuntimeException('Metadata enkripsi Secret Key hilang.');
        }
        self::validate($value);
        return $value;
    }

    private static function validate(array $options): void
    {
        $invalid = static function () {
            throw new \RuntimeException('Isi pengaturan Turnstile tidak valid.');
        };
        if (!array_key_exists('enabled', $options) || !is_bool($options['enabled'])) $invalid();
        foreach (['librarian', 'memberarea', 'forgot'] as $section) {
            if (array_key_exists($section, $options) && !is_bool($options[$section])) $invalid();
            if ($options['enabled'] && !array_key_exists($section, $options)) $invalid();
        }
        foreach (['sitekey', 'secret'] as $key) {
            if (isset($options[$key]) && (!is_string($options[$key]) || strlen($options[$key]) > 255
                || preg_match('/[\x00-\x1f\x7f]/', $options[$key]))) $invalid();
            if ($options['enabled'] && (!isset($options[$key]) || $options[$key] === '')) $invalid();
        }
        if (isset($options['hostnames'])) {
            if (!is_array($options['hostnames']) || count($options['hostnames']) > 10) $invalid();
            foreach ($options['hostnames'] as $host) {
                if (!is_string($host) || strlen($host) > 253 || strpos($host, '.') === false
                    || !filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) $invalid();
            }
        }
        if ($options['enabled'] && empty($options['hostnames'])) $invalid();
    }

    public static function save(array $options): void
    {
        self::validate($options);
        // Never accept caller-provided encryption metadata or write a plaintext secret.
        if (array_key_exists('_secret_encryption', $options)) {
            throw new \RuntimeException('Metadata enkripsi tidak boleh diisi melalui form.');
        }
        $stored = $options;
        if (isset($options['secret']) && $options['secret'] !== '') {
            $stored['secret'] = SecretCipher::encrypt($options['secret']);
            $stored['_secret_encryption'] = 'aes-256-gcm:v1';
        }
        $statement = DB::getInstance()->prepare(
            'INSERT INTO setting (setting_name, setting_value) VALUES (:name, :value) '
            . 'ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)'
        );
        if (!$statement->execute(['name' => 'cloudflare_turnstile', 'value' => serialize($stored)])) {
            throw new \RuntimeException('Pengaturan Turnstile gagal disimpan.');
        }
        // Success means it can also be read through the same path used on the next request.
        if (self::load() !== $options) {
            throw new \RuntimeException('Verifikasi penyimpanan Turnstile gagal.');
        }
    }
}
