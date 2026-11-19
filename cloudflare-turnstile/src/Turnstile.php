<?php
namespace SLiMS\Turnstile;

use SLiMS\Captcha\Factory;
use SLiMS\Captcha\Providers\Contract;

class Turnstile extends Contract
{
    private array $options;

    public function __construct(Factory $factory)
    {
        $this->factory = $factory;
        try {
            $this->options = Settings::load();
        } catch (\Throwable $e) {
            $this->options = ['unavailable' => true];
        }
    }

    public function generateCaptcha()
    {
        if (!empty($this->options['unavailable'])) {
            return '<div role="alert">Verifikasi keamanan belum tersedia. Hubungi administrator.</div>';
        }
        $key = htmlspecialchars((string) ($this->options['sitekey'] ?? ''), ENT_QUOTES, 'UTF-8');
        $action = htmlspecialchars($this->action(), ENT_QUOTES, 'UTF-8');
        $widget = '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>'
            . '<div class="cf-turnstile" data-sitekey="' . $key . '" data-action="' . $action
            . '" data-theme="auto" data-size="flexible" data-retry="auto" data-refresh-expired="auto"></div>'
            . '<noscript>Aktifkan JavaScript untuk menyelesaikan verifikasi keamanan.</noscript>';
        if ($this->factory->getCaptchaSection() === 'memberarea') {
            // Inherit the same theme width rules as the member password input.
            // Remove input decoration so the flexible widget fills the wrapper exactly.
            return '<div class="form-control slims-turnstile-member" style="height:auto;padding:0;border:0;background:transparent;box-shadow:none;">'
                . $widget . '</div>';
        }
        return $widget;
    }

    public function validate()
    {
        $this->error = null;
        if (!empty($this->options['unavailable'])) {
            return $this->fail('Konfigurasi verifikasi keamanan tidak dapat dibaca. Hubungi administrator.');
        }
        $token = $_POST['cf-turnstile-response'] ?? '';
        if (!is_string($token) || $token === '' || strlen($token) > 2048) {
            return $this->fail('Verifikasi keamanan belum selesai atau sudah kedaluwarsa. Silakan coba lagi.');
        }
        $secret = $this->options['secret'] ?? '';
        if (!is_string($secret) || $secret === '' || empty($this->options['hostnames'])) {
            return $this->fail('Konfigurasi Turnstile belum lengkap. Hubungi administrator.');
        }
        try {
            $result = $this->verifyToken($secret, $token);
            if (($result['success'] ?? null) !== true) {
                return $this->fail('Verifikasi keamanan gagal. Silakan muat ulang halaman dan coba lagi.');
            }
            // Exact allowlist from settings; never trust HTTP_HOST / forwarded headers.
            if (!is_string($result['hostname'] ?? null)
                || !in_array(strtolower($result['hostname']), $this->options['hostnames'], true)
                || ($result['action'] ?? null) !== $this->action()) {
                return $this->fail('Hostname atau tujuan verifikasi keamanan tidak sesuai.');
            }
            return true;
        } catch (\Throwable $e) {
            // Do not expose the secret, token, or raw transport response.
            return $this->fail('Layanan verifikasi keamanan tidak dapat dihubungi. Silakan coba lagi.');
        }
    }

    protected function verifyToken(string $secret, string $token): array
    {
        if (!function_exists('curl_init')) throw new \RuntimeException('cURL unavailable');
        $handle = curl_init('https://challenges.cloudflare.com/turnstile/v0/siteverify');
        if ($handle === false) throw new \RuntimeException('Cannot initialize transport');
        try {
            curl_setopt_array($handle, [
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => http_build_query(['secret' => $secret, 'response' => $token]),
                CURLOPT_HTTPHEADER => ['Content-Type: application/x-www-form-urlencoded'],
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_CONNECTTIMEOUT => 5,
                CURLOPT_TIMEOUT => 10,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_FOLLOWLOCATION => false,
            ]);
            $body = curl_exec($handle);
            if (!is_string($body) || curl_getinfo($handle, CURLINFO_HTTP_CODE) !== 200) {
                throw new \RuntimeException('Siteverify unavailable');
            }
            $result = json_decode($body, true);
            if (!is_array($result)) throw new \RuntimeException('Invalid response');
            return $result;
        } finally {
            curl_close($handle);
        }
    }

    private function action(): string
    {
        return 'slims_' . $this->factory->getCaptchaSection();
    }

    private function fail(string $message): bool
    {
        $this->error = $message;
        return false;
    }
}
