<?php
use SLiMS\Turnstile\Settings;
use Volnix\CSRF\CSRF;

defined('INDEX_AUTH') or die('Direct access is not allowed!');
require_once SB . 'admin/default/session.inc.php';
require_once SB . 'admin/default/session_check.inc.php';
require_once LIB . 'ip_based_access.inc.php';
do_checkIP('smc');
do_checkIP('smc-system');
if (!utility::havePrivilege('system', 'r') || !utility::havePrivilege('system', 'w')) {
    http_response_code(403);
    exit('Anda tidak memiliki hak akses pengaturan sistem.');
}

$error = '';
try {
    $options = Settings::load();
} catch (Throwable $e) {
    $options = [];
    $error = 'Pengaturan tidak dapat dibaca. Isi ulang kunci dan hostname untuk memperbaikinya. Login dilindungi tetap diblokir sampai konfigurasi diperbaiki.';
}
if (isset($_POST['saveTurnstile'])) {
    $error = '';
    $csrfInput = $_POST[CSRF::getTokenName()] ?? null;
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST' || !is_string($csrfInput)
        || strlen($csrfInput) > 256 || !CSRF::validate($_POST)) {
        $error = 'Form tidak valid. Muat ulang halaman pengaturan.';
    } else {
        $read = static function (string $name): string {
            return isset($_POST[$name]) && is_string($_POST[$name]) ? trim($_POST[$name]) : '';
        };
        $hostnameInput = strtolower($read('hostnames'));
        $hosts = $hostnameInput === '' ? [] : [$hostnameInput];
        $new = [
            'enabled' => isset($_POST['enabled']),
            'sitekey' => $read('sitekey'),
            'secret' => $read('secret') ?: ($options['secret'] ?? ''),
            'hostnames' => array_values(array_unique($hosts)),
            'librarian' => isset($_POST['librarian']),
            'memberarea' => isset($_POST['memberarea']),
            'forgot' => isset($_POST['forgot']),
        ];
        foreach ($new['hostnames'] as $hostname) {
            if (!filter_var($hostname, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)
                || strpos($hostname, '.') === false || strlen($hostname) > 253) {
                $error = 'Hostname harus berupa domain tanpa protokol, port, wildcard, atau path.';
                break;
            }
        }
        if ($new['enabled'] && (!$new['sitekey'] || !$new['secret'] || !$new['hostnames'])) {
            $error = 'Lengkapi Site Key, Secret Key, dan hostname sebelum mengaktifkan Turnstile.';
        }
        if ($new['enabled'] && !function_exists('curl_init')) {
            $error = 'Ekstensi PHP cURL harus tersedia sebelum Turnstile diaktifkan.';
        }
        if ($new['enabled'] && (preg_match('/^[123]x0/', $new['sitekey']) || preg_match('/^[123]x0/', $new['secret']))) {
            $error = 'Gunakan kunci asli. Kunci dummy tidak mendukung pemeriksaan hostname/action plugin ini.';
        }
        if (!$error) {
            try {
                Settings::save($new);
                $options = $new;
                toastr('Pengaturan Turnstile tersimpan dan berhasil dibaca kembali dari database.')->success();
            } catch (Throwable $e) {
                $error = 'Pengaturan gagal disimpan. Pastikan OpenSSL tersedia dan folder private plugin dapat ditulis PHP; jangan gunakan izin 777.';
            }
        }
    }
}
if (isset($_POST['saveTurnstile'])) {
    if ($error) toastr($error)->error();
    // SLiMS submits this form through an iframe; refresh the parent's rotated CSRF token.
    $tokenName = json_encode(CSRF::getTokenName(), JSON_HEX_TAG | JSON_HEX_AMP);
    $tokenValue = json_encode(CSRF::getToken(), JSON_HEX_TAG | JSON_HEX_AMP);
    echo '<script>(function(){var f=parent.document.getElementById("mainForm");if(!f)return;var t=f.elements.namedItem(' . $tokenName . ');if(t)t.value=' . $tokenValue . ';})();</script>';
    exit;
}
$escape = static function ($value): string {
    return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
};
require_once SIMBIO . 'simbio_GUI/table/simbio_table.inc.php';
require_once SIMBIO . 'simbio_GUI/form_maker/simbio_form_table_AJAX.inc.php';
$action = AWB . 'plugin_container.php?' . http_build_query(['mod' => 'system', 'id' => md5(realpath(__FILE__))]);
?>
<div class="menuBox"><div class="menuBoxInner systemIcon"><div class="per_title"><h2>Cloudflare Turnstile 1.0.8</h2></div></div></div>
<?php if ($error): ?><div class="errorBox"><?= $escape($error) ?></div><?php endif; ?>
<?php if (is_file(__DIR__ . '/DISABLED')): ?><div class="errorBox">Mode pemulihan aktif: hapus file DISABLED di folder plugin untuk menjalankan Turnstile.</div><?php endif; ?>
<div class="infoBox">Buat widget Managed di Cloudflare dan daftarkan hostname SLiMS. Secret Key dienkripsi saat disimpan dan tidak ditampilkan kembali. Kunci enkripsi dibuat otomatis di private/encryption-key.php; cadangkan file ini dan jangan hapus saat upgrade. Untuk data lama, klik Simpan Pengaturan sekali untuk mengenkripsi Secret Key tersimpan. Pengaturan ini menggantikan provider CAPTCHA selama Turnstile aktif. CAPTCHA bawaan kembali digunakan setelah plugin dinonaktifkan.</div>
<?php
$form = new simbio_form_table_AJAX('mainForm', $action, 'post');
$form->table_attr = 'id="dataList" class="s-table table"';
$form->table_header_attr = 'class="alterCell font-weight-bold"';
$form->table_content_attr = 'class="alterCell2"';
$form->submit_button_attr = 'name="saveTurnstile" value="Simpan Pengaturan" class="btn btn-default"';
$form->addAnything('Aktifkan Turnstile', CSRF::getHiddenInputString() . '<label><input type="checkbox" name="enabled" value="1"' . (!empty($options['enabled']) ? ' checked' : '') . '> Aktif</label>');
$form->addAnything('Site Key', '<input class="form-control" type="text" name="sitekey" maxlength="255" value="' . $escape($options['sitekey'] ?? '') . '">');
$form->addAnything('Secret Key', '<input class="form-control" type="password" name="secret" maxlength="255" autocomplete="new-password" value=""><small>Kosongkan untuk mempertahankan Secret Key tersimpan.</small>');
$form->addAnything('Hostname SLiMS', '<input class="form-control" type="text" name="hostnames" maxlength="253" placeholder="opac.example.org" value="' . $escape(implode(', ', $options['hostnames'] ?? [])) . '"><small>Isi satu hostname tanpa https:// atau path, sesuai widget Cloudflare.</small>');
$sections = '';
foreach (['librarian' => 'Login pustakawan', 'memberarea' => 'Login anggota', 'forgot' => 'Lupa password pustakawan'] as $section => $label) {
    $checked = !array_key_exists($section, $options) || !empty($options[$section]);
    $sections .= '<label class="d-block"><input type="checkbox" name="' . $section . '" value="1"' . ($checked ? ' checked' : '') . '> ' . $label . '</label>';
}
$form->addAnything('Halaman yang dilindungi', $sections . '<small>Pertahankan proteksi lupa password agar alur reset bawaan tetap dapat digunakan.</small>');
echo $form->printOut();
