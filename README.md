# Cloudflare Turnstile untuk SLiMS Bulian

Plugin Cloudflare Turnstile untuk membantu melindungi halaman login pustakawan/pengguna sistem, login anggota perpustakaan, dan lupa password pustakawan pada SLiMS Bulian.

**Versi plugin: 1.0.8** · **Pengembang: Agung PW**

[Unduh plugin 1.0.8](dist/cloudflare-turnstile-1.0.8.zip?raw=true)

## Cara kerja

Plugin menampilkan widget Turnstile pada form yang dipilih. Saat form dikirim, server memvalidasi token melalui Cloudflare Siteverify dan memeriksa hostname serta tujuan verifikasinya sebelum SLiMS melanjutkan proses login.

Integrasi menggunakan sistem plugin dan provider CAPTCHA SLiMS. Tidak perlu mengedit core atau template bawaan. Secret Key dienkripsi saat disimpan di database; Site Key tetap publik sesuai kebutuhan widget.

## Kebutuhan

- SLiMS Bulian 9.7.2 atau 9.8.0; instalasi lain perlu diperiksa kompatibilitasnya.
- PHP sesuai persyaratan SLiMS, dengan ekstensi cURL dan OpenSSL yang mendukung AES-256-GCM.
- Akun Cloudflare dan widget Turnstile mode **Managed**.
- Browser dan server dapat mengakses `challenges.cloudflare.com`.
- Folder `private` di dalam plugin dapat ditulis oleh user PHP. Jangan gunakan izin `777`.

## Cara pasang

1. Unduh ZIP plugin pada tautan di atas, lalu ekstrak folder `cloudflare-turnstile` ke direktori `plugins/` SLiMS.
2. Aktifkan **Cloudflare Turnstile** melalui menu pengelola plugin SLiMS.
3. Buat widget **Managed** di dashboard Cloudflare Turnstile dan daftarkan hostname situs.
4. Buka **System → Cloudflare Turnstile**, lalu isi Site Key, Secret Key, dan hostname situs. Gunakan domain saja, misalnya `opac.domainanda.ac.id`, tanpa `https://`, port, atau path.
5. Pilih halaman yang dilindungi, centang **Aktif**, lalu klik **Simpan Pengaturan**.
6. Uji login pustakawan dan anggota melalui browser privat sambil mempertahankan sesi admin yang masih aktif.

Jika mengunduh seluruh repository melalui **Code → Download ZIP**, gunakan subfolder `cloudflare-turnstile` sebagai folder plugin; jangan menyalin seluruh folder repository ke `plugins/`.

## Catatan

- Setiap instalasi memakai kunci Cloudflare dan hostname miliknya sendiri. Paket distribusi tidak menyertakan kredensial atau file kunci enkripsi instalasi.
- Kolom Secret Key sengaja ditampilkan kosong. Saat menyimpan, biarkan kosong untuk mempertahankan nilai sebelumnya.
- Untuk pembaruan, timpa file plugin tanpa menghapus folder `private`. Setelah memperbarui versi lama, simpan pengaturan sekali untuk mengenkripsi Secret Key yang sebelumnya tersimpan biasa.
- Kunci enkripsi dibuat otomatis. Jangan membagikan `private/encryption-key.php` dari situs aktif atau menyertakannya dalam paket komunitas.
- CSP tambahan pada web server/proxy dan template/login kustom mungkin memerlukan penyesuaian. Halaman yang tidak memakai slot CAPTCHA bawaan tidak otomatis tercakup.
- Turnstile tidak menggantikan keamanan core, HTTPS, pembatasan percobaan login, maupun pengamanan server. API/SSO/login kustom tidak otomatis dilindungi.
- Pengujian terisolasi telah dilakukan dengan Config/Factory SLiMS 9.7.2 dan 9.8.0, termasuk validasi token, CSRF, konfigurasi, dan enkripsi. Hasilnya bukan jaminan bebas kerentanan; pengujian di masing-masing instalasi tetap diperlukan.

## Struktur repository

- `cloudflare-turnstile/`: source plugin siap dipasang, tanpa file `.md`.
- `cloudflare-turnstile/INSTALL.txt`: petunjuk pemasangan singkat.
- `dist/`: ZIP distribusi komunitas.
- `LICENSE`: teks lisensi GNU GPL v3.

## Kontak dan laporan masalah

- Website: https://agungprasetyo.net/
- GitHub: https://github.com/prazetyo
- Bug dan masukan: https://github.com/prazetyo/slims-cloudflare-turnstile/issues

## Lisensi

Plugin ini didistribusikan dengan **GNU General Public License versi 3 (GPL v3)**, sejalan dengan lisensi SLiMS. Anda dapat menggunakan, memodifikasi, dan membagikannya kembali sesuai ketentuan [LICENSE](LICENSE). Tidak ada jaminan tersurat maupun tersirat.

Cloudflare Turnstile merupakan layanan pihak ketiga; penggunaan layanan tersebut mengikuti ketentuan Cloudflare. Plugin ini bukan produk resmi Cloudflare.
