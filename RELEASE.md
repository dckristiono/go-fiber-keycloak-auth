# Release Process

Dokumen ini menjelaskan proses rilis untuk `go-fiber-keycloak-auth`.

## Versioning

Proyek ini menggunakan [Semantic Versioning (SemVer)](https://semver.org/). Format versi: `vMAJOR.MINOR.PATCH`.

- **MAJOR**: Perubahan yang tidak kompatibel dengan versi sebelumnya
- **MINOR**: Penambahan fitur yang kompatibel dengan versi sebelumnya
- **PATCH**: Perbaikan bug yang kompatibel dengan versi sebelumnya

## Proses Rilis

1. Pastikan semua tests berjalan dengan baik:
   ```bash
   go test -v ./...
   ```

2. Update nilai versi di file dokumentasi jika diperlukan.

3. Buat tag baru dengan format `vX.Y.Z`:
   ```bash
   git tag -a vX.Y.Z -m "Release vX.Y.Z"
   ```

4. Push tag ke GitHub:
   ```bash
   git push origin vX.Y.Z
   ```

5. GitHub Action akan secara otomatis:
    - Menjalankan tests
    - Membuat GitHub Release
    - Menghasilkan changelog berdasarkan commit sejak rilis terakhir

## Changelog

Changelog untuk setiap rilis dihasilkan secara otomatis dari pesan commit. Untuk memastikan changelog yang baik:

- Gunakan format pesan commit yang konsisten
- Prefix commit dengan kategori (`feat:`, `fix:`, `docs:`, dll.)
- Tulis pesan yang jelas dan deskriptif

Commit yang diawali dengan `docs:`, `test:`, dan `ci:` tidak akan muncul di changelog.

## Rilis

### v0.1.0 (Initial Release)

Fitur utama:
- Validasi token Keycloak menggunakan JWKS
- Role-based access control untuk GoFiber routes
- Middleware terpadu `Auth()` dengan konfigurasi fleksibel
- Attribute mapping dari token Keycloak ke context Fiber
- Role-based attribute mapping
- Caching JWKS untuk performa optimal
- Fungsi helper untuk mengakses informasi token

## Checklist Pra-Rilis

- [ ] Semua tests berjalan sukses
- [ ] Dokumentasi telah diperbarui
- [ ] Examples telah diperbarui
- [ ] Breaking changes telah didokumentasikan (jika ada)
- [ ] PR terkait telah di-merge