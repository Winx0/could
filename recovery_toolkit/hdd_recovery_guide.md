# HDD Recovery Guide untuk Wallet `1B8hgFxNK7ac2k5EtrAanxQPFcnfHLMcko`

Untuk: HDD (Hard Disk Drive) yang masih terpakai sejak 2020.

---

## CRITICAL: Lakukan Sebelum Apapun!

### Stop Menulis ke Disk Sebanyak Mungkin

Setiap byte baru yang Anda tulis ke disk berpotensi menimpa data wallet lama. Sebelum recovery:

1. JANGAN install software apapun ke disk yang sama
2. JANGAN download file besar
3. JANGAN restart yang tidak perlu (Windows menulis swap/page file)
4. Idealnya: matikan PC, pasang HDD sebagai external (slave) di PC lain

Kalau itu tidak mungkin, install recovery tool ke USB / partisi berbeda dari yang berisi data lama.

---

## 4 Strategi Recovery (Urutan dari Mudah ke Sulit)

### Strategi 1: Cari Langsung di Filesystem (5 menit) — MULAI DARI SINI

File mungkin masih ada utuh di filesystem, hanya saja Anda lupa lokasinya.

#### Windows
Buka **PowerShell** (sebagai Admin):

```powershell
# Cari di seluruh disk C:
Get-ChildItem -Path C:\ -Filter "*.aes.json" -Recurse -Force -ErrorAction SilentlyContinue | Select-Object FullName, Length, LastWriteTime

# Cari semua file wallet
Get-ChildItem -Path C:\ -Include "wallet*","*.aes.json","*backup*.json","*seed*","*recovery*" -Recurse -Force -ErrorAction SilentlyContinue

# Cari di Windows.old (kalau pernah reinstall)
Get-ChildItem -Path "C:\Windows.old" -Filter "*.aes.json" -Recurse -Force -ErrorAction SilentlyContinue

# Cari di profil user lama
Get-ChildItem -Path "C:\Users" -Filter "*.aes.json" -Recurse -Force -ErrorAction SilentlyContinue
```

Atau pakai File Explorer:
- Tekan `Win + E`
- Klik bar "This PC"
- Search box (kanan atas): `*.aes.json`
- Centang opsi "Hidden items" di tab View

#### Mac/Linux
```bash
# Search dengan find
sudo find / -name "*.aes.json" 2>/dev/null
sudo find / -name "wallet.aes.json" 2>/dev/null
sudo find / -iname "*blockchain*" 2>/dev/null

# Search dengan locate (kalau database updated)
sudo updatedb
locate "wallet.aes.json"
locate "*.aes.json"
```

### Strategi 2: Cek Volume Shadow Copy / Restore Points (10 menit)

Windows otomatis bikin snapshot disk. Kalau pernah aktif, file lama bisa di-restore.

#### Windows PowerShell (Admin):
```powershell
# Lihat snapshot yang tersedia
vssadmin list shadows
```

Atau via UI:
1. Klik kanan folder `C:\Users\NamaAnda` → Properties
2. Tab "Previous Versions"
3. Kalau ada snapshot lama (Aug 2020 atau setelahnya), buka & cek isi

### Strategi 3: Recovery Software (30-60 menit) — PALING POWERFUL

Pakai software recovery untuk scan sektor disk yang "dihapus" tapi belum ter-overwrite.

#### Pilihan Software (Free)

| Software | OS | Speciality | Link |
|---|---|---|---|
| Recuva | Windows | User-friendly, deep scan | https://www.ccleaner.com/recuva |
| PhotoRec (TestDisk) | All | File signature recovery, paling powerful | https://www.cgsecurity.org/wiki/PhotoRec |
| Disk Drill | Windows/Mac | UI bagus, free trial | https://www.cleverfiles.com/ |
| R-Studio | All | Professional, paling robust | https://www.r-tt.com/ |

#### Rekomendasi: Recuva (untuk pemula) atau PhotoRec (untuk power user)

##### Recuva Step-by-Step:

1. **Download** Recuva ke USB drive (jangan install di disk yang berisi data lama)
2. **Run as Admin**
3. **Pilih disk** yang berisi data lama
4. **File type**: pilih "All Files" atau filter "Documents"
5. **Aktifkan "Deep Scan"** (lebih lama tapi lebih thorough)
6. Scan akan jalan 1-3 jam tergantung ukuran disk
7. **Filter hasil** dengan keyword: `wallet`, `aes`, `seed`, `recovery`, `bitcoin`
8. **Recover** ke disk BERBEDA (USB external, atau partisi lain)

##### PhotoRec Step-by-Step (Lebih Powerful):

1. Download TestDisk/PhotoRec dari https://www.cgsecurity.org
2. Extract ke USB
3. Run `photorec_win.exe` (Windows) atau `photorec` (Mac/Linux)
4. Pilih disk -> pilih partition
5. **File Opt** -> enable: `txt`, `json` (kalau ada)
6. **File System** -> pilih "Other" untuk NTFS
7. **Free** atau **Whole** scan
8. Output ke disk berbeda
9. Setelah selesai, pakai `local_search.py` dari toolkit kita untuk sortir hasil

### Strategi 4: Browser Cache / localStorage Recovery

Bahkan kalau file utama hilang, browser mungkin cache-kan data Blockchain.com:

#### Cek Chrome (Windows):
```
C:\Users\NamaAnda\AppData\Local\Google\Chrome\User Data\Default\Local Storage\leveldb\
```

#### Cek Firefox:
```
C:\Users\NamaAnda\AppData\Roaming\Mozilla\Firefox\Profiles\
```

Pakai tool kita:
```bash
python extract_wallet_id.py --scan
```

Akan otomatis scan browser localStorage untuk Wallet IDs dan referensi Blockchain.com.

#### Untuk Browser Profile yang Lebih Lama:

Kalau Anda pakai browser yang sama dari 2020 sampai sekarang **tanpa clear data**, localStorage Blockchain.com kemungkinan masih ada walau file utama hilang.

---

## Workflow Optimal untuk Anda

```
+---------------------------------------------------------+
|  Step 1: STOP gunakan disk untuk hal-hal baru          |
|  Step 2: PowerShell search (5 min) - mungkin langsung  |
|          ketemu                                          |
|  Step 3: Cek Windows.old - kalau ada, JACKPOT          |
|  Step 4: Cek browser localStorage dengan tool kita     |
|  Step 5: Recuva deep scan - 1-3 jam                    |
|  Step 6: PhotoRec full scan - 4-12 jam                 |
|  Step 7: Pakai blockchain_decrypt.py untuk decrypt     |
|          file yang ditemukan                            |
+---------------------------------------------------------+
```

---

## Checklist File yang Anda Cari

Setelah scan, prioritaskan file dengan ciri:

### Filename
- `wallet.aes.json` ** JACKPOT
- `*.aes.json`
- `wallet.json`
- File dengan size 1-50 KB berisi text "payload"

### Lokasi yang Sering
- `C:\Users\NamaAnda\Downloads\`
- `C:\Users\NamaAnda\Desktop\`
- `C:\Users\NamaAnda\Documents\`
- `C:\Users\NamaAnda\AppData\Local\Google\Chrome\` (browser data)
- `C:\Users\NamaAnda\AppData\Roaming\` (app data)
- Folder backup pribadi Anda

### Konten (kalau buka file)
- Format JSON: `{"guid": "...", "version": ..., "payload": "..."}`
- Atau langsung berupa string base64 panjang

---

## Saya Akan Bantu Real-Time

Setelah Anda jalankan command-command di atas, kabari saya:
- Apakah PowerShell search ketemu file?
- Apakah ada folder `Windows.old`?
- Hasil Recuva scan ada `aes.json`?

Saya bisa bantu interpretasi hasil dan langkah selanjutnya.
