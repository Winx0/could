# HDD Deleted File Recovery Guide untuk Wallet ID

## Konteks

User: HDD tidak pernah ganti, tapi Windows pernah reinstall. Data 2020 mungkin masih ada di sektor disk yang ditandai "deleted" tapi belum di-overwrite.

## Tahap 1: Scan File AKTIF (Yang Belum Dihapus)

```powershell
cd C:\Users\"ERWIN SYAH ST"\Desktop\could
git pull origin recovery-toolkit
cd recovery_toolkit

# Scan semua drive D: sampai F: yang ada
python extract_wallet_id_smart.py --all-drives
```

Atau spesifik per drive:

```powershell
python extract_wallet_id_smart.py --grep-multi "D:\,E:\,F:\"
```

⏱️ **30-90 menit** tergantung total ukuran data.

## Tahap 2: Recovery File DELETED dari Disk

### Step 1: Download PhotoRec

Open-source, free, paling reliable untuk file recovery:
- Website: https://www.cgsecurity.org/wiki/TestDisk_Download
- Download: **TestDisk & PhotoRec** (Windows 64-bit)
- Extract ke USB drive (jangan ke C: untuk avoid overwrite)

### Step 2: Run PhotoRec

```powershell
# Run dari USB
F:\testdisk-7.x\photorec_win.exe
```

GUI text-based:
1. Select disk drive (HDD lama Anda)
2. Select partition table type: **Intel/PC**
3. Pilih **Free** (scan unallocated space = file deleted)
4. Pilih partisi target (misal D: atau E:)
5. **File Opt** → enable hanya:
   - `txt` (text files)
   - `json` (JSON termasuk wallet.aes.json)
   - `sqlite` (browser data)
   - `ldb` (LevelDB browser localStorage)
6. Output destination: drive **EXTERNAL** (USB) — jangan output ke disk yang di-scan!
7. **Search**

### Step 3: Wait for Recovery (Slow)

⏱️ **2-12 jam** tergantung ukuran disk dan jumlah deleted files.

PhotoRec akan recover **ribuan file** ke folder output. File names akan generic seperti `f0123456.json`, `f0234567.txt`.

### Step 4: Filter Hasil PhotoRec

```powershell
# Pindah ke folder output PhotoRec
cd F:\photorec_recovery_output

# Filter file JSON yang berisi pattern Blockchain.com format
Get-ChildItem -Filter "*.json" -Recurse | ForEach-Object {
    if ((Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue) -match '"payload".*"guid"|"guid".*"payload"') {
        Write-Host "MATCH: $($_.FullName)" -ForegroundColor Green
    }
}
```

Atau gunakan smart scanner:

```powershell
python C:\Users\"ERWIN SYAH ST"\Desktop\could\recovery_toolkit\extract_wallet_id_smart.py --grep "F:\photorec_recovery_output"
```

## Tahap 3: Recovery via Windows Shadow Copy

Windows kadang menyimpan snapshot otomatis. Cek apakah ada:

```powershell
vssadmin list shadows
```

Kalau ada snapshot dari era 2020-2022, restore via:
```powershell
vssadmin list shadows /for=C:
# Mount snapshot
```

## Tahap 4: Recovery Tools Alternative

Kalau PhotoRec terlalu kompleks, alternatif lebih user-friendly:

### Recuva (Free, Windows)
- Download: https://www.ccleaner.com/recuva
- Pilih: **Documents & Pictures**
- Scan target drive
- Filter hasil dengan keyword `wallet`, `blockchain`

### R-Studio (Trial)
- Lebih powerful tapi berbayar untuk full features

## Tahap 5: Untuk Ekstrak Browser Data Spesifik

Kalau Anda ingat browser apa yang Anda pakai 2020 (Chrome/Firefox/Brave), recovery file LevelDB-nya:

```
File extension yang harus di-recover dari deleted space:
- .ldb (LevelDB)
- .log (LevelDB write-ahead log)
- .sqlite (Firefox)
- .localstorage (legacy)
```

## Realistic Expectations

| Skenario | Probability |
|---|---|
| File 2020 masih ada di sektor & PhotoRec recover | 30-60% |
| Wallet ID ditemukan di recovered files | 20-40% |
| Wallet ID berisi address `1B8hg...` | 30-50% |
| **Total: recovery sukses** | **5-15%** |

## Catatan Penting

1. **HDD sudah dipakai 5+ tahun** — banyak sektor mungkin sudah di-overwrite oleh aktivitas baru
2. **PhotoRec bisa recover RIBUAN file** — siapkan disk besar (200GB+) untuk output
3. **Scan time bisa 12+ jam** untuk full HDD scan
4. **Jangan tulis ke disk yang sedang di-scan** — selalu output ke USB/disk lain
