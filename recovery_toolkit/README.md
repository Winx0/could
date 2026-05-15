# Bitcoin Wallet Recovery Toolkit

Untuk address: `1B8hgFxNK7ac2k5EtrAanxQPFcnfHLMcko`
Saldo: 0.00318536 BTC

---

## ⚠️ KEAMANAN — BACA DULU

1. **Jalankan SEMUA script ini di komputer pribadi Anda** — JANGAN di server cloud, JANGAN di komputer publik
2. **Idealnya offline** — cabut WiFi/LAN saat menjalankan, terutama saat menampilkan seed/key
3. **JANGAN paste output ke ChatGPT, Claude, AI manapun, forum, Telegram, dll**
4. **JANGAN install ini dari sumber tidak resmi** — verify isi script-nya sendiri sebelum run
5. **Hapus file output (`recovery_findings.txt`, `decrypted_wallet.json`) setelah selesai**

---

## Setup (sekali saja)

Butuh Python 3.8+. Install dependencies:

```bash
pip install bip_utils mnemonic pycryptodome
```

---

## Tool 1: `address_finder.py` — Validasi Seed/Key

**Pakai kalau Anda PUNYA seed phrase atau private key** dan mau cek apakah cocok dengan address target.

```bash
python address_finder.py
```

Pilihan menu:
1. Punya 12-kata seed lengkap → cek di semua derivation path standar
2. Punya 11 kata, lupa 1 kata → brute force 1 kata yang hilang (2048 percobaan, cepat)
3. Punya WIF private key (`5...`, `K...`, `L...`)
4. Punya hex private key (64 karakter hex)
5. Punya beberapa kata acak → cek mana yang valid BIP39

---

## Tool 2: `local_search.py` — Scan Komputer

**Pakai untuk mencari file yang mungkin berisi seed/key di komputer Anda**.

```bash
# Scan home directory
python local_search.py ~

# Atau folder spesifik
python local_search.py /path/to/folder

# Windows
python local_search.py "C:\Users\YourName"
```

Yang dicari:
- File berisi 12/18/24 kata BIP39 berurutan
- File berisi WIF private key
- File berisi hex 64-char yang berpotensi private key
- File berisi extended key (`xprv...`)
- Filename mencurigakan (wallet.dat, seed.txt, recovery, dll)
- File yang menyebut address target

Output: `recovery_findings.txt` di folder kerja. **REVIEW LALU DELETE**.

Tip: Sebelum scan, pikirkan dulu:
- Folder backup HP lama Anda (Android backup, iCloud backup)
- Folder Documents, Downloads, Desktop
- Folder Notes app (jika sync ke filesystem)
- File `.bak`, `.old` yang Anda simpan

---

## Tool 3: `blockchain_decrypt.py` — Decrypt Blockchain.com Backup

**Pakai kalau Anda PUNYA file `wallet.aes.json`** dari Blockchain.com (biasanya didownload dari menu "Backup" atau ditemukan di local storage browser lama).

### Cara cari file wallet.aes.json:

**Browser localStorage** (Blockchain.com Web Wallet 2020):
- Chrome: `~/.config/google-chrome/Default/Local Storage/leveldb/`
- Firefox: `~/.mozilla/firefox/<profile>/storage/default/https+++blockchain.com/`

**File backup yang pernah Anda download**:
```bash
# Linux/Mac:
find ~ -name "wallet.aes.json" 2>/dev/null
find ~ -name "*.aes.json" 2>/dev/null
find ~ -iname "*blockchain*backup*" 2>/dev/null
```

### Cara pakai:

```bash
# Mode interaktif (input password manual)
python blockchain_decrypt.py wallet.aes.json

# Mode brute-force dari list password yang Anda ingat
python blockchain_decrypt.py wallet.aes.json --candidates my_passwords.txt
```

**Format `my_passwords.txt`** — satu password per baris. Tulis semua variasi password yang mungkin Anda pakai 2020:

```
mypassword
MyPassword
mypassword123
MyPassword!
[birthday]
[pet name]
[old common password]
[etc]
```

Script akan coba semua kandidat dengan iteration count yang berbeda.

---

## Strategi Recovery Komplet

### Skenario A — Anda pakai Blockchain.com 2020

1. **Cek email lama** — search keyword "Blockchain.com", harusnya dapat Wallet ID
2. **Cek browser lama** — apakah masih ada localStorage / cookie yang nyimpan login
3. **Cek download folder** — apakah pernah backup wallet.aes.json
4. **Login ke https://login.blockchain.com**:
   - Masukkan Wallet ID + password
   - Atau pakai email + password
5. **Setelah masuk, IMMEDIATELY cek backup phrase** di Settings → Security
6. Jika lupa password tapi punya wallet.aes.json → pakai `blockchain_decrypt.py`
7. Jika lupa password & tidak punya wallet.aes.json → recovery email lewat support@blockchain.com

### Skenario B — Anda pakai Trust Wallet 2020

1. **HP lama** — apakah Trust Wallet masih ter-install? Buka, masuk Settings → Wallets → titik 3 → "Show Recovery Phrase"
2. **Cloud backup** (Google Drive, iCloud) — apakah pernah backup app data?
3. **Cek Notes / Photos** — banyak orang screenshot seed phrase
4. **Cari file `.txt` / dokumentasi** — pakai `local_search.py`

### Skenario C — Anda punya seed phrase tapi address tidak ketemu di wallet biasa

Wallet seperti Trust Wallet biasanya hanya tampilkan address dengan derivation default. Address `1B8hg...` mungkin di derivation path non-standar.

→ Pakai `address_finder.py` untuk scan **SEMUA** path standar.

Jika ditemukan path-nya, Anda bisa import seed ke **Electrum** atau **Sparrow Wallet** dengan custom derivation path untuk akses dana.

---

## Yang TIDAK Bisa Dilakukan

- ❌ Recover wallet **tanpa apapun** (tidak ada email, tidak ada seed, tidak ada file)
- ❌ Brute-force seed phrase dari nol (matematis tidak feasible)
- ❌ Crack password Blockchain.com tanpa kandidat (10⁹⁹⁹⁹ kemungkinan)
- ❌ Recover dari Trust Wallet tanpa seed phrase (self-custody, no server backup)

Kalau Anda di posisi ini → dana kemungkinan **hilang permanen**. Jangan tertipu service yang janji bisa recover tanpa info apa-apa.

---

## Script-nya Bisa Dipercaya?

Saya enkourager Anda untuk:
1. Baca dulu source code script-nya sebelum run (semua plain Python, ~300 LOC per file)
2. Verifikasi dependencies via PyPI: `bip_utils`, `mnemonic`, `pycryptodome` (semua open-source legit)
3. Tidak ada koneksi keluar — semua proses lokal
4. Tidak ada simpan / kirim data Anda ke manapun

Cek manual untuk antusias keamanan:
```bash
grep -E 'urlopen|requests|socket|urllib' *.py
# Harusnya kosong (hanya import library standar untuk crypto)
```
