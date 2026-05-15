# Bitcoin Wallet Recovery Toolkit

Untuk address: `1B8hgFxNK7ac2k5EtrAanxQPFcnfHLMcko`
Saldo: 0.00318536 BTC (~$252)

---

## ⚠️ KEAMANAN — BACA DULU

1. **Jalankan SEMUA script di komputer pribadi Anda** — JANGAN di server, JANGAN di komputer publik
2. **Idealnya offline** — cabut WiFi/LAN saat menjalankan, terutama saat menampilkan seed/key
3. **JANGAN paste output ke ChatGPT, Claude, AI manapun, forum, Telegram, dll**
4. **Verifikasi script** dulu sebelum run (semua plain Python, audit-able)
5. **Hapus file output** (`recovery_findings.txt`, `decrypted_wallet.json`, `candidates.txt`) setelah selesai

---

## Setup (sekali saja)

Butuh Python 3.8+. Install dependencies:

```bash
pip install bip_utils mnemonic pycryptodome
```

---

## Tool 1: `find_wallet_files.py` — Cari File wallet.aes.json

Scan komputer Anda untuk menemukan file backup Blockchain.com yang mungkin tersimpan.

```bash
# Auto-scan lokasi umum (Downloads, Documents, browser localStorage, dll)
python find_wallet_files.py

# Atau scan path spesifik
python find_wallet_files.py ~/Documents ~/old_backups
```

Akan kembalikan daftar file kandidat dengan format Blockchain.com.

---

## Tool 2: `blockchain_decrypt.py` — Decrypt wallet.aes.json

**Inilah tool utama untuk Anda** karena Anda punya file `wallet.aes.json`.

### Mode A: Anda ingat password
```bash
python blockchain_decrypt.py wallet.aes.json
```
Kemudian masukkan password saat diminta. Auto-detect versi & iteration count.

### Mode B: Coba banyak file wallet sekaligus (untuk Anda yang punya banyak akun)
```bash
python blockchain_decrypt.py wallet1.aes.json wallet2.aes.json wallet3.aes.json
```
Atau pakai glob:
```bash
python blockchain_decrypt.py /path/to/folder/*.aes.json
```

### Mode C: Brute force dengan password candidates
```bash
python blockchain_decrypt.py wallet.aes.json --candidates passwords.txt
```
Format `passwords.txt` — satu password per baris.

### Output yang Anda dapatkan
- **HD mnemonic (12-24 kata)** — bisa import ke wallet lain
- **Imported keys** — daftar address + private key WIF
- **Auto-flag target address** — kalau `1B8hg...LMcko` ada di wallet, akan di-highlight
- **Auto-derive HD addresses** — generate 100 address pertama dari mnemonic untuk cek vs target

---

## Tool 3: `password_generator.py` — Generate Password Candidates

Pakai kalau Anda **lupa password tapi ingat pola/komponen** password Anda.

```bash
python password_generator.py
```

Anda akan diminta input:
1. **Base words** — kata-kata yang Anda biasa pakai (nama, hobi, dll)
2. **Numbers** — angka favorit (tahun lahir, ulang tahun, dll)
3. **Symbols** — simbol yang biasa Anda pakai
4. **Output filename** — file untuk di-feed ke `blockchain_decrypt.py`

Tool akan generate ribuan kombinasi dengan variasi case & leet substitution.

Contoh:
- Input: `bitcoin, john` + `1990, 2020` + `! @`
- Output: `bitcoin`, `Bitcoin`, `b1tc01n`, `bitcoin1990`, `Bitcoin1990!`, `john2020@`, `JohnBitcoin1990!`, dll (~5000 kombinasi)

---

## Tool 4: `address_finder.py` — Validasi Seed/Key

Pakai kalau Anda PUNYA seed phrase atau private key dan mau cek apakah cocok dengan address target.

```bash
python address_finder.py
```

Pilihan menu:
1. Punya 12-kata seed lengkap → cek di semua derivation path standar
2. Punya 11 kata, lupa 1 kata → brute force 1 kata yang hilang (2048 percobaan)
3. Punya WIF private key (`5...`, `K...`, `L...`)
4. Punya hex private key (64 karakter hex)

---

## Tool 5: `local_search.py` — Scan Komputer

Pakai untuk mencari file yang mungkin berisi seed/key di komputer Anda.

```bash
python local_search.py ~
```

Yang dicari:
- File berisi 12/18/24 kata BIP39 berurutan
- File berisi WIF private key
- File berisi hex 64-char yang berpotensi private key
- File berisi extended key (`xprv...`)
- Filename mencurigakan (wallet.dat, seed.txt, recovery, dll)

Output: `recovery_findings.txt` — **REVIEW LALU DELETE**.

---

## 🎯 STRATEGI UNTUK ANDA — Punya wallet.aes.json + Banyak Akun Email Blockchain.com

### Step 1: Identifikasi semua file wallet
```bash
python find_wallet_files.py
```

Atau manual cari:
```bash
# Linux/Mac:
find ~ -name "wallet.aes.json" 2>/dev/null
find ~ -iname "*.aes.json" 2>/dev/null
find ~ -iname "*blockchain*backup*" 2>/dev/null

# Windows (PowerShell):
Get-ChildItem -Path C:\Users -Filter "wallet.aes.json" -Recurse -ErrorAction SilentlyContinue
```

### Step 2: Buat list password kandidat

Pikirkan semua password yang **mungkin** Anda pakai sekitar 2020:
- Password Email Anda di tahun itu
- Password reuse dari service lain
- Pola password Anda (ada nama, ada tahun, dll)

Tulis ke file `my_passwords.txt`, satu per baris:
```
password123
MyPassword2020
mypw!
Bitcoin2020
[etc]
```

Atau pakai generator:
```bash
python password_generator.py
```

### Step 3: Coba decrypt SEMUA wallet sekaligus

```bash
python blockchain_decrypt.py wallet1.aes.json wallet2.aes.json --candidates my_passwords.txt
```

Tool akan coba semua kombinasi. Yang berhasil akan **otomatis di-flag** kalau berisi address `1B8hg...LMcko`.

### Step 4: Plan B — Login Manual dengan Email

Untuk akun yang kita belum tahu password-nya:

```
https://login.blockchain.com/recover
```

Masukkan email satu per satu. Cek inbox untuk:
- "Your Wallet ID" emails — catat semua Wallet ID
- "Login attempt" emails — bantu identifikasi akun aktif

Jika dapat akses ke akun Blockchain.com aktif via email reset:
1. Login → Settings → Security → **Backup Phrase**
2. Catat 12 kata phrase di tempat aman
3. Verify dengan toolkit kita: `python address_finder.py` mode 1

---

## Skenario Umum & Solusi

| Situasi | Solusi |
|---|---|
| Punya wallet.aes.json + ingat password | `blockchain_decrypt.py wallet.aes.json` |
| Punya wallet.aes.json + lupa password total | `blockchain_decrypt.py --candidates ...` (low success kalau pw kuat) |
| Punya wallet.aes.json + ingat sebagian | `password_generator.py` lalu `--candidates` |
| Lupa semua, punya banyak akun email | Login manual via login.blockchain.com/recover |
| Punya seed phrase tapi address tidak muncul di wallet | `address_finder.py` mode 1 (cek semua path) |
| Punya seed tapi hilang 1 kata | `address_finder.py` mode 2 |

---

## Yang TIDAK Bisa Dilakukan

- ❌ Recover **tanpa apapun** (tidak ada email, tidak ada seed, tidak ada file)
- ❌ Brute-force seed phrase dari nol (matematis tidak feasible)
- ❌ Crack password yang strong (>12 char random) tanpa kandidat — butuh waktu astronomis

---

## Verifikasi Toolkit Aman

Cek bahwa tidak ada koneksi keluar:
```bash
grep -E 'urlopen|requests|socket|urllib|http' *.py
# Output harus kosong
```

Audit dependencies (semua open source, well-known):
- `bip_utils` — Bitcoin/crypto key derivation lib
- `mnemonic` — BIP39 wordlist library
- `pycryptodome` — AES/PBKDF2 cryptography (industry standard)
