# Bitcoin P2PKH Wallet Recovery Tool

## Cara Pakai

### 1. Install Python (jika belum)
Download dari: https://www.python.org/downloads/
Pastikan centang "Add Python to PATH" saat install.

### 2. Install Dependencies
Buka **PowerShell** dan jalankan:

```powershell
pip install mnemonic bip_utils requests
```

### 3. Konfigurasi
Edit file `recovery.py`, ubah bagian CONFIGURATION jika perlu:

```python
TARGET_ADDRESS = "1B8hgFxNK7ac2k5EtrAanxQPFcnfHLMcko"
INPUT_FOLDER = r"D:\Downloads\Downloads\notest\arb-scanner"
DERIVE_COUNT = 20          # Jumlah alamat per mnemonic
CHECK_BALANCE = True       # Cek saldo semua alamat
API_DELAY = 0.3            # Delay antar API call
```

### 4. Jalankan dari PowerShell

```powershell
cd D:\path\ke\folder\script
python recovery.py
```

### 5. Output

Script akan:
- Scan semua file (.txt, .csv, .json, .log, dll) di folder input
- Auto-detect mnemonic phrases (12/24 kata) dan private keys (WIF/hex)
- Generate alamat P2PKH menggunakan berbagai derivation path:
  - BIP44: `m/44'/0'/0'/0/i` (standar)
  - BIP32: `m/0/i` (Electrum-like)
  - BIP32: `m/0'/0/i` (beberapa wallet lain)
- Cocokkan dengan target address
- Cek saldo semua alamat via blockchain.info API
- Simpan hasil ke `recovery_results.txt`

### Format File Input

Script bisa baca file yang berisi:

```
# Mnemonic (satu per baris, 12 atau 24 kata)
abandon ability able about above absent absorb abstract absurd abuse access accident

# Private Key WIF (dimulai dengan 5, K, atau L)
5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ
KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn

# Private Key Hex (64 karakter)
0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d
```

### Keamanan

- Jangan share hasil recovery ke siapa pun
- Segera pindahkan dana ke wallet baru setelah recovery berhasil
- Hapus file hasil scan setelah selesai

## Troubleshooting

| Error | Solusi |
|-------|--------|
| `Module 'mnemonic' belum terinstall` | `pip install mnemonic` |
| `Module 'bip_utils' belum terinstall` | `pip install bip_utils` |
| `Module 'requests' belum terinstall` | `pip install requests` |
| `Folder tidak ditemukan` | Cek path di `INPUT_FOLDER` |
| Rate limited by API | Naikkan `API_DELAY` ke 1.0 atau lebih |
