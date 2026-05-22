"""
=============================================================
  Bitcoin P2PKH Wallet Recovery & Balance Scanner
=============================================================
  Target: 1B8hgFxNK7ac2k5EtrAanxQPFcnfHLMcko
  
  Scan semua mnemonic & private key dari folder input,
  generate alamat P2PKH, cocokkan dengan target,
  dan cek saldo semua alamat yang ditemukan.
=============================================================
"""

import os
import sys
import hashlib
import time
import json
import glob

try:
    from mnemonic import Mnemonic
except ImportError:
    print("[!] Module 'mnemonic' belum terinstall.")
    print("    Jalankan: pip install mnemonic")
    sys.exit(1)

try:
    from bip_utils import (
        Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes,
        Bip32Slip10Secp256k1, WifDecoder, P2PKHAddrEncoder,
        Secp256k1PrivateKey, CoinsConf, BitcoinConf
    )
except ImportError:
    print("[!] Module 'bip_utils' belum terinstall.")
    print("    Jalankan: pip install bip_utils")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("[!] Module 'requests' belum terinstall.")
    print("    Jalankan: pip install requests")
    sys.exit(1)


# ============ CONFIGURATION ============
TARGET_ADDRESS = "1B8hgFxNK7ac2k5EtrAanxQPFcnfHLMcko"
INPUT_FOLDER = r"D:\Downloads\Downloads\notest\arb-scanner"
# Jumlah alamat yang di-derive per mnemonic (index 0 sampai N-1)
DERIVE_COUNT = 20
# Cek saldo untuk semua alamat yang ditemukan
CHECK_BALANCE = True
# Delay antara API calls (detik) untuk menghindari rate limit
API_DELAY = 0.3
# ========================================


def get_balance(address):
    """Cek saldo Bitcoin via blockchain.info API"""
    try:
        url = f"https://blockchain.info/q/addressbalance/{address}"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            satoshi = int(resp.text)
            return satoshi
        else:
            return None
    except Exception:
        return None


def get_balance_batch(addresses):
    """Cek saldo multiple addresses sekaligus via blockchain.info"""
    results = {}
    # Blockchain.info multi address API
    try:
        addr_str = "|".join(addresses)
        url = f"https://blockchain.info/multiaddr?active={addr_str}&n=0"
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            for addr_info in data.get("addresses", []):
                results[addr_info["address"]] = addr_info.get("final_balance", 0)
            return results
    except Exception:
        pass
    
    # Fallback: satu per satu
    for addr in addresses:
        bal = get_balance(addr)
        if bal is not None:
            results[addr] = bal
        time.sleep(API_DELAY)
    return results


def privkey_to_p2pkh(privkey_bytes):
    """Convert private key bytes ke alamat P2PKH (compressed)"""
    from bip_utils import (
        Secp256k1PrivateKey, Secp256k1PublicKey,
        P2PKHAddrEncoder, BitcoinConf
    )
    
    priv = Secp256k1PrivateKey.FromBytes(privkey_bytes)
    pub = priv.PublicKey()
    
    # Compressed public key -> P2PKH address
    addr = P2PKHAddrEncoder.EncodeKey(
        pub,
        net_ver=BitcoinConf.ParamByKey("p2pkh_net_ver")
    )
    return addr


def privkey_to_p2pkh_uncompressed(privkey_bytes):
    """Convert private key bytes ke alamat P2PKH (uncompressed)"""
    from bip_utils import Secp256k1PrivateKey
    
    priv = Secp256k1PrivateKey.FromBytes(privkey_bytes)
    pub = priv.PublicKey()
    
    # Get uncompressed public key
    pub_bytes_uncompressed = pub.RawUncompressed().ToBytes()
    
    # SHA256 + RIPEMD160
    sha = hashlib.sha256(b'\x04' + pub_bytes_uncompressed).digest()
    ripe = hashlib.new('ripemd160', sha).digest()
    
    # Add version byte (0x00 for mainnet)
    versioned = b'\x00' + ripe
    
    # Double SHA256 checksum
    checksum = hashlib.sha256(hashlib.sha256(versioned).digest()).digest()[:4]
    
    # Base58 encode
    return base58_encode(versioned + checksum)


def base58_encode(data):
    """Base58 encoding"""
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num = int.from_bytes(data, 'big')
    encoded = ''
    while num > 0:
        num, remainder = divmod(num, 58)
        encoded = alphabet[remainder] + encoded
    
    # Add leading '1's for leading zero bytes
    for byte in data:
        if byte == 0:
            encoded = '1' + encoded
        else:
            break
    
    return encoded


def decode_wif(wif_str):
    """Decode WIF private key, return (privkey_bytes, compressed)"""
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    
    num = 0
    for char in wif_str:
        num = num * 58 + alphabet.index(char)
    
    # Convert to bytes
    combined = num.to_bytes(38, byteorder='big')
    # Trim leading zeros to get proper length
    if wif_str[0] in ('5',):  # Uncompressed
        # 1 byte version + 32 bytes key + 4 bytes checksum = 37
        combined = num.to_bytes(37, byteorder='big')
        privkey = combined[1:33]
        return privkey, False
    elif wif_str[0] in ('K', 'L'):  # Compressed
        # 1 byte version + 32 bytes key + 1 byte flag + 4 bytes checksum = 38
        combined = num.to_bytes(38, byteorder='big')
        privkey = combined[1:33]
        return privkey, True
    else:
        # Try to decode anyway
        try:
            decoded = WifDecoder.Decode(wif_str)
            return decoded.Raw().ToBytes(), True
        except Exception:
            return None, None


def mnemonic_to_addresses(mnemonic_str, passphrase=""):
    """Generate P2PKH addresses dari mnemonic menggunakan berbagai derivation paths"""
    addresses = []  # List of (address, derivation_info, privkey_hex)
    
    try:
        # Generate seed
        seed = Bip39SeedGenerator(mnemonic_str).Generate(passphrase)
        
        # === BIP44 Standard: m/44'/0'/0'/0/i ===
        try:
            bip44 = Bip44.FromSeed(seed, Bip44Coins.BITCOIN)
            account = bip44.Purpose().Coin().Account(0)
            
            # External chain (receiving)
            chain_ext = account.Change(Bip44Changes.CHAIN_EXT)
            for i in range(DERIVE_COUNT):
                addr_obj = chain_ext.AddressIndex(i)
                addr = addr_obj.PublicKey().ToAddress()
                priv_hex = addr_obj.PrivateKey().Raw().ToHex()
                addresses.append((addr, f"BIP44 m/44'/0'/0'/0/{i}", priv_hex))
            
            # Internal chain (change)
            chain_int = account.Change(Bip44Changes.CHAIN_INT)
            for i in range(DERIVE_COUNT):
                addr_obj = chain_int.AddressIndex(i)
                addr = addr_obj.PublicKey().ToAddress()
                priv_hex = addr_obj.PrivateKey().Raw().ToHex()
                addresses.append((addr, f"BIP44 m/44'/0'/0'/1/{i}", priv_hex))
        except Exception as e:
            pass
        
        # === BIP32 Direct: m/0/i (Electrum-like) ===
        try:
            master = Bip32Slip10Secp256k1.FromSeed(seed)
            for i in range(DERIVE_COUNT):
                child = master.ChildKey(0).ChildKey(i)
                priv_bytes = child.PrivateKey().Raw().ToBytes()
                addr = privkey_to_p2pkh(priv_bytes)
                priv_hex = priv_bytes.hex()
                addresses.append((addr, f"BIP32 m/0/{i}", priv_hex))
        except Exception:
            pass
        
        # === m/0'/0/i (some wallets) ===
        try:
            master = Bip32Slip10Secp256k1.FromSeed(seed)
            for i in range(DERIVE_COUNT):
                child = master.ChildKey(Bip32Slip10Secp256k1.HardenIndex(0)).ChildKey(0).ChildKey(i)
                priv_bytes = child.PrivateKey().Raw().ToBytes()
                addr = privkey_to_p2pkh(priv_bytes)
                priv_hex = priv_bytes.hex()
                addresses.append((addr, f"BIP32 m/0'/0/{i}", priv_hex))
        except Exception:
            pass
            
    except Exception as e:
        pass
    
    return addresses


def scan_file(filepath):
    """Scan satu file, return list of (type, value) — mnemonic atau private key"""
    items = []
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception:
        return items
    
    lines = content.strip().split('\n')
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('//'):
            continue
        
        # Cek apakah ini WIF private key
        if len(line) >= 51 and len(line) <= 52 and line[0] in ('5', 'K', 'L'):
            # Kemungkinan WIF private key
            try:
                items.append(('privkey', line))
                continue
            except Exception:
                pass
        
        # Cek apakah hex private key (64 karakter hex)
        if len(line) == 64:
            try:
                int(line, 16)
                items.append(('privkey_hex', line))
                continue
            except ValueError:
                pass
        
        # Cek apakah mnemonic (12 atau 24 kata)
        words = line.split()
        if len(words) in (12, 15, 18, 21, 24):
            # Validasi sebagai mnemonic
            m = Mnemonic("english")
            if m.check(line):
                items.append(('mnemonic', line))
                continue
            else:
                # Mungkin mnemonic tapi invalid checksum, tetap coba
                all_alpha = all(w.isalpha() for w in words)
                if all_alpha:
                    items.append(('mnemonic_unverified', line))
                    continue
        
        # Cek apakah baris panjang yang mungkin berisi mnemonic words
        if len(words) >= 12 and all(w.isalpha() and len(w) <= 10 for w in words[:12]):
            items.append(('mnemonic_unverified', ' '.join(words[:12])))
    
    return items


def main():
    print("=" * 60)
    print("  BITCOIN P2PKH WALLET RECOVERY & BALANCE SCANNER")
    print("=" * 60)
    print(f"\n  Target Address : {TARGET_ADDRESS}")
    print(f"  Input Folder   : {INPUT_FOLDER}")
    print(f"  Derive Count   : {DERIVE_COUNT} addresses per mnemonic")
    print(f"  Check Balance  : {CHECK_BALANCE}")
    print("=" * 60)
    
    # Cek apakah folder ada
    if not os.path.exists(INPUT_FOLDER):
        print(f"\n[ERROR] Folder tidak ditemukan: {INPUT_FOLDER}")
        print("        Pastikan path benar!")
        sys.exit(1)
    
    # Scan semua file di folder
    print(f"\n[*] Scanning folder: {INPUT_FOLDER}")
    
    all_files = []
    for ext in ['*.txt', '*.csv', '*.json', '*.log', '*.dat', '*.key', '*.bak', '*.*']:
        all_files.extend(glob.glob(os.path.join(INPUT_FOLDER, '**', ext), recursive=True))
    
    # Remove duplicates
    all_files = list(set(all_files))
    print(f"[*] Ditemukan {len(all_files)} file untuk di-scan\n")
    
    # Collect semua items
    all_mnemonics = []
    all_privkeys = []
    
    for filepath in all_files:
        items = scan_file(filepath)
        for item_type, item_value in items:
            if 'mnemonic' in item_type:
                all_mnemonics.append((item_value, filepath))
            elif 'privkey' in item_type:
                all_privkeys.append((item_value, item_type, filepath))
    
    print(f"[*] Total mnemonic ditemukan : {len(all_mnemonics)}")
    print(f"[*] Total private key ditemukan: {len(all_privkeys)}")
    print("-" * 60)
    
    # Results
    found_target = False
    all_addresses_found = []  # (address, source_info, privkey)
    
    # === Process Mnemonics ===
    if all_mnemonics:
        print(f"\n[*] Processing {len(all_mnemonics)} mnemonics...")
        for idx, (mnemonic, source_file) in enumerate(all_mnemonics):
            short_mn = ' '.join(mnemonic.split()[:3]) + '...'
            print(f"    [{idx+1}/{len(all_mnemonics)}] {short_mn} (from {os.path.basename(source_file)})")
            
            addresses = mnemonic_to_addresses(mnemonic)
            
            for addr, path_info, priv_hex in addresses:
                all_addresses_found.append((addr, f"Mnemonic: {short_mn} | {path_info}", priv_hex))
                
                if addr == TARGET_ADDRESS:
                    found_target = True
                    print(f"\n{'='*60}")
                    print(f"  !!! TARGET FOUND !!!")
                    print(f"{'='*60}")
                    print(f"  Address     : {addr}")
                    print(f"  Mnemonic    : {mnemonic}")
                    print(f"  Path        : {path_info}")
                    print(f"  Private Key : {priv_hex}")
                    print(f"  Source File : {source_file}")
                    print(f"{'='*60}\n")
    
    # === Process Private Keys ===
    if all_privkeys:
        print(f"\n[*] Processing {len(all_privkeys)} private keys...")
        for idx, (privkey_str, pk_type, source_file) in enumerate(all_privkeys):
            short_pk = privkey_str[:8] + '...' + privkey_str[-4:]
            print(f"    [{idx+1}/{len(all_privkeys)}] {short_pk} (from {os.path.basename(source_file)})")
            
            try:
                if pk_type == 'privkey_hex':
                    priv_bytes = bytes.fromhex(privkey_str)
                    # Compressed
                    addr_c = privkey_to_p2pkh(priv_bytes)
                    all_addresses_found.append((addr_c, f"PrivKey(compressed): {short_pk}", privkey_str))
                    
                    if addr_c == TARGET_ADDRESS:
                        found_target = True
                        print(f"\n  !!! TARGET FOUND (compressed) !!!")
                        print(f"  Private Key: {privkey_str}")
                        print(f"  Source: {source_file}\n")
                    
                    # Uncompressed
                    try:
                        addr_u = privkey_to_p2pkh_uncompressed(priv_bytes)
                        all_addresses_found.append((addr_u, f"PrivKey(uncompressed): {short_pk}", privkey_str))
                        
                        if addr_u == TARGET_ADDRESS:
                            found_target = True
                            print(f"\n  !!! TARGET FOUND (uncompressed) !!!")
                            print(f"  Private Key: {privkey_str}")
                            print(f"  Source: {source_file}\n")
                    except Exception:
                        pass
                        
                elif pk_type == 'privkey':
                    # WIF format
                    priv_bytes, compressed = decode_wif(privkey_str)
                    if priv_bytes:
                        addr = privkey_to_p2pkh(priv_bytes)
                        all_addresses_found.append((addr, f"PrivKey(WIF): {short_pk}", priv_bytes.hex()))
                        
                        if addr == TARGET_ADDRESS:
                            found_target = True
                            print(f"\n  !!! TARGET FOUND !!!")
                            print(f"  WIF Key: {privkey_str}")
                            print(f"  Source: {source_file}\n")
            except Exception as e:
                pass
    
    # === Summary ===
    print("\n" + "=" * 60)
    print("  SCAN COMPLETE")
    print("=" * 60)
    print(f"  Total addresses generated: {len(all_addresses_found)}")
    print(f"  Target match found: {'YES !!!' if found_target else 'NO'}")
    
    # === Check Balances ===
    if CHECK_BALANCE and all_addresses_found:
        print(f"\n[*] Checking balances for {len(all_addresses_found)} addresses...")
        print("    (Ini mungkin memakan waktu beberapa menit...)\n")
        
        # Batch process (max 100 per request)
        wallets_with_balance = []
        unique_addresses = list(set([a[0] for a in all_addresses_found]))
        
        batch_size = 80
        for i in range(0, len(unique_addresses), batch_size):
            batch = unique_addresses[i:i+batch_size]
            print(f"    Checking batch {i//batch_size + 1}/{(len(unique_addresses)-1)//batch_size + 1}...")
            
            balances = get_balance_batch(batch)
            
            for addr, balance in balances.items():
                if balance and balance > 0:
                    # Find source info
                    source_info = ""
                    priv_key = ""
                    for a, s, p in all_addresses_found:
                        if a == addr:
                            source_info = s
                            priv_key = p
                            break
                    
                    wallets_with_balance.append((addr, balance, source_info, priv_key))
            
            time.sleep(API_DELAY)
        
        # Report wallets with balance
        if wallets_with_balance:
            print(f"\n{'='*60}")
            print(f"  WALLETS WITH BALANCE FOUND: {len(wallets_with_balance)}")
            print(f"{'='*60}")
            for addr, balance, source, pk in wallets_with_balance:
                btc = balance / 100_000_000
                print(f"\n  Address : {addr}")
                print(f"  Balance : {btc:.8f} BTC ({balance} satoshi)")
                print(f"  Source  : {source}")
                print(f"  PrivKey : {pk}")
            print(f"\n{'='*60}")
        else:
            print("\n  Tidak ada wallet dengan saldo > 0 ditemukan.")
    
    # === Save results to file ===
    results_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "recovery_results.txt")
    with open(results_file, 'w') as f:
        f.write(f"Recovery Scan Results\n")
        f.write(f"Target: {TARGET_ADDRESS}\n")
        f.write(f"Target Found: {found_target}\n")
        f.write(f"Total Addresses Scanned: {len(all_addresses_found)}\n")
        f.write(f"{'='*60}\n\n")
        
        if found_target:
            f.write("!!! TARGET ADDRESS MATCHED !!!\n\n")
        
        for addr, source, pk in all_addresses_found:
            if addr == TARGET_ADDRESS:
                f.write(f"*** MATCH *** {addr} | {source} | Key: {pk}\n")
    
    print(f"\n[*] Results saved to: {results_file}")
    print("\n[DONE] Scan selesai!")
    
    if found_target:
        print("\n" + "*" * 60)
        print("  SELAMAT! Target address ditemukan!")
        print("  Segera pindahkan dana ke wallet baru yang aman!")
        print("*" * 60)


if __name__ == "__main__":
    main()
