import os
import sys
import hashlib
import time
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
        Secp256k1PrivateKey, BitcoinConf
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
INPUT_FOLDER = r"D:\recovery"
DERIVE_COUNT = 20
CHECK_BALANCE = True
API_DELAY = 0.3
# ========================================


def base58_encode(data):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num = int.from_bytes(data, 'big')
    encoded = ''
    while num > 0:
        num, remainder = divmod(num, 58)
        encoded = alphabet[remainder] + encoded
    for byte in data:
        if byte == 0:
            encoded = '1' + encoded
        else:
            break
    return encoded


def privkey_to_p2pkh(privkey_bytes):
    priv = Secp256k1PrivateKey.FromBytes(privkey_bytes)
    pub = priv.PublicKey()
    addr = P2PKHAddrEncoder.EncodeKey(
        pub,
        net_ver=BitcoinConf.ParamByKey("p2pkh_net_ver")
    )
    return addr


def privkey_to_p2pkh_uncompressed(privkey_bytes):
    priv = Secp256k1PrivateKey.FromBytes(privkey_bytes)
    pub = priv.PublicKey()
    pub_bytes_uncompressed = pub.RawUncompressed().ToBytes()
    sha = hashlib.sha256(b'\x04' + pub_bytes_uncompressed).digest()
    ripe = hashlib.new('ripemd160', sha).digest()
    versioned = b'\x00' + ripe
    checksum = hashlib.sha256(hashlib.sha256(versioned).digest()).digest()[:4]
    return base58_encode(versioned + checksum)


def get_balance_batch(addresses):
    results = {}
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
    for addr in addresses:
        try:
            url = f"https://blockchain.info/q/addressbalance/{addr}"
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                results[addr] = int(resp.text)
        except Exception:
            pass
        time.sleep(API_DELAY)
    return results


def decode_wif(wif_str):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    try:
        num = 0
        for char in wif_str:
            num = num * 58 + alphabet.index(char)
        if wif_str[0] in ('5',):
            combined = num.to_bytes(37, byteorder='big')
            privkey = combined[1:33]
            return privkey, False
        elif wif_str[0] in ('K', 'L'):
            combined = num.to_bytes(38, byteorder='big')
            privkey = combined[1:33]
            return privkey, True
    except Exception:
        pass
    return None, None


def mnemonic_to_addresses(mnemonic_str, passphrase=""):
    addresses = []
    try:
        seed = Bip39SeedGenerator(mnemonic_str).Generate(passphrase)
        try:
            bip44 = Bip44.FromSeed(seed, Bip44Coins.BITCOIN)
            account = bip44.Purpose().Coin().Account(0)
            chain_ext = account.Change(Bip44Changes.CHAIN_EXT)
            for i in range(DERIVE_COUNT):
                addr_obj = chain_ext.AddressIndex(i)
                addr = addr_obj.PublicKey().ToAddress()
                priv_hex = addr_obj.PrivateKey().Raw().ToHex()
                addresses.append((addr, f"BIP44 m/44'/0'/0'/0/{i}", priv_hex))
            chain_int = account.Change(Bip44Changes.CHAIN_INT)
            for i in range(DERIVE_COUNT):
                addr_obj = chain_int.AddressIndex(i)
                addr = addr_obj.PublicKey().ToAddress()
                priv_hex = addr_obj.PrivateKey().Raw().ToHex()
                addresses.append((addr, f"BIP44 m/44'/0'/0'/1/{i}", priv_hex))
        except Exception:
            pass
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
    except Exception:
        pass
    return addresses


def scan_file(filepath):
    items = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception:
        return items
    lines = content.strip().split('\n')
    m = Mnemonic("english")
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('//'):
            continue
        if len(line) >= 51 and len(line) <= 52 and line[0] in ('5', 'K', 'L'):
            items.append(('privkey', line))
            continue
        if len(line) == 64:
            try:
                int(line, 16)
                items.append(('privkey_hex', line))
                continue
            except ValueError:
                pass
        words = line.split()
        if len(words) in (12, 15, 18, 21, 24):
            if m.check(line):
                items.append(('mnemonic', line))
                continue
            else:
                all_alpha = all(w.isalpha() for w in words)
                if all_alpha:
                    items.append(('mnemonic_unverified', line))
                    continue
    return items


def main():
    print("=" * 60)
    print("  BITCOIN P2PKH WALLET RECOVERY & BALANCE SCANNER")
    print("=" * 60)
    print(f"  Target Address : {TARGET_ADDRESS}")
    print(f"  Input Folder   : {INPUT_FOLDER}")
    print(f"  Derive Count   : {DERIVE_COUNT} addresses per mnemonic")
    print(f"  Check Balance  : {CHECK_BALANCE}")
    print("=" * 60)

    if not os.path.exists(INPUT_FOLDER):
        print(f"[ERROR] Folder tidak ditemukan: {INPUT_FOLDER}")
        sys.exit(1)

    print(f"[*] Scanning folder: {INPUT_FOLDER}")
    all_files = []
    for f in os.listdir(INPUT_FOLDER):
        fp = os.path.join(INPUT_FOLDER, f)
        if os.path.isfile(fp) and f.endswith(('.txt', '.csv', '.json', '.log', '.key', '.bak')):
            all_files.append(fp)
    print(f"[*] Ditemukan {len(all_files)} file untuk di-scan")

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

    found_target = False
    all_addresses_found = []

    if all_mnemonics:
        print(f"[*] Processing {len(all_mnemonics)} mnemonics...")
        for idx, (mnemonic, source_file) in enumerate(all_mnemonics):
            short_mn = ' '.join(mnemonic.split()[:3]) + '...'
            print(f"    [{idx+1}/{len(all_mnemonics)}] {short_mn}")
            addresses = mnemonic_to_addresses(mnemonic)
            for addr, path_info, priv_hex in addresses:
                all_addresses_found.append((addr, f"Mnemonic: {short_mn} | {path_info}", priv_hex))
                if addr == TARGET_ADDRESS:
                    found_target = True
                    print(f"  !!! TARGET FOUND !!!")
                    print(f"  Address     : {addr}")
                    print(f"  Mnemonic    : {mnemonic}")
                    print(f"  Path        : {path_info}")
                    print(f"  Private Key : {priv_hex}")
                    print(f"  Source File : {source_file}")

    if all_privkeys:
        print(f"[*] Processing {len(all_privkeys)} private keys...")
        for idx, (privkey_str, pk_type, source_file) in enumerate(all_privkeys):
            short_pk = privkey_str[:8] + '...'
            print(f"    [{idx+1}/{len(all_privkeys)}] {short_pk}")
            try:
                if pk_type == 'privkey_hex':
                    priv_bytes = bytes.fromhex(privkey_str)
                    addr_c = privkey_to_p2pkh(priv_bytes)
                    all_addresses_found.append((addr_c, f"PrivKey(compressed): {short_pk}", privkey_str))
                    if addr_c == TARGET_ADDRESS:
                        found_target = True
                        print(f"  !!! TARGET FOUND !!!")
                        print(f"  Private Key: {privkey_str}")
                        print(f"  Source: {source_file}")
                    try:
                        addr_u = privkey_to_p2pkh_uncompressed(priv_bytes)
                        all_addresses_found.append((addr_u, f"PrivKey(uncompressed): {short_pk}", privkey_str))
                        if addr_u == TARGET_ADDRESS:
                            found_target = True
                            print(f"  !!! TARGET FOUND (uncompressed) !!!")
                            print(f"  Private Key: {privkey_str}")
                            print(f"  Source: {source_file}")
                    except Exception:
                        pass
                elif pk_type == 'privkey':
                    priv_bytes, compressed = decode_wif(privkey_str)
                    if priv_bytes:
                        addr = privkey_to_p2pkh(priv_bytes)
                        all_addresses_found.append((addr, f"PrivKey(WIF): {short_pk}", priv_bytes.hex()))
                        if addr == TARGET_ADDRESS:
                            found_target = True
                            print(f"  !!! TARGET FOUND !!!")
                            print(f"  WIF Key: {privkey_str}")
                            print(f"  Source: {source_file}")
            except Exception:
                pass

    print("=" * 60)
    print("  SCAN COMPLETE")
    print(f"  Total addresses generated: {len(all_addresses_found)}")
    print(f"  Target match found: {'YES !!!' if found_target else 'NO'}")
    print("=" * 60)

    if CHECK_BALANCE and all_addresses_found:
        print(f"[*] Checking balances for {len(all_addresses_found)} addresses...")
        wallets_with_balance = []
        unique_addresses = list(set([a[0] for a in all_addresses_found]))
        batch_size = 80
        for i in range(0, len(unique_addresses), batch_size):
            batch = unique_addresses[i:i+batch_size]
            print(f"    Checking batch {i//batch_size + 1}/{(len(unique_addresses)-1)//batch_size + 1}...")
            balances = get_balance_batch(batch)
            for addr, balance in balances.items():
                if balance and balance > 0:
                    source_info = ""
                    priv_key = ""
                    for a, s, p in all_addresses_found:
                        if a == addr:
                            source_info = s
                            priv_key = p
                            break
                    wallets_with_balance.append((addr, balance, source_info, priv_key))
            time.sleep(API_DELAY)

        if wallets_with_balance:
            print(f"  WALLETS WITH BALANCE: {len(wallets_with_balance)}")
            for addr, balance, source, pk in wallets_with_balance:
                btc = balance / 100_000_000
                print(f"  Address : {addr}")
                print(f"  Balance : {btc:.8f} BTC ({balance} sat)")
                print(f"  Source  : {source}")
                print(f"  PrivKey : {pk}")
                print()
        else:
            print("  Tidak ada wallet dengan saldo > 0.")

    results_file = os.path.join(INPUT_FOLDER, "recovery_results.txt")
    with open(results_file, 'w') as f:
        f.write(f"Target: {TARGET_ADDRESS}\n")
        f.write(f"Found: {found_target}\n")
        f.write(f"Total scanned: {len(all_addresses_found)}\n\n")
        for addr, source, pk in all_addresses_found:
            marker = "*** MATCH ***" if addr == TARGET_ADDRESS else ""
            f.write(f"{marker} {addr} | {source} | {pk}\n")
    print(f"[*] Results saved to: {results_file}")
    print("[DONE]")


if __name__ == "__main__":
    main()
