import os
import sys
import hashlib
import time

try:
    from mnemonic import Mnemonic
except ImportError:
    print("[!] pip install mnemonic")
    sys.exit(1)

try:
    from bip_utils import (
        Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes,
        Bip32Slip10Secp256k1
    )
except ImportError:
    print("[!] pip install bip_utils")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("[!] pip install requests")
    sys.exit(1)

TARGET_ADDRESS = "1B8hgFxNK7ac2k5EtrAanxQPFcnfHLMcko"
INPUT_FOLDER = os.path.dirname(os.path.abspath(__file__))
DERIVE_COUNT = 20
CHECK_BALANCE = True
API_DELAY = 0.3


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


def pubkey_to_p2pkh(pubkey_bytes):
    sha = hashlib.sha256(pubkey_bytes).digest()
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
        if wif_str[0] == '5':
            combined = num.to_bytes(37, byteorder='big')
            return combined[1:33], False
        elif wif_str[0] in ('K', 'L'):
            combined = num.to_bytes(38, byteorder='big')
            return combined[1:33], True
    except Exception:
        pass
    return None, None


def privkey_to_pubkey_compressed(privkey_bytes):
    from coincurve import PrivateKey
    pk = PrivateKey(privkey_bytes)
    return pk.public_key.format(compressed=True)


def privkey_to_pubkey_uncompressed(privkey_bytes):
    from coincurve import PrivateKey
    pk = PrivateKey(privkey_bytes)
    return pk.public_key.format(compressed=False)


def mnemonic_to_addresses(mnemonic_str):
    addresses = []
    try:
        seed = Bip39SeedGenerator(mnemonic_str).Generate("")
        # BIP44: m/44'/0'/0'/0/i
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
        # BIP32: m/0/i
        try:
            master = Bip32Slip10Secp256k1.FromSeed(seed)
            for i in range(DERIVE_COUNT):
                child = master.ChildKey(0).ChildKey(i)
                priv_bytes = child.PrivateKey().Raw().ToBytes()
                pub = privkey_to_pubkey_compressed(priv_bytes)
                addr = pubkey_to_p2pkh(pub)
                addresses.append((addr, f"BIP32 m/0/{i}", priv_bytes.hex()))
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
    m = Mnemonic("english")
    for line in content.strip().split('\n'):
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('//'):
            continue
        # WIF private key
        if len(line) >= 51 and len(line) <= 52 and line[0] in ('5', 'K', 'L'):
            items.append(('privkey_wif', line))
            continue
        # Hex private key
        if len(line) == 64:
            try:
                int(line, 16)
                items.append(('privkey_hex', line))
                continue
            except ValueError:
                pass
        # Mnemonic
        words = line.split()
        if len(words) in (12, 15, 18, 21, 24):
            if m.check(line):
                items.append(('mnemonic', line))
            elif all(w.isalpha() for w in words):
                items.append(('mnemonic', line))
    return items


def main():
    print("=" * 60)
    print("  BITCOIN P2PKH WALLET RECOVERY")
    print("=" * 60)
    print(f"  Target : {TARGET_ADDRESS}")
    print(f"  Folder : {INPUT_FOLDER}")
    print("=" * 60)

    all_files = [os.path.join(INPUT_FOLDER, f) for f in os.listdir(INPUT_FOLDER)
                 if f.endswith(('.txt', '.csv', '.json', '.log'))]
    print(f"\n[*] Files to scan: {len(all_files)}")

    all_mnemonics = []
    all_privkeys = []
    for fp in all_files:
        for item_type, item_value in scan_file(fp):
            if item_type == 'mnemonic':
                all_mnemonics.append((item_value, fp))
            else:
                all_privkeys.append((item_value, item_type, fp))

    print(f"[*] Mnemonics found: {len(all_mnemonics)}")
    print(f"[*] Private keys found: {len(all_privkeys)}")
    print("-" * 60)

    found_target = False
    all_addresses = []

    # Process mnemonics
    if all_mnemonics:
        print(f"\n[*] Processing {len(all_mnemonics)} mnemonics...")
        for idx, (mn, src) in enumerate(all_mnemonics):
            short = ' '.join(mn.split()[:3]) + '...'
            print(f"    [{idx+1}/{len(all_mnemonics)}] {short}")
            for addr, path_info, priv_hex in mnemonic_to_addresses(mn):
                all_addresses.append((addr, f"{short} | {path_info}", priv_hex))
                if addr == TARGET_ADDRESS:
                    found_target = True
                    print(f"\n  *** TARGET FOUND ***")
                    print(f"  Mnemonic : {mn}")
                    print(f"  Path     : {path_info}")
                    print(f"  PrivKey  : {priv_hex}")
                    print(f"  Source   : {src}\n")

    # Process private keys
    if all_privkeys:
        print(f"\n[*] Processing {len(all_privkeys)} private keys...")
        for idx, (pk_str, pk_type, src) in enumerate(all_privkeys):
            short_pk = pk_str[:8] + '...'
            print(f"    [{idx+1}/{len(all_privkeys)}] {short_pk}")
            try:
                if pk_type == 'privkey_hex':
                    priv_bytes = bytes.fromhex(pk_str)
                elif pk_type == 'privkey_wif':
                    priv_bytes, compressed = decode_wif(pk_str)
                    if not priv_bytes:
                        continue
                else:
                    continue
                # Compressed address
                pub_c = privkey_to_pubkey_compressed(priv_bytes)
                addr_c = pubkey_to_p2pkh(pub_c)
                all_addresses.append((addr_c, f"PK(c): {short_pk}", priv_bytes.hex()))
                if addr_c == TARGET_ADDRESS:
                    found_target = True
                    print(f"\n  *** TARGET FOUND (compressed) ***")
                    print(f"  PrivKey: {pk_str}")
                    print(f"  Source : {src}\n")
                # Uncompressed address
                pub_u = privkey_to_pubkey_uncompressed(priv_bytes)
                addr_u = pubkey_to_p2pkh(pub_u)
                all_addresses.append((addr_u, f"PK(u): {short_pk}", priv_bytes.hex()))
                if addr_u == TARGET_ADDRESS:
                    found_target = True
                    print(f"\n  *** TARGET FOUND (uncompressed) ***")
                    print(f"  PrivKey: {pk_str}")
                    print(f"  Source : {src}\n")
            except Exception:
                pass

    print("\n" + "=" * 60)
    print(f"  SCAN COMPLETE")
    print(f"  Total addresses: {len(all_addresses)}")
    print(f"  Target found: {'YES!!!' if found_target else 'NO'}")
    print("=" * 60)

    # Check balances
    if CHECK_BALANCE and all_addresses:
        print(f"\n[*] Checking balances ({len(all_addresses)} addresses)...")
        unique_addrs = list(set([a[0] for a in all_addresses]))
        wallets_with_balance = []
        batch_size = 50
        for i in range(0, len(unique_addrs), batch_size):
            batch = unique_addrs[i:i+batch_size]
            print(f"    Batch {i//batch_size+1}/{(len(unique_addrs)-1)//batch_size+1}...")
            balances = get_balance_batch(batch)
            for addr, bal in balances.items():
                if bal > 0:
                    for a, s, p in all_addresses:
                        if a == addr:
                            wallets_with_balance.append((addr, bal, s, p))
                            break
            time.sleep(API_DELAY)

        if wallets_with_balance:
            print(f"\n{'='*60}")
            print(f"  WALLETS WITH BALANCE: {len(wallets_with_balance)}")
            print(f"{'='*60}")
            for addr, bal, source, pk in wallets_with_balance:
                btc = bal / 100_000_000
                print(f"  {addr}")
                print(f"  Balance: {btc:.8f} BTC")
                print(f"  Source : {source}")
                print(f"  Key    : {pk}")
                print()
        else:
            print("  No wallets with balance found.")

    # Save results
    out_file = os.path.join(INPUT_FOLDER, "results.txt")
    with open(out_file, 'w') as f:
        f.write(f"Target: {TARGET_ADDRESS}\nFound: {found_target}\n")
        f.write(f"Total: {len(all_addresses)}\n\n")
        for addr, src, pk in all_addresses:
            tag = "MATCH!" if addr == TARGET_ADDRESS else ""
            f.write(f"{tag} {addr} | {src} | {pk}\n")
    print(f"\n[*] Results saved: {out_file}")
    print("[DONE]")


if __name__ == "__main__":
    main()
