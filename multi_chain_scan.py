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

try:
    from coincurve import PrivateKey as CPrivateKey
except ImportError:
    print("[!] pip install coincurve")
    sys.exit(1)

INPUT_FOLDER = os.path.dirname(os.path.abspath(__file__))
DERIVE_COUNT = 10
API_DELAY = 0.5

# Supported chains via BIP44
CHAINS = {
    "BTC": {"coin": Bip44Coins.BITCOIN, "name": "Bitcoin"},
    "ETH": {"coin": Bip44Coins.ETHEREUM, "name": "Ethereum"},
    "BNB": {"coin": Bip44Coins.ETHEREUM, "name": "BNB Smart Chain"},
    "LTC": {"coin": Bip44Coins.LITECOIN, "name": "Litecoin"},
    "DOGE": {"coin": Bip44Coins.DOGECOIN, "name": "Dogecoin"},
    "TRX": {"coin": Bip44Coins.TRON, "name": "Tron"},
    "BCH": {"coin": Bip44Coins.BITCOIN_CASH, "name": "Bitcoin Cash"},
    "DASH": {"coin": Bip44Coins.DASH, "name": "Dash"},
}


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


def pubkey_to_p2pkh(pubkey_bytes, version=b'\x00'):
    sha = hashlib.sha256(pubkey_bytes).digest()
    ripe = hashlib.new('ripemd160', sha).digest()
    versioned = version + ripe
    checksum = hashlib.sha256(hashlib.sha256(versioned).digest()).digest()[:4]
    return base58_encode(versioned + checksum)


def privkey_to_eth_address(privkey_bytes):
    try:
        from Crypto.Hash import keccak as keccak_pycrypto
        pk = CPrivateKey(privkey_bytes)
        pub_uncompressed = pk.public_key.format(compressed=False)[1:]  # remove 04 prefix
        k = keccak_pycrypto.new(digest_bits=256)
        k.update(pub_uncompressed)
        return '0x' + k.hexdigest()[-40:]
    except ImportError:
        pass
    try:
        import hashlib as hl
        pk = CPrivateKey(privkey_bytes)
        pub_uncompressed = pk.public_key.format(compressed=False)[1:]
        h = hl.sha3_256(pub_uncompressed).hexdigest()
        # sha3_256 is NOT keccak256, try anyway
        return None
    except Exception:
        return None


def privkey_to_eth_keccak(privkey_bytes):
    """Use coincurve + manual keccak"""
    pk = CPrivateKey(privkey_bytes)
    pub_uncompressed = pk.public_key.format(compressed=False)[1:]  # 64 bytes
    try:
        # Try pycryptodome Keccak
        from Crypto.Hash import keccak
        k = keccak.new(digest_bits=256, data=pub_uncompressed)
        return '0x' + k.hexdigest()[-40:]
    except Exception:
        pass
    try:
        # Try pysha3
        import sha3
        k = sha3.keccak_256(pub_uncompressed)
        return '0x' + k.hexdigest()[-40:]
    except Exception:
        pass
    return None


def check_btc_balance(address):
    try:
        url = f"https://blockchain.info/q/addressbalance/{address}"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            return int(r.text)
    except Exception:
        pass
    return 0


def check_eth_balance(address):
    """Check ETH balance via public API"""
    try:
        url = f"https://api.blockchair.com/ethereum/dashboards/address/{address}"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            bal = data.get("data", {}).get(address.lower(), {}).get("address", {}).get("balance", 0)
            return int(bal)
    except Exception:
        pass
    return 0


def check_bnb_balance(address):
    """Check BNB Smart Chain balance"""
    try:
        url = f"https://api.blockchair.com/bnb/dashboards/address/{address}"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            bal = data.get("data", {}).get(address.lower(), {}).get("address", {}).get("balance", 0)
            return int(bal)
    except Exception:
        pass
    return 0


def check_ltc_balance(address):
    try:
        url = f"https://api.blockchair.com/litecoin/dashboards/address/{address}"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            bal = data.get("data", {}).get(address, {}).get("address", {}).get("balance", 0)
            return int(bal)
    except Exception:
        pass
    return 0


def check_doge_balance(address):
    try:
        url = f"https://api.blockchair.com/dogecoin/dashboards/address/{address}"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            bal = data.get("data", {}).get(address, {}).get("address", {}).get("balance", 0)
            return int(bal)
    except Exception:
        pass
    return 0


def check_trx_balance(address):
    try:
        url = f"https://api.trongrid.io/v1/accounts/{address}"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            if data.get("data") and len(data["data"]) > 0:
                return data["data"][0].get("balance", 0)
    except Exception:
        pass
    return 0


def check_bch_balance(address):
    try:
        url = f"https://api.blockchair.com/bitcoin-cash/dashboards/address/{address}"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            bal = data.get("data", {}).get(address, {}).get("address", {}).get("balance", 0)
            return int(bal)
    except Exception:
        pass
    return 0


def derive_addresses_multichain(mnemonic_str):
    """Derive addresses for multiple chains from a single mnemonic"""
    results = []  # (chain, address, privkey_hex, path)

    try:
        seed = Bip39SeedGenerator(mnemonic_str).Generate("")

        # BTC - P2PKH
        try:
            bip44 = Bip44.FromSeed(seed, Bip44Coins.BITCOIN)
            acc = bip44.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT)
            for i in range(DERIVE_COUNT):
                obj = acc.AddressIndex(i)
                addr = obj.PublicKey().ToAddress()
                pk = obj.PrivateKey().Raw().ToHex()
                results.append(("BTC", addr, pk, f"m/44'/0'/0'/0/{i}"))
        except Exception:
            pass

        # ETH/BNB/ARB/MATIC (same derivation, different chain)
        try:
            bip44 = Bip44.FromSeed(seed, Bip44Coins.ETHEREUM)
            acc = bip44.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT)
            for i in range(DERIVE_COUNT):
                obj = acc.AddressIndex(i)
                pk_hex = obj.PrivateKey().Raw().ToHex()
                pk_bytes = bytes.fromhex(pk_hex)
                eth_addr = privkey_to_eth_keccak(pk_bytes)
                if eth_addr:
                    results.append(("ETH", eth_addr, pk_hex, f"m/44'/60'/0'/0/{i}"))
                    results.append(("BNB", eth_addr, pk_hex, f"m/44'/60'/0'/0/{i}"))
                    results.append(("ARB", eth_addr, pk_hex, f"m/44'/60'/0'/0/{i}"))
                    results.append(("MATIC", eth_addr, pk_hex, f"m/44'/60'/0'/0/{i}"))
                    results.append(("AVAX", eth_addr, pk_hex, f"m/44'/60'/0'/0/{i}"))
                    results.append(("FTM", eth_addr, pk_hex, f"m/44'/60'/0'/0/{i}"))
                    results.append(("OP", eth_addr, pk_hex, f"m/44'/60'/0'/0/{i}"))
        except Exception:
            pass

        # LTC
        try:
            bip44 = Bip44.FromSeed(seed, Bip44Coins.LITECOIN)
            acc = bip44.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT)
            for i in range(DERIVE_COUNT):
                obj = acc.AddressIndex(i)
                addr = obj.PublicKey().ToAddress()
                pk = obj.PrivateKey().Raw().ToHex()
                results.append(("LTC", addr, pk, f"m/44'/2'/0'/0/{i}"))
        except Exception:
            pass

        # DOGE
        try:
            bip44 = Bip44.FromSeed(seed, Bip44Coins.DOGECOIN)
            acc = bip44.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT)
            for i in range(DERIVE_COUNT):
                obj = acc.AddressIndex(i)
                addr = obj.PublicKey().ToAddress()
                pk = obj.PrivateKey().Raw().ToHex()
                results.append(("DOGE", addr, pk, f"m/44'/3'/0'/0/{i}"))
        except Exception:
            pass

        # TRX (Tron) - coin type 195
        try:
            bip44 = Bip44.FromSeed(seed, Bip44Coins.TRON)
            acc = bip44.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT)
            for i in range(DERIVE_COUNT):
                obj = acc.AddressIndex(i)
                addr = obj.PublicKey().ToAddress()
                pk = obj.PrivateKey().Raw().ToHex()
                results.append(("TRX", addr, pk, f"m/44'/195'/0'/0/{i}"))
        except Exception:
            pass

        # BCH
        try:
            bip44 = Bip44.FromSeed(seed, Bip44Coins.BITCOIN_CASH)
            acc = bip44.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT)
            for i in range(DERIVE_COUNT):
                obj = acc.AddressIndex(i)
                addr = obj.PublicKey().ToAddress()
                pk = obj.PrivateKey().Raw().ToHex()
                results.append(("BCH", addr, pk, f"m/44'/145'/0'/0/{i}"))
        except Exception:
            pass

        # DASH
        try:
            bip44 = Bip44.FromSeed(seed, Bip44Coins.DASH)
            acc = bip44.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT)
            for i in range(DERIVE_COUNT):
                obj = acc.AddressIndex(i)
                addr = obj.PublicKey().ToAddress()
                pk = obj.PrivateKey().Raw().ToHex()
                results.append(("DASH", addr, pk, f"m/44'/5'/0'/0/{i}"))
        except Exception:
            pass

    except Exception:
        pass

    return results


def check_balance_by_chain(chain, address):
    """Check balance based on chain type"""
    if chain == "BTC":
        bal = check_btc_balance(address)
        return bal, bal / 100_000_000, "BTC"
    elif chain in ("ETH", "ARB", "OP"):
        bal = check_eth_balance(address)
        return bal, bal / 1e18, "ETH"
    elif chain in ("BNB", "AVAX", "FTM", "MATIC"):
        bal = check_bnb_balance(address)
        return bal, bal / 1e18, chain
    elif chain == "LTC":
        bal = check_ltc_balance(address)
        return bal, bal / 100_000_000, "LTC"
    elif chain == "DOGE":
        bal = check_doge_balance(address)
        return bal, bal / 100_000_000, "DOGE"
    elif chain == "TRX":
        bal = check_trx_balance(address)
        return bal, bal / 1_000_000, "TRX"
    elif chain == "BCH":
        bal = check_bch_balance(address)
        return bal, bal / 100_000_000, "BCH"
    return 0, 0, chain


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
    print("  MULTI-CHAIN CRYPTO BALANCE SCANNER")
    print("=" * 60)
    print(f"  Folder : {INPUT_FOLDER}")
    print(f"  Chains : BTC, ETH, BNB, ARB, MATIC, LTC, DOGE, TRX, BCH, DASH")
    print(f"  Derive : {DERIVE_COUNT} per chain per mnemonic")
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

    wallets_with_balance = []
    all_derived = []  # (chain, address, privkey, path, source)

    # === Process Mnemonics ===
    if all_mnemonics:
        print(f"\n[*] Deriving multi-chain addresses from {len(all_mnemonics)} mnemonics...")
        for idx, (mn, src) in enumerate(all_mnemonics):
            short = ' '.join(mn.split()[:3]) + '...'
            print(f"    [{idx+1}/{len(all_mnemonics)}] {short}")
            derived = derive_addresses_multichain(mn)
            for chain, addr, pk, path in derived:
                all_derived.append((chain, addr, pk, path, src, mn))

    # === Process Private Keys (ETH-compatible) ===
    if all_privkeys:
        print(f"\n[*] Processing {len(all_privkeys)} private keys for ETH/BNB/BTC...")
        for idx, (pk_str, pk_type, src) in enumerate(all_privkeys):
            short_pk = pk_str[:8] + '...'
            print(f"    [{idx+1}/{len(all_privkeys)}] {short_pk}")
            try:
                if pk_type == 'privkey_hex':
                    priv_bytes = bytes.fromhex(pk_str)
                elif pk_type == 'privkey_wif':
                    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
                    num = 0
                    for char in pk_str:
                        num = num * 58 + alphabet.index(char)
                    if pk_str[0] == '5':
                        combined = num.to_bytes(37, byteorder='big')
                        priv_bytes = combined[1:33]
                    elif pk_str[0] in ('K', 'L'):
                        combined = num.to_bytes(38, byteorder='big')
                        priv_bytes = combined[1:33]
                    else:
                        continue
                else:
                    continue

                # BTC compressed
                pk_obj = CPrivateKey(priv_bytes)
                pub_c = pk_obj.public_key.format(compressed=True)
                btc_addr = pubkey_to_p2pkh(pub_c)
                all_derived.append(("BTC", btc_addr, priv_bytes.hex(), "direct", src, pk_str))

                # ETH/BNB
                eth_addr = privkey_to_eth_keccak(priv_bytes)
                if eth_addr:
                    all_derived.append(("ETH", eth_addr, priv_bytes.hex(), "direct", src, pk_str))
                    all_derived.append(("BNB", eth_addr, priv_bytes.hex(), "direct", src, pk_str))

            except Exception:
                pass

    print(f"\n[*] Total addresses derived: {len(all_derived)}")
    print("-" * 60)

    # === Check Balances ===
    print(f"\n[*] Checking balances (this may take a while)...")

    # Group by chain to check efficiently
    checked = set()
    total_checks = 0

    for chain, addr, pk, path, src, original in all_derived:
        key = f"{chain}:{addr}"
        if key in checked:
            continue
        checked.add(key)
        total_checks += 1

        # Only check certain chains to avoid too many API calls
        if chain in ("BTC", "ETH", "BNB", "LTC", "DOGE", "TRX", "BCH"):
            try:
                raw_bal, human_bal, symbol = check_balance_by_chain(chain, addr)
                if raw_bal > 0:
                    wallets_with_balance.append((chain, addr, human_bal, symbol, pk, path, src, original))
                    print(f"\n  *** BALANCE FOUND ***")
                    print(f"  Chain   : {chain}")
                    print(f"  Address : {addr}")
                    print(f"  Balance : {human_bal} {symbol}")
                    print(f"  PrivKey : {pk}")
                    print(f"  Path    : {path}")
                    print(f"  Source  : {os.path.basename(src)}")
            except Exception:
                pass
            time.sleep(API_DELAY)

        if total_checks % 20 == 0:
            print(f"    ... checked {total_checks} addresses")

    # === Summary ===
    print("\n" + "=" * 60)
    print("  SCAN COMPLETE")
    print(f"  Total addresses checked: {total_checks}")
    print(f"  Wallets with balance: {len(wallets_with_balance)}")
    print("=" * 60)

    if wallets_with_balance:
        print(f"\n{'='*60}")
        print(f"  WALLETS WITH BALANCE FOUND!")
        print(f"{'='*60}")
        for chain, addr, bal, symbol, pk, path, src, original in wallets_with_balance:
            print(f"\n  Chain   : {chain}")
            print(f"  Address : {addr}")
            print(f"  Balance : {bal} {symbol}")
            print(f"  PrivKey : {pk}")
            print(f"  Path    : {path}")
            print(f"  Source  : {os.path.basename(src)}")
        print(f"\n{'='*60}")
    else:
        print("\n  No wallets with balance found on any chain.")

    # Save results
    out_file = os.path.join(INPUT_FOLDER, "multichain_results.txt")
    with open(out_file, 'w') as f:
        f.write("MULTI-CHAIN SCAN RESULTS\n")
        f.write(f"Total checked: {total_checks}\n")
        f.write(f"With balance: {len(wallets_with_balance)}\n\n")
        if wallets_with_balance:
            for chain, addr, bal, symbol, pk, path, src, original in wallets_with_balance:
                f.write(f"Chain: {chain} | Addr: {addr} | Bal: {bal} {symbol} | Key: {pk} | Path: {path}\n")
        f.write(f"\n\nAll derived addresses:\n")
        for chain, addr, pk, path, src, original in all_derived:
            f.write(f"{chain} | {addr} | {pk} | {path}\n")
    print(f"\n[*] Results saved: {out_file}")
    print("[DONE]")


if __name__ == "__main__":
    main()
