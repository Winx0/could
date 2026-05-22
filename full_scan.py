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
    from coincurve import PrivateKey
except ImportError:
    print("[!] pip install coincurve")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("[!] pip install requests")
    sys.exit(1)

INPUT_FOLDER = os.path.dirname(os.path.abspath(__file__))
WA_FILE = r"D:\Downloads\Downloads\Chat WhatsApp dengan AS ENTER DATA.txt"
DERIVE_COUNT = 5
API_DELAY = 0.3

import re


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


def privkey_to_eth(privkey_bytes):
    pk = PrivateKey(privkey_bytes)
    pub = pk.public_key.format(compressed=False)[1:]
    try:
        from Crypto.Hash import keccak
        k = keccak.new(digest_bits=256, data=pub)
        return '0x' + k.hexdigest()[-40:]
    except Exception:
        return None


def check_btc_balance(address):
    try:
        r = requests.get(f"https://blockchain.info/q/addressbalance/{address}", timeout=10)
        if r.status_code == 200:
            return int(r.text)
    except Exception:
        pass
    return 0


def check_eth_balance(address):
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


def collect_all_mnemonics():
    """Collect mnemonics from all txt files in folder + WA chat"""
    mn_obj = Mnemonic("english")
    wordlist = set(mn_obj.wordlist)
    all_mn = set()
    all_pk = set()

    # From txt files in script folder
    for f in os.listdir(INPUT_FOLDER):
        if f.endswith(('.txt', '.csv', '.log')):
            fp = os.path.join(INPUT_FOLDER, f)
            try:
                with open(fp, 'r', encoding='utf-8', errors='ignore') as file:
                    for line in file:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        # WIF key
                        if len(line) >= 51 and len(line) <= 52 and line[0] in ('5', 'K', 'L'):
                            valid = all(c in '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz' for c in line)
                            if valid:
                                all_pk.add(line)
                            continue
                        # Hex key
                        if len(line) == 64:
                            try:
                                int(line, 16)
                                all_pk.add(line)
                                continue
                            except ValueError:
                                pass
                        # Mnemonic
                        words = line.split()
                        if len(words) in (12, 15, 18, 21, 24):
                            if all(w.lower() in wordlist for w in words):
                                all_mn.add(line.lower())
            except Exception:
                pass

    # From WA chat file
    if os.path.exists(WA_FILE):
        try:
            with open(WA_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            lines = content.split('\n')
            for line in lines:
                cleaned = re.sub(r'^\d{1,2}/\d{1,2}/\d{2,4},?\s*\d{1,2}[.:]\d{2}\s*(?:AM|PM|am|pm)?\s*-\s*[^:]*:\s*', '', line).strip()
                if not cleaned:
                    continue
                words_in_line = cleaned.split()
                # Check for keys
                for word in words_in_line:
                    word = word.strip('.,;:!?()[]{}"\' ')
                    if len(word) >= 51 and len(word) <= 52 and word[0] in ('5', 'K', 'L'):
                        valid = all(c in '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz' for c in word)
                        if valid:
                            all_pk.add(word)
                    if len(word) == 64:
                        try:
                            int(word, 16)
                            all_pk.add(word)
                        except ValueError:
                            pass
                # Check for mnemonic
                bip39_words = [w.lower() for w in words_in_line if w.lower() in wordlist]
                if len(bip39_words) >= 12:
                    for length in [24, 12]:
                        if len(bip39_words) >= length:
                            candidate = ' '.join(bip39_words[:length])
                            all_mn.add(candidate)
                            break
        except Exception:
            pass

    return list(all_mn), list(all_pk)


def derive_all_addresses(mnemonic_str):
    """Derive BTC + ETH addresses from mnemonic"""
    results = []  # (chain, address, privkey_hex)
    try:
        seed = Bip39SeedGenerator(mnemonic_str).Generate("")

        # BTC BIP44
        try:
            bip44 = Bip44.FromSeed(seed, Bip44Coins.BITCOIN)
            acc = bip44.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT)
            for i in range(DERIVE_COUNT):
                obj = acc.AddressIndex(i)
                addr = obj.PublicKey().ToAddress()
                pk = obj.PrivateKey().Raw().ToHex()
                results.append(("BTC", addr, pk))
        except Exception:
            pass

        # ETH/BNB (same key)
        try:
            bip44 = Bip44.FromSeed(seed, Bip44Coins.ETHEREUM)
            acc = bip44.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT)
            for i in range(DERIVE_COUNT):
                obj = acc.AddressIndex(i)
                pk_hex = obj.PrivateKey().Raw().ToHex()
                eth_addr = privkey_to_eth(bytes.fromhex(pk_hex))
                if eth_addr:
                    results.append(("ETH", eth_addr, pk_hex))
                    results.append(("BNB", eth_addr, pk_hex))
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
                results.append(("LTC", addr, pk))
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
                results.append(("DOGE", addr, pk))
        except Exception:
            pass

        # TRX
        try:
            bip44 = Bip44.FromSeed(seed, Bip44Coins.TRON)
            acc = bip44.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT)
            for i in range(DERIVE_COUNT):
                obj = acc.AddressIndex(i)
                addr = obj.PublicKey().ToAddress()
                pk = obj.PrivateKey().Raw().ToHex()
                results.append(("TRX", addr, pk))
        except Exception:
            pass

    except Exception:
        pass
    return results


def main():
    print("=" * 60)
    print("  FULL MULTI-CHAIN BALANCE FINDER")
    print("  Gabungkan semua source, cek semua chain")
    print("=" * 60)

    print("\n[*] Collecting all mnemonics & keys...")
    all_mn, all_pk = collect_all_mnemonics()
    print(f"    Total unique mnemonics: {len(all_mn)}")
    print(f"    Total unique privkeys : {len(all_pk)}")
    print("-" * 60)

    wallets_found = []
    all_addresses = []  # (chain, addr, pk)

    # Derive from mnemonics
    if all_mn:
        print(f"\n[*] Deriving addresses from {len(all_mn)} mnemonics...")
        for idx, mn in enumerate(all_mn):
            short = ' '.join(mn.split()[:3]) + '...'
            if (idx + 1) % 10 == 0 or idx == 0:
                print(f"    [{idx+1}/{len(all_mn)}] {short}")
            derived = derive_all_addresses(mn)
            for chain, addr, pk in derived:
                all_addresses.append((chain, addr, pk, mn))

    # Derive from private keys
    if all_pk:
        print(f"\n[*] Processing {len(all_pk)} private keys...")
        for idx, pk_str in enumerate(all_pk):
            try:
                if len(pk_str) == 64:
                    priv_bytes = bytes.fromhex(pk_str)
                else:
                    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
                    num = 0
                    for char in pk_str:
                        num = num * 58 + alphabet.index(char)
                    if pk_str[0] == '5':
                        priv_bytes = num.to_bytes(37, byteorder='big')[1:33]
                    elif pk_str[0] in ('K', 'L'):
                        priv_bytes = num.to_bytes(38, byteorder='big')[1:33]
                    else:
                        continue

                # BTC
                pk_obj = PrivateKey(priv_bytes)
                pub_c = pk_obj.public_key.format(compressed=True)
                btc_addr = pubkey_to_p2pkh(pub_c)
                all_addresses.append(("BTC", btc_addr, priv_bytes.hex(), pk_str))

                # ETH/BNB
                eth_addr = privkey_to_eth(priv_bytes)
                if eth_addr:
                    all_addresses.append(("ETH", eth_addr, priv_bytes.hex(), pk_str))
                    all_addresses.append(("BNB", eth_addr, priv_bytes.hex(), pk_str))
            except Exception:
                pass

    print(f"\n[*] Total addresses to check: {len(all_addresses)}")
    print("-" * 60)

    # Check balances by chain
    print(f"\n[*] CHECKING BALANCES...")
    checked = set()
    total_checked = 0

    for chain, addr, pk, source in all_addresses:
        key = f"{chain}:{addr}"
        if key in checked:
            continue
        checked.add(key)
        total_checked += 1

        bal = 0
        try:
            if chain == "BTC":
                bal = check_btc_balance(addr)
            elif chain == "ETH":
                bal = check_eth_balance(addr)
            elif chain == "BNB":
                bal = check_bnb_balance(addr)
            elif chain == "LTC":
                bal = check_ltc_balance(addr)
            elif chain == "DOGE":
                bal = check_doge_balance(addr)
            elif chain == "TRX":
                bal = check_trx_balance(addr)
        except Exception:
            pass

        if bal > 0:
            if chain == "BTC":
                human = bal / 100_000_000
                unit = "BTC"
            elif chain in ("ETH", "BNB"):
                human = bal / 1e18
                unit = chain
            elif chain in ("LTC", "DOGE"):
                human = bal / 100_000_000
                unit = chain
            elif chain == "TRX":
                human = bal / 1_000_000
                unit = "TRX"
            else:
                human = bal
                unit = chain

            wallets_found.append((chain, addr, human, unit, pk, source))
            print(f"\n  *** BALANCE FOUND ***")
            print(f"  Chain   : {chain}")
            print(f"  Address : {addr}")
            print(f"  Balance : {human} {unit}")
            print(f"  PrivKey : {pk}")
            print(f"  Source  : {source[:50]}...")

        if total_checked % 30 == 0:
            print(f"    ... checked {total_checked}/{len(checked)} addresses")
        time.sleep(API_DELAY)

    # Summary
    print("\n" + "=" * 60)
    print(f"  SCAN COMPLETE")
    print(f"  Total checked: {total_checked}")
    print(f"  Wallets with balance: {len(wallets_found)}")
    print("=" * 60)

    if wallets_found:
        print(f"\n{'='*60}")
        print(f"  ALL WALLETS WITH BALANCE:")
        print(f"{'='*60}")
        for chain, addr, bal, unit, pk, source in wallets_found:
            print(f"\n  Chain   : {chain}")
            print(f"  Address : {addr}")
            print(f"  Balance : {bal} {unit}")
            print(f"  PrivKey : {pk}")
            print(f"  Source  : {source[:60]}")
        print(f"\n{'='*60}")

        # Save found wallets
        out_file = os.path.join(INPUT_FOLDER, "FOUND_WALLETS.txt")
        with open(out_file, 'w') as f:
            f.write("WALLETS WITH BALANCE FOUND!\n\n")
            for chain, addr, bal, unit, pk, source in wallets_found:
                f.write(f"Chain: {chain}\n")
                f.write(f"Address: {addr}\n")
                f.write(f"Balance: {bal} {unit}\n")
                f.write(f"PrivKey: {pk}\n")
                f.write(f"Source: {source}\n\n")
        print(f"\n[*] SAVED: {out_file}")
    else:
        print("\n  No wallets with balance found on any chain.")

    # Save all addresses for reference
    ref_file = os.path.join(INPUT_FOLDER, "all_addresses.txt")
    with open(ref_file, 'w') as f:
        f.write(f"Total: {len(all_addresses)}\n\n")
        for chain, addr, pk, source in all_addresses:
            f.write(f"{chain} | {addr} | {pk}\n")
    print(f"[*] All addresses saved: {ref_file}")
    print("[DONE]")


if __name__ == "__main__":
    main()
