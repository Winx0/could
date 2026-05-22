import os
import sys
import hashlib
import time
import re

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

# ============ CONFIGURATION ============
MIN_USD = 100  # Minimum $100 balance to report
INPUT_FOLDER = os.path.dirname(os.path.abspath(__file__))
WA_FILE = r"D:\Downloads\Downloads\Chat WhatsApp dengan AS ENTER DATA.txt"
DERIVE_COUNT = 10
API_DELAY = 0.5
# ========================================


def get_prices():
    """Get current crypto prices in USD"""
    prices = {"BTC": 0, "ETH": 0, "BNB": 0, "LTC": 0, "DOGE": 0, "TRX": 0}
    try:
        url = "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin,ethereum,binancecoin,litecoin,dogecoin,tron&vs_currencies=usd"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            prices["BTC"] = data.get("bitcoin", {}).get("usd", 0)
            prices["ETH"] = data.get("ethereum", {}).get("usd", 0)
            prices["BNB"] = data.get("binancecoin", {}).get("usd", 0)
            prices["LTC"] = data.get("litecoin", {}).get("usd", 0)
            prices["DOGE"] = data.get("dogecoin", {}).get("usd", 0)
            prices["TRX"] = data.get("tron", {}).get("usd", 0)
    except Exception:
        # Fallback approximate prices
        prices = {"BTC": 70000, "ETH": 3500, "BNB": 600, "LTC": 80, "DOGE": 0.15, "TRX": 0.25}
    return prices


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
    """Collect mnemonics from all sources"""
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
                        if len(line) >= 51 and len(line) <= 52 and line[0] in ('5', 'K', 'L'):
                            valid = all(c in '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz' for c in line)
                            if valid:
                                all_pk.add(line)
                            continue
                        if len(line) == 64:
                            try:
                                int(line, 16)
                                all_pk.add(line)
                                continue
                            except ValueError:
                                pass
                        words = line.split()
                        if len(words) in (12, 15, 18, 21, 24):
                            if all(w.lower() in wordlist for w in words):
                                all_mn.add(' '.join(w.lower() for w in words))
            except Exception:
                pass

    # From WA chat
    if os.path.exists(WA_FILE):
        try:
            with open(WA_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            for line in content.split('\n'):
                cleaned = re.sub(r'^\d{1,2}/\d{1,2}/\d{2,4},?\s*\d{1,2}[.:]\d{2}\s*(?:AM|PM|am|pm)?\s*-\s*[^:]*:\s*', '', line).strip()
                if not cleaned:
                    continue
                words_in_line = cleaned.split()
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
                bip39_words = [w.lower() for w in words_in_line if w.lower() in wordlist]
                if len(bip39_words) >= 12:
                    for length in [24, 12]:
                        if len(bip39_words) >= length:
                            all_mn.add(' '.join(bip39_words[:length]))
                            break
        except Exception:
            pass

    return list(all_mn), list(all_pk)


def derive_and_check(mnemonic_str, prices):
    """Derive addresses and check balance, return only those above MIN_USD"""
    results = []
    try:
        seed = Bip39SeedGenerator(mnemonic_str).Generate("")

        # BTC
        try:
            bip44 = Bip44.FromSeed(seed, Bip44Coins.BITCOIN)
            acc = bip44.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT)
            for i in range(DERIVE_COUNT):
                obj = acc.AddressIndex(i)
                addr = obj.PublicKey().ToAddress()
                pk = obj.PrivateKey().Raw().ToHex()
                bal = check_btc_balance(addr)
                if bal > 0:
                    btc = bal / 100_000_000
                    usd = btc * prices["BTC"]
                    if usd >= MIN_USD:
                        results.append(("BTC", addr, btc, usd, pk, mnemonic_str))
                    else:
                        print(f"      [small] BTC {addr}: {btc:.8f} BTC (${usd:.2f})")
                time.sleep(API_DELAY)
        except Exception:
            pass

        # ETH/BNB
        try:
            bip44 = Bip44.FromSeed(seed, Bip44Coins.ETHEREUM)
            acc = bip44.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT)
            for i in range(DERIVE_COUNT):
                obj = acc.AddressIndex(i)
                pk_hex = obj.PrivateKey().Raw().ToHex()
                eth_addr = privkey_to_eth(bytes.fromhex(pk_hex))
                if eth_addr:
                    # ETH
                    bal = check_eth_balance(eth_addr)
                    if bal > 0:
                        eth = bal / 1e18
                        usd = eth * prices["ETH"]
                        if usd >= MIN_USD:
                            results.append(("ETH", eth_addr, eth, usd, pk_hex, mnemonic_str))
                        else:
                            print(f"      [small] ETH {eth_addr}: {eth:.6f} ETH (${usd:.2f})")
                    time.sleep(API_DELAY)
                    # BNB
                    bal = check_bnb_balance(eth_addr)
                    if bal > 0:
                        bnb = bal / 1e18
                        usd = bnb * prices["BNB"]
                        if usd >= MIN_USD:
                            results.append(("BNB", eth_addr, bnb, usd, pk_hex, mnemonic_str))
                        else:
                            print(f"      [small] BNB {eth_addr}: {bnb:.6f} BNB (${usd:.2f})")
                    time.sleep(API_DELAY)
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
                bal = check_ltc_balance(addr)
                if bal > 0:
                    ltc = bal / 100_000_000
                    usd = ltc * prices["LTC"]
                    if usd >= MIN_USD:
                        results.append(("LTC", addr, ltc, usd, pk, mnemonic_str))
                    else:
                        print(f"      [small] LTC {addr}: {ltc:.8f} LTC (${usd:.2f})")
                time.sleep(API_DELAY)
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
                bal = check_doge_balance(addr)
                if bal > 0:
                    doge = bal / 100_000_000
                    usd = doge * prices["DOGE"]
                    if usd >= MIN_USD:
                        results.append(("DOGE", addr, doge, usd, pk, mnemonic_str))
                    else:
                        print(f"      [small] DOGE {addr}: {doge:.2f} DOGE (${usd:.2f})")
                time.sleep(API_DELAY)
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
                bal = check_trx_balance(addr)
                if bal > 0:
                    trx = bal / 1_000_000
                    usd = trx * prices["TRX"]
                    if usd >= MIN_USD:
                        results.append(("TRX", addr, trx, usd, pk, mnemonic_str))
                    else:
                        print(f"      [small] TRX {addr}: {trx:.2f} TRX (${usd:.2f})")
                time.sleep(API_DELAY)
        except Exception:
            pass

    except Exception:
        pass
    return results


def main():
    print("=" * 60)
    print("  HIGH BALANCE FINDER (>$100 USD)")
    print("=" * 60)
    print(f"  Minimum : ${MIN_USD} USD")
    print(f"  Chains  : BTC, ETH, BNB, LTC, DOGE, TRX")
    print("=" * 60)

    # Get prices
    print("\n[*] Fetching crypto prices...")
    prices = get_prices()
    print(f"    BTC: ${prices['BTC']:,.0f}")
    print(f"    ETH: ${prices['ETH']:,.0f}")
    print(f"    BNB: ${prices['BNB']:,.0f}")
    print(f"    LTC: ${prices['LTC']:,.0f}")
    print(f"    DOGE: ${prices['DOGE']:.4f}")
    print(f"    TRX: ${prices['TRX']:.4f}")

    # Collect data
    print("\n[*] Collecting all mnemonics & keys...")
    all_mn, all_pk = collect_all_mnemonics()
    print(f"    Mnemonics: {len(all_mn)}")
    print(f"    PrivKeys : {len(all_pk)}")
    print("-" * 60)

    big_wallets = []

    # Process mnemonics
    if all_mn:
        print(f"\n[*] Scanning {len(all_mn)} mnemonics across all chains...")
        print(f"    (Only showing wallets with balance >= ${MIN_USD})")
        print()
        for idx, mn in enumerate(all_mn):
            short = ' '.join(mn.split()[:3]) + '...'
            print(f"  [{idx+1}/{len(all_mn)}] {short}")
            found = derive_and_check(mn, prices)
            if found:
                for item in found:
                    big_wallets.append(item)
                    chain, addr, bal, usd, pk, source = item
                    print(f"\n  {'='*50}")
                    print(f"  $$$ HIGH VALUE WALLET FOUND $$$")
                    print(f"  Chain   : {chain}")
                    print(f"  Address : {addr}")
                    print(f"  Balance : {bal} {chain} (${usd:.2f})")
                    print(f"  PrivKey : {pk}")
                    print(f"  Mnemonic: {source}")
                    print(f"  {'='*50}\n")

    # Process private keys
    if all_pk:
        print(f"\n[*] Scanning {len(all_pk)} private keys...")
        for idx, pk_str in enumerate(all_pk):
            short_pk = pk_str[:8] + '...'
            print(f"  [{idx+1}/{len(all_pk)}] {short_pk}")
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
                bal = check_btc_balance(btc_addr)
                if bal > 0:
                    btc = bal / 100_000_000
                    usd = btc * prices["BTC"]
                    if usd >= MIN_USD:
                        big_wallets.append(("BTC", btc_addr, btc, usd, priv_bytes.hex(), pk_str))
                        print(f"\n  $$$ BTC FOUND: {btc:.8f} BTC (${usd:.2f}) $$$")
                    else:
                        print(f"      [small] BTC: {btc:.8f} BTC (${usd:.2f})")
                time.sleep(API_DELAY)

                # ETH/BNB
                eth_addr = privkey_to_eth(priv_bytes)
                if eth_addr:
                    bal = check_eth_balance(eth_addr)
                    if bal > 0:
                        eth = bal / 1e18
                        usd = eth * prices["ETH"]
                        if usd >= MIN_USD:
                            big_wallets.append(("ETH", eth_addr, eth, usd, priv_bytes.hex(), pk_str))
                            print(f"\n  $$$ ETH FOUND: {eth:.6f} ETH (${usd:.2f}) $$$")
                        else:
                            print(f"      [small] ETH: {eth:.6f} ETH (${usd:.2f})")
                    time.sleep(API_DELAY)
                    bal = check_bnb_balance(eth_addr)
                    if bal > 0:
                        bnb = bal / 1e18
                        usd = bnb * prices["BNB"]
                        if usd >= MIN_USD:
                            big_wallets.append(("BNB", eth_addr, bnb, usd, priv_bytes.hex(), pk_str))
                            print(f"\n  $$$ BNB FOUND: {bnb:.6f} BNB (${usd:.2f}) $$$")
                        else:
                            print(f"      [small] BNB: {bnb:.6f} BNB (${usd:.2f})")
                    time.sleep(API_DELAY)
            except Exception:
                pass

    # Final summary
    print("\n" + "=" * 60)
    print(f"  SCAN COMPLETE")
    print(f"  Wallets >= ${MIN_USD}: {len(big_wallets)}")
    print("=" * 60)

    if big_wallets:
        total_usd = sum(w[3] for w in big_wallets)
        print(f"\n  TOTAL VALUE FOUND: ${total_usd:,.2f} USD")
        print(f"\n{'='*60}")
        print(f"  HIGH VALUE WALLETS:")
        print(f"{'='*60}")
        for chain, addr, bal, usd, pk, source in big_wallets:
            print(f"\n  Chain    : {chain}")
            print(f"  Address  : {addr}")
            print(f"  Balance  : {bal} {chain} (${usd:.2f})")
            print(f"  PrivKey  : {pk}")
            print(f"  Source   : {source[:60]}")
        print(f"\n{'='*60}")

        # Save
        out_file = os.path.join(INPUT_FOLDER, "HIGH_VALUE_WALLETS.txt")
        with open(out_file, 'w') as f:
            f.write(f"HIGH VALUE WALLETS (>= ${MIN_USD})\n")
            f.write(f"Total USD: ${total_usd:,.2f}\n\n")
            for chain, addr, bal, usd, pk, source in big_wallets:
                f.write(f"Chain: {chain}\n")
                f.write(f"Address: {addr}\n")
                f.write(f"Balance: {bal} {chain} (${usd:.2f})\n")
                f.write(f"PrivKey: {pk}\n")
                f.write(f"Source: {source}\n\n")
        print(f"\n[*] SAVED: {out_file}")
    else:
        print("\n  No wallets with balance >= $100 found.")

    print("[DONE]")


if __name__ == "__main__":
    main()
