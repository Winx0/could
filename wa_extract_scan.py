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
TARGET_ADDRESS = "1B8hgFxNK7ac2k5EtrAanxQPFcnfHLMcko"
WA_FILE = r"D:\Downloads\Downloads\Chat WhatsApp dengan AS ENTER DATA.txt"
OUTPUT_FOLDER = os.path.dirname(os.path.abspath(__file__))
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


def pubkey_to_p2pkh(pubkey_bytes):
    sha = hashlib.sha256(pubkey_bytes).digest()
    ripe = hashlib.new('ripemd160', sha).digest()
    versioned = b'\x00' + ripe
    checksum = hashlib.sha256(hashlib.sha256(versioned).digest()).digest()[:4]
    return base58_encode(versioned + checksum)


def privkey_to_pubkey_compressed(privkey_bytes):
    pk = PrivateKey(privkey_bytes)
    return pk.public_key.format(compressed=True)


def privkey_to_pubkey_uncompressed(privkey_bytes):
    pk = PrivateKey(privkey_bytes)
    return pk.public_key.format(compressed=False)


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
        # BIP44 Account 1
        try:
            bip44 = Bip44.FromSeed(seed, Bip44Coins.BITCOIN)
            account1 = bip44.Purpose().Coin().Account(1)
            chain_ext1 = account1.Change(Bip44Changes.CHAIN_EXT)
            for i in range(DERIVE_COUNT):
                addr_obj = chain_ext1.AddressIndex(i)
                addr = addr_obj.PublicKey().ToAddress()
                priv_hex = addr_obj.PrivateKey().Raw().ToHex()
                addresses.append((addr, f"BIP44 m/44'/0'/1'/0/{i}", priv_hex))
        except Exception:
            pass
    except Exception:
        pass
    return addresses


def extract_crypto_from_wa(filepath):
    """Extract mnemonics and private keys from WhatsApp chat export"""
    mnemonics = []
    privkeys = []

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        print(f"[ERROR] Cannot read file: {e}")
        return mnemonics, privkeys

    mn_obj = Mnemonic("english")
    wordlist = set(mn_obj.wordlist)

    # Method 1: Find lines that look like mnemonics (12/24 BIP39 words)
    lines = content.split('\n')
    for line in lines:
        # Remove WA timestamp/sender prefix
        # Format: "1/15/23, 10:30 - Person: actual message"
        cleaned = re.sub(r'^\d{1,2}/\d{1,2}/\d{2,4},?\s*\d{1,2}[.:]\d{2}\s*(?:AM|PM|am|pm)?\s*-\s*[^:]*:\s*', '', line)
        cleaned = cleaned.strip()

        if not cleaned:
            continue

        # Check for WIF private key
        words_in_line = cleaned.split()
        for word in words_in_line:
            word = word.strip('.,;:!?()[]{}"\' ')
            if len(word) >= 51 and len(word) <= 52 and word[0] in ('5', 'K', 'L'):
                # Validate it's base58
                valid = all(c in '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz' for c in word)
                if valid:
                    privkeys.append(word)

            # Hex private key
            if len(word) == 64:
                try:
                    int(word, 16)
                    privkeys.append(word)
                except ValueError:
                    pass

        # Check if line contains 12+ BIP39 words
        bip39_words = [w.lower() for w in words_in_line if w.lower() in wordlist]

        if len(bip39_words) >= 12:
            # Try as mnemonic (take first 12 or 24)
            for length in [24, 12]:
                if len(bip39_words) >= length:
                    candidate = ' '.join(bip39_words[:length])
                    if mn_obj.check(candidate):
                        mnemonics.append(candidate)
                    else:
                        # Still add as unverified
                        mnemonics.append(candidate)
                    break

    # Method 2: Sliding window - find consecutive BIP39 words across lines
    all_words = []
    for line in lines:
        cleaned = re.sub(r'^\d{1,2}/\d{1,2}/\d{2,4},?\s*\d{1,2}[.:]\d{2}\s*(?:AM|PM|am|pm)?\s*-\s*[^:]*:\s*', '', line)
        for w in cleaned.split():
            w_clean = w.strip('.,;:!?()[]{}"\' ').lower()
            if w_clean in wordlist:
                all_words.append(w_clean)
            else:
                all_words.append(None)

    # Find sequences of 12+ consecutive BIP39 words
    i = 0
    while i < len(all_words):
        if all_words[i] is not None:
            seq = []
            j = i
            while j < len(all_words) and all_words[j] is not None:
                seq.append(all_words[j])
                j += 1
            if len(seq) >= 12:
                # Try 12-word and 24-word chunks
                for start in range(0, len(seq) - 11):
                    candidate12 = ' '.join(seq[start:start+12])
                    if mn_obj.check(candidate12):
                        mnemonics.append(candidate12)
                    if start + 24 <= len(seq):
                        candidate24 = ' '.join(seq[start:start+24])
                        if mn_obj.check(candidate24):
                            mnemonics.append(candidate24)
            i = j
        else:
            i += 1

    # Remove duplicates
    mnemonics = list(set(mnemonics))
    privkeys = list(set(privkeys))

    return mnemonics, privkeys


def main():
    print("=" * 60)
    print("  WHATSAPP CHAT CRYPTO EXTRACTOR & SCANNER")
    print("=" * 60)
    print(f"  Target : {TARGET_ADDRESS}")
    print(f"  File   : {WA_FILE}")
    print("=" * 60)

    if not os.path.exists(WA_FILE):
        print(f"\n[ERROR] File not found: {WA_FILE}")
        print("  Check the path!")
        sys.exit(1)

    file_size = os.path.getsize(WA_FILE)
    print(f"\n[*] File size: {file_size / 1024:.1f} KB")
    print("[*] Extracting crypto data from WhatsApp chat...")

    mnemonics, privkeys = extract_crypto_from_wa(WA_FILE)

    print(f"\n[*] Extracted:")
    print(f"    Mnemonics found   : {len(mnemonics)}")
    print(f"    Private keys found: {len(privkeys)}")
    print("-" * 60)

    # Save extracted data
    extract_file = os.path.join(OUTPUT_FOLDER, "wa_extracted.txt")
    with open(extract_file, 'w') as f:
        f.write("# Mnemonics extracted from WhatsApp chat\n")
        for mn in mnemonics:
            f.write(f"{mn}\n")
        f.write("\n# Private keys extracted from WhatsApp chat\n")
        for pk in privkeys:
            f.write(f"{pk}\n")
    print(f"[*] Extracted data saved: {extract_file}")

    if not mnemonics and not privkeys:
        print("\n[!] No crypto data found in chat!")
        print("    The chat might use different format or encoding.")
        sys.exit(0)

    # Process mnemonics
    found_target = False
    all_addresses = []

    if mnemonics:
        print(f"\n[*] Processing {len(mnemonics)} mnemonics...")
        for idx, mn in enumerate(mnemonics):
            short = ' '.join(mn.split()[:3]) + '...'
            print(f"    [{idx+1}/{len(mnemonics)}] {short}")
            for addr, path_info, priv_hex in mnemonic_to_addresses(mn):
                all_addresses.append((addr, f"{short} | {path_info}", priv_hex))
                if addr == TARGET_ADDRESS:
                    found_target = True
                    print(f"\n  *** TARGET FOUND ***")
                    print(f"  Mnemonic : {mn}")
                    print(f"  Path     : {path_info}")
                    print(f"  PrivKey  : {priv_hex}\n")

    # Process private keys
    if privkeys:
        print(f"\n[*] Processing {len(privkeys)} private keys...")
        for idx, pk_str in enumerate(privkeys):
            short_pk = pk_str[:8] + '...'
            print(f"    [{idx+1}/{len(privkeys)}] {short_pk}")
            try:
                if len(pk_str) == 64:
                    priv_bytes = bytes.fromhex(pk_str)
                else:
                    priv_bytes, compressed = decode_wif(pk_str)
                    if not priv_bytes:
                        continue

                pub_c = privkey_to_pubkey_compressed(priv_bytes)
                addr_c = pubkey_to_p2pkh(pub_c)
                all_addresses.append((addr_c, f"PK(c): {short_pk}", priv_bytes.hex()))
                if addr_c == TARGET_ADDRESS:
                    found_target = True
                    print(f"\n  *** TARGET FOUND ***")
                    print(f"  PrivKey: {pk_str}\n")

                pub_u = privkey_to_pubkey_uncompressed(priv_bytes)
                addr_u = pubkey_to_p2pkh(pub_u)
                all_addresses.append((addr_u, f"PK(u): {short_pk}", priv_bytes.hex()))
                if addr_u == TARGET_ADDRESS:
                    found_target = True
                    print(f"\n  *** TARGET FOUND (uncompressed) ***")
                    print(f"  PrivKey: {pk_str}\n")
            except Exception:
                pass

    print("\n" + "=" * 60)
    print(f"  EXTRACTION & SCAN COMPLETE")
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

    # Save full results
    out_file = os.path.join(OUTPUT_FOLDER, "wa_scan_results.txt")
    with open(out_file, 'w') as f:
        f.write(f"Target: {TARGET_ADDRESS}\nFound: {found_target}\n")
        f.write(f"Mnemonics: {len(mnemonics)}\nPrivKeys: {len(privkeys)}\n")
        f.write(f"Total addresses: {len(all_addresses)}\n\n")
        for addr, src, pk in all_addresses:
            tag = "MATCH!" if addr == TARGET_ADDRESS else ""
            f.write(f"{tag} {addr} | {src} | {pk}\n")
    print(f"\n[*] Full results saved: {out_file}")
    print("[DONE]")


if __name__ == "__main__":
    main()
