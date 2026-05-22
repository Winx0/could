import os
import sys
import hashlib
import time
import itertools

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

TARGET_ADDRESS = "1B8hgFxNK7ac2k5EtrAanxQPFcnfHLMcko"
INPUT_FOLDER = os.path.dirname(os.path.abspath(__file__))
DERIVE_COUNT = 5


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


def check_mnemonic_for_target(mnemonic_str):
    """Check if mnemonic produces target address. Returns (found, path, privkey) or (False, None, None)"""
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
                if addr == TARGET_ADDRESS:
                    return True, f"BIP44 m/44'/0'/0'/0/{i}", addr_obj.PrivateKey().Raw().ToHex()
            chain_int = account.Change(Bip44Changes.CHAIN_INT)
            for i in range(DERIVE_COUNT):
                addr_obj = chain_int.AddressIndex(i)
                addr = addr_obj.PublicKey().ToAddress()
                if addr == TARGET_ADDRESS:
                    return True, f"BIP44 m/44'/0'/0'/1/{i}", addr_obj.PrivateKey().Raw().ToHex()
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
                if addr == TARGET_ADDRESS:
                    return True, f"BIP32 m/0/{i}", priv_bytes.hex()
        except Exception:
            pass
    except Exception:
        pass
    return False, None, None


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
        words = line.split()
        if len(words) in (12, 15, 18, 21, 24):
            if m.check(line):
                items.append(line)
            elif all(w.isalpha() for w in words):
                items.append(line)
    return items


def bruteforce_swap(mnemonic_str, mn_obj):
    """Try swapping every pair of words"""
    words = mnemonic_str.split()
    n = len(words)
    attempts = 0
    for i in range(n):
        for j in range(i + 1, n):
            swapped = words[:]
            swapped[i], swapped[j] = swapped[j], swapped[i]
            candidate = ' '.join(swapped)
            if mn_obj.check(candidate):
                found, path, pk = check_mnemonic_for_target(candidate)
                if found:
                    return True, candidate, path, pk
            attempts += 1
    return False, None, None, None


def bruteforce_replace_one(mnemonic_str, wordlist, mn_obj):
    """Try replacing each word with every word in BIP39 wordlist"""
    words = mnemonic_str.split()
    n = len(words)
    attempts = 0
    for pos in range(n):
        original_word = words[pos]
        for new_word in wordlist:
            if new_word == original_word:
                continue
            candidate_words = words[:]
            candidate_words[pos] = new_word
            candidate = ' '.join(candidate_words)
            if mn_obj.check(candidate):
                found, path, pk = check_mnemonic_for_target(candidate)
                if found:
                    return True, candidate, path, pk
            attempts += 1
            if attempts % 5000 == 0:
                print(f"        ... {attempts} attempts (pos {pos+1}/{n})")
    return False, None, None, None


def bruteforce_swap_adjacent(mnemonic_str, mn_obj):
    """Try swapping adjacent words (common mistake when writing down)"""
    words = mnemonic_str.split()
    n = len(words)
    for i in range(n - 1):
        swapped = words[:]
        swapped[i], swapped[i+1] = swapped[i+1], swapped[i]
        candidate = ' '.join(swapped)
        if mn_obj.check(candidate):
            found, path, pk = check_mnemonic_for_target(candidate)
            if found:
                return True, candidate, path, pk
    return False, None, None, None


def main():
    print("=" * 60)
    print("  MNEMONIC BRUTE FORCE CORRECTION")
    print("=" * 60)
    print(f"  Target : {TARGET_ADDRESS}")
    print(f"  Folder : {INPUT_FOLDER}")
    print(f"  Method : Swap pairs + Replace 1 word")
    print("=" * 60)

    mn_obj = Mnemonic("english")
    wordlist = mn_obj.wordlist

    # Scan files for mnemonics
    all_files = [os.path.join(INPUT_FOLDER, f) for f in os.listdir(INPUT_FOLDER)
                 if f.endswith(('.txt', '.csv', '.json', '.log'))]

    all_mnemonics = []
    for fp in all_files:
        mnemonics = scan_file(fp)
        for m in mnemonics:
            all_mnemonics.append((m, fp))

    print(f"\n[*] Mnemonics found: {len(all_mnemonics)}")
    print(f"[*] Wordlist size: {len(wordlist)}")
    print("-" * 60)

    if not all_mnemonics:
        print("[!] No mnemonics found in files!")
        sys.exit(1)

    found = False
    start_time = time.time()

    for idx, (mn, src) in enumerate(all_mnemonics):
        short = ' '.join(mn.split()[:3]) + '...'
        word_count = len(mn.split())
        print(f"\n[{idx+1}/{len(all_mnemonics)}] Testing: {short} ({word_count} words)")
        print(f"    Source: {os.path.basename(src)}")

        # Phase 1: Try original first
        print(f"    [Phase 0] Testing original...")
        ok, path, pk = check_mnemonic_for_target(mn)
        if ok:
            print(f"\n{'='*60}")
            print(f"  *** FOUND WITH ORIGINAL MNEMONIC ***")
            print(f"  Mnemonic : {mn}")
            print(f"  Path     : {path}")
            print(f"  PrivKey  : {pk}")
            print(f"{'='*60}")
            found = True
            break

        # Phase 2: Swap adjacent words
        print(f"    [Phase 1] Swapping adjacent words...")
        ok, corrected, path, pk = bruteforce_swap_adjacent(mn, mn_obj)
        if ok:
            print(f"\n{'='*60}")
            print(f"  *** FOUND WITH ADJACENT SWAP ***")
            print(f"  Original : {mn}")
            print(f"  Corrected: {corrected}")
            print(f"  Path     : {path}")
            print(f"  PrivKey  : {pk}")
            print(f"{'='*60}")
            found = True
            break

        # Phase 3: Swap any 2 words
        print(f"    [Phase 2] Swapping any 2 words ({word_count*(word_count-1)//2} combinations)...")
        ok, corrected, path, pk = bruteforce_swap(mn, mn_obj)
        if ok:
            print(f"\n{'='*60}")
            print(f"  *** FOUND WITH WORD SWAP ***")
            print(f"  Original : {mn}")
            print(f"  Corrected: {corrected}")
            print(f"  Path     : {path}")
            print(f"  PrivKey  : {pk}")
            print(f"{'='*60}")
            found = True
            break

        # Phase 4: Replace 1 word
        total_attempts = word_count * len(wordlist)
        print(f"    [Phase 3] Replacing 1 word ({total_attempts} combinations)...")
        ok, corrected, path, pk = bruteforce_replace_one(mn, wordlist, mn_obj)
        if ok:
            print(f"\n{'='*60}")
            print(f"  *** FOUND WITH WORD REPLACEMENT ***")
            print(f"  Original : {mn}")
            print(f"  Corrected: {corrected}")
            print(f"  Path     : {path}")
            print(f"  PrivKey  : {pk}")
            print(f"{'='*60}")
            found = True
            break

        elapsed = time.time() - start_time
        print(f"    Done. Elapsed: {elapsed:.1f}s")

    print("\n" + "=" * 60)
    total_time = time.time() - start_time
    if found:
        print(f"  SUCCESS! Target address found!")
        print(f"  Time: {total_time:.1f}s")
        # Save to file
        out_file = os.path.join(INPUT_FOLDER, "bruteforce_result.txt")
        with open(out_file, 'w') as f:
            f.write(f"TARGET FOUND!\n")
            f.write(f"Address: {TARGET_ADDRESS}\n")
            f.write(f"Corrected mnemonic: {corrected}\n")
            f.write(f"Path: {path}\n")
            f.write(f"Private Key: {pk}\n")
        print(f"  Saved to: {out_file}")
    else:
        print(f"  Target NOT found after trying all corrections.")
        print(f"  Time: {total_time:.1f}s")
        print(f"\n  Suggestions:")
        print(f"  - Try with passphrase (25th word)")
        print(f"  - Check if more mnemonics exist elsewhere")
        print(f"  - Try replacing 2 words (much slower)")
    print("=" * 60)


if __name__ == "__main__":
    main()
