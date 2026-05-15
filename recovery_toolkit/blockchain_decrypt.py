#!/usr/bin/env python3
"""
Bitcoin Wallet Recovery - Blockchain.com Wallet Decryptor
==========================================================
Decrypts a `wallet.aes.json` backup file from Blockchain.com.

Now supports:
  - Multiple wallet files at once (you have many accounts)
  - Single password attempt
  - Password candidate list (brute-force from your guesses)
  - Auto-check if target address (1B8hg...LMcko) exists in decrypted wallet
  - All Blockchain.com format versions (v1/v2/v3/v4)

USAGE:
  # Single wallet, interactive password
  python blockchain_decrypt.py wallet.aes.json

  # Multiple wallets at once
  python blockchain_decrypt.py wallet1.aes.json wallet2.aes.json wallet3.aes.json

  # All wallets in a folder
  python blockchain_decrypt.py /path/to/wallets/*.aes.json

  # Brute force with candidates
  python blockchain_decrypt.py wallet.aes.json --candidates passwords.txt

  # Check decrypted wallet against target address
  python blockchain_decrypt.py wallet.aes.json --target 1B8hgFxNK7ac2k5EtrAanxQPFcnfHLMcko

SECURITY:
  - Run on YOUR OWN OFFLINE computer
  - Output contains private keys in plain text - HANDLE WITH CARE
  - Never run on shared/cloud machine
"""

import argparse
import base64
import getpass
import json
import sys
from pathlib import Path

try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Hash import SHA256
except ImportError:
    print("Run: pip install pycryptodome")
    sys.exit(1)

DEFAULT_TARGET = "1B8hgFxNK7ac2k5EtrAanxQPFcnfHLMcko"


# ============================================================================
# CORE DECRYPTION
# ============================================================================

def try_decrypt(payload_b64: str, password: str, iterations: int) -> str:
    """
    Try decrypt one Blockchain.com payload with given iterations.
    Returns plain JSON string if success, raises Exception if fails.
    """
    raw = base64.b64decode(payload_b64)
    iv = raw[:16]
    ciphertext = raw[16:]

    key = PBKDF2(
        password.encode('utf-8'),
        iv,
        dkLen=32,
        count=iterations,
        hmac_hash_module=SHA256,
    )
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    # Strip PKCS#7 padding
    pad_len = plaintext[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("invalid padding")
    plaintext = plaintext[:-pad_len]

    text = plaintext.decode('utf-8')
    if not (text.startswith('{') or text.startswith('[')):
        raise ValueError("not json output")
    # Try parse to confirm
    json.loads(text)
    return text


def attempt_password(payload_b64: str, version: int, password: str):
    """
    Try multiple iteration counts (Blockchain.com used different ones over time).
    Returns (plaintext, iterations) on success, (None, None) on failure.
    """
    if version == 1:
        iter_options = [10]
    elif version == 2:
        iter_options = [1000]
    elif version == 3:
        iter_options = [5000]
    elif version == 4:
        iter_options = [5000, 10000]
    else:
        # Unknown - try common values
        iter_options = [5000, 10000, 1000, 10, 100, 50000]

    for it in iter_options:
        try:
            return try_decrypt(payload_b64, password, it), it
        except Exception:
            continue
    return None, None


# ============================================================================
# WALLET INSPECTION
# ============================================================================

def extract_addresses(decrypted_json: str) -> list:
    """Extract all BTC addresses from decrypted wallet content."""
    data = json.loads(decrypted_json)
    addresses = []

    # Imported / legacy keys
    for k in data.get("keys", []):
        addr = k.get("addr")
        if addr:
            addresses.append(("imported", addr))

    # Address book
    for a in data.get("address_book", []):
        addr = a.get("addr")
        if addr:
            addresses.append(("address_book", addr))

    # HD account watching addresses (cached)
    for w in data.get("hd_wallets", []):
        for acct in w.get("accounts", []):
            for cache_type in ("cache",):
                cache = acct.get(cache_type, {})
                # Some versions store ext/int chain xpubs only — addresses
                # are derived later. We just record xpub.
                if "receiveAccount" in cache:
                    addresses.append(("hd_xpub_recv", cache["receiveAccount"]))
                if "changeAccount" in cache:
                    addresses.append(("hd_xpub_chg", cache["changeAccount"]))

    return addresses


def derive_hd_addresses_from_seed(decrypted_json: str, gap: int = 100) -> list:
    """
    Generate first N addresses from each HD wallet seed/mnemonic.
    Returns list of (path, address).
    """
    try:
        from bip_utils import (
            Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes,
        )
    except ImportError:
        return []

    data = json.loads(decrypted_json)
    found = []

    for w in data.get("hd_wallets", []):
        mnemonic = w.get("mnemonic_verified") or w.get("mnemonic")
        if not mnemonic:
            continue
        try:
            seed = Bip39SeedGenerator(mnemonic).Generate(w.get("passphrase", ""))
            ctx = Bip44.FromSeed(seed, Bip44Coins.BITCOIN)
            for change in (Bip44Changes.CHAIN_EXT, Bip44Changes.CHAIN_INT):
                for i in range(gap):
                    addr = ctx.Purpose().Coin().Account(0).Change(change).AddressIndex(i).PublicKey().ToAddress()
                    found.append((f"BIP44 {change.name} idx {i}", addr))
        except Exception as e:
            print(f"  Warning: HD derivation error: {e}")

    return found


def show_decrypted(plaintext: str, target_address: str = None):
    """Pretty-print the decrypted wallet content."""
    data = json.loads(plaintext)
    print("\n=== DECRYPTED WALLET CONTENT ===")
    print("(Keys/seed below are in PLAIN TEXT - handle securely)")
    print()

    # Wallet GUID
    guid = data.get("guid", "?")
    print(f"Wallet GUID: {guid}")

    # HD wallets
    hdws = data.get("hd_wallets", [])
    print(f"\nHD wallets: {len(hdws)}")
    for idx, w in enumerate(hdws):
        seed_hex = w.get("seed_hex")
        mnemonic = w.get("mnemonic_verified") or w.get("mnemonic")
        passphrase = w.get("passphrase", "")
        if seed_hex:
            print(f"  [{idx}] Seed (hex): {seed_hex}")
        if mnemonic:
            print(f"  [{idx}] Mnemonic: {mnemonic}")
        if passphrase:
            print(f"  [{idx}] BIP39 passphrase: '{passphrase}'")

    # Imported keys (legacy addresses imported manually)
    keys = data.get("keys", [])
    print(f"\nImported keys: {len(keys)}")
    target_hit_in_imported = False
    for k in keys:
        addr = k.get("addr", "?")
        priv = k.get("priv", "?")
        label = k.get("label", "")
        marker = ""
        if target_address and addr == target_address:
            marker = "  <<< TARGET ADDRESS FOUND! >>>"
            target_hit_in_imported = True
        print(f"  {addr}  | priv: {priv}  | label: {label}{marker}")

    # Auto-derive HD addresses to check against target
    if target_address and not target_hit_in_imported:
        print(f"\nDeriving HD addresses to check vs target {target_address}...")
        derived = derive_hd_addresses_from_seed(plaintext, gap=100)
        hit = None
        for path, addr in derived:
            if addr == target_address:
                hit = (path, addr)
                break
        if hit:
            print(f"\n  >>> TARGET FOUND in HD derivation: {hit[0]}")
        else:
            print(f"  Target not in first 100 HD addresses (ext + int chains)")
            print(f"  Try increasing gap limit or check derivation path.")

    # Save full JSON
    out = Path("decrypted_wallet.json")
    out.write_text(plaintext)
    print(f"\nFull decrypted JSON saved to: {out.resolve()}")
    print("REMEMBER: Delete this file after extracting your keys!")


# ============================================================================
# MAIN
# ============================================================================

def process_wallet(wallet_path: Path, candidates: list, target: str):
    print(f"\n{'='*70}")
    print(f"Wallet file: {wallet_path}")
    print(f"{'='*70}")

    try:
        with open(wallet_path) as f:
            envelope = json.load(f)
    except Exception as e:
        print(f"Failed to load file: {e}")
        return False

    payload = envelope.get("payload")
    version = envelope.get("version", 0)
    if not payload:
        # Some old formats don't wrap in envelope
        if isinstance(envelope, str):
            payload = envelope
        else:
            print("Format not recognized (no 'payload' key)")
            return False

    print(f"Wallet version: {version}")
    print(f"Payload length: {len(payload)} chars")

    if candidates:
        print(f"Trying {len(candidates)} password candidates...")
        for i, pw in enumerate(candidates, 1):
            if i % 100 == 0:
                print(f"  ... {i}/{len(candidates)} tried")
            result, iters = attempt_password(payload, version, pw)
            if result:
                print(f"\n*** PASSWORD FOUND: '{pw}' (iterations={iters}) ***")
                show_decrypted(result, target)
                return True
        print("\nNo password from candidates worked.")
        return False
    else:
        pw = getpass.getpass("Enter password: ")
        result, iters = attempt_password(payload, version, pw)
        if result:
            print(f"\n*** SUCCESS (iterations={iters}) ***")
            show_decrypted(result, target)
            return True
        else:
            print("\nWrong password (or wallet format unsupported).")
            return False


def main():
    parser = argparse.ArgumentParser(
        description="Decrypt Blockchain.com wallet.aes.json backup",
    )
    parser.add_argument(
        "wallet_files",
        nargs='+',
        help="Path(s) to wallet.aes.json file(s) - can specify multiple",
    )
    parser.add_argument(
        "--candidates",
        help="File with one password candidate per line",
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Target address to check for (default: {DEFAULT_TARGET})",
    )
    args = parser.parse_args()

    candidates = None
    if args.candidates:
        cand_path = Path(args.candidates)
        if not cand_path.exists():
            print(f"Candidates file not found: {cand_path}")
            sys.exit(1)
        with open(cand_path) as f:
            candidates = [line.rstrip("\n") for line in f if line.strip()]
        print(f"Loaded {len(candidates)} password candidates")

    print(f"Target address: {args.target}")
    print(f"Will process {len(args.wallet_files)} wallet file(s)\n")

    successes = 0
    for wf in args.wallet_files:
        wallet_path = Path(wf)
        if not wallet_path.exists():
            print(f"\nSkipping (not found): {wallet_path}")
            continue
        if process_wallet(wallet_path, candidates, args.target):
            successes += 1

    print(f"\n\n{'='*70}")
    print(f"DONE. Successfully decrypted {successes}/{len(args.wallet_files)} wallet(s).")


if __name__ == "__main__":
    main()
