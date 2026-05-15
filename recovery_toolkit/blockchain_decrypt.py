#!/usr/bin/env python3
"""
Bitcoin Wallet Recovery - Blockchain.com Wallet Decryptor
==========================================================
Decrypts a `wallet.aes.json` backup file from Blockchain.com.

If you have your password (or remember PARTIALLY), this script can:
  1. Decrypt with the exact password.
  2. Try a list of password candidates (e.g. variations you might have used).

USAGE:
  python blockchain_decrypt.py wallet.aes.json
  python blockchain_decrypt.py wallet.aes.json --candidates passwords.txt

After decryption, you'll see all addresses + private keys (or the seed phrase).

SECURITY:
  - Run on YOUR OWN OFFLINE computer
  - Output contains private keys in plain text - HANDLE WITH CARE
  - Never run on shared/cloud machine

Background:
  Blockchain.com uses AES-256-CBC with PBKDF2 (10,000 - 5,000 iterations
  depending on version). Wrapped in a JSON envelope.
"""

import argparse
import base64
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
    Returns plaintext on success, None on failure.
    """
    iter_options = []
    if version == 1:
        iter_options = [10]
    elif version == 2:
        iter_options = [1000]
    elif version == 3:
        iter_options = [5000]
    else:
        # Unknown - try common values
        iter_options = [5000, 10000, 1000, 10]

    for it in iter_options:
        try:
            return try_decrypt(payload_b64, password, it), it
        except Exception:
            continue
    return None, None


def main():
    parser = argparse.ArgumentParser(
        description="Decrypt Blockchain.com wallet.aes.json backup",
    )
    parser.add_argument("wallet_file", help="Path to wallet.aes.json")
    parser.add_argument(
        "--candidates",
        help="Optional: file with one password candidate per line",
    )
    args = parser.parse_args()

    wallet_path = Path(args.wallet_file)
    if not wallet_path.exists():
        print(f"File not found: {wallet_path}")
        sys.exit(1)

    with open(wallet_path) as f:
        envelope = json.load(f)

    payload = envelope.get("payload")
    version = envelope.get("version", 0)
    if not payload:
        print("Format wallet.aes.json tidak valid (missing 'payload')")
        sys.exit(1)

    print(f"Wallet version: {version}")
    print(f"Payload length: {len(payload)} chars")
    print()

    if args.candidates:
        cand_path = Path(args.candidates)
        if not cand_path.exists():
            print(f"Candidates file not found: {cand_path}")
            sys.exit(1)
        with open(cand_path) as f:
            candidates = [line.rstrip("\n") for line in f if line.strip()]
        print(f"Trying {len(candidates)} password candidates...")
        for i, pw in enumerate(candidates, 1):
            if i % 50 == 0:
                print(f"  ... {i}/{len(candidates)} tried")
            result, iters = attempt_password(payload, version, pw)
            if result:
                print(f"\n*** PASSWORD FOUND: '{pw}' (iterations={iters}) ***")
                show_decrypted(result)
                return
        print("\nNo password from candidates worked.")
    else:
        pw = input("Enter password (input is masked): ")
        result, iters = attempt_password(payload, version, pw)
        if result:
            print(f"\n*** SUCCESS (iterations={iters}) ***")
            show_decrypted(result)
        else:
            print("\nWrong password (or wallet format unsupported).")
            print("Tip: try using --candidates with a list of likely passwords.")


def show_decrypted(plaintext: str):
    """Pretty-print the decrypted wallet content with sensitive parts masked."""
    data = json.loads(plaintext)
    print("\n=== DECRYPTED WALLET CONTENT ===")
    print("(Save this output to a SECURE file. Keys/seed are in PLAIN TEXT)")
    print()

    # Hierarchical Deterministic wallets
    hdws = data.get("hd_wallets", [])
    for w in hdws:
        seed_hex = w.get("seed_hex")
        mnemonic = w.get("mnemonic_verified") or w.get("mnemonic")
        if seed_hex:
            print(f"HD seed (hex): {seed_hex}")
        if mnemonic:
            print(f"HD mnemonic: {mnemonic}")

    # Imported / legacy keys
    keys = data.get("keys", [])
    print(f"\nImported keys: {len(keys)}")
    for k in keys[:50]:  # cap output
        addr = k.get("addr", "?")
        priv = k.get("priv", "?")
        label = k.get("label", "")
        print(f"  {addr}  |  priv: {priv}  | label: {label}")

    # Addresses (some versions)
    addresses = data.get("addresses", [])
    if addresses:
        print(f"\nAddresses entries: {len(addresses)}")
        for a in addresses[:50]:
            print(f"  {a}")

    # Save full JSON
    out = Path("decrypted_wallet.json")
    out.write_text(plaintext)
    print(f"\nFull decrypted JSON saved to: {out.resolve()}")
    print("REMEMBER: Delete this file after extracting your keys!")


if __name__ == "__main__":
    main()
