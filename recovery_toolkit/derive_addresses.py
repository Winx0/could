#!/usr/bin/env python3
"""
Bitcoin Wallet Recovery - Derive Addresses from Seed Phrase
============================================================
Derives a wide range of addresses from a BIP39 seed phrase across
multiple derivation paths used by common wallets.

Output: a text file with addresses (one per line) that can be fed to
check_balances.py to find which addresses actually have BTC.

USAGE:
  python derive_addresses.py
  Then paste seed phrase when prompted (input hidden).

OUTPUT:
  derived_addresses.txt - all derived addresses
  Then feed to: python check_balances.py derived_addresses.txt

DERIVATION PATHS COVERED:
  - BIP44 m/44'/0'/0'/0..1/0..N    (Legacy 1...) - Trust Wallet, Bitcoin Core HD, Exodus
  - BIP49 m/49'/0'/0'/0..1/0..N    (P2SH 3...) - Trust Wallet
  - BIP84 m/84'/0'/0'/0..1/0..N    (Native SegWit bc1q...) - Modern wallets
  - BIP86 m/86'/0'/0'/0..1/0..N    (Taproot bc1p...) - Newer Sparrow/Bitcoin Core
  - Electrum m/0..1/0..N           (Electrum 2.x)
  - BIP44 multi-account m/44'/0'/0..4'/...

SECURITY:
  - Run on YOUR OWN computer
  - Seed phrase input is hidden
  - Seed phrase is NEVER written to disk by this tool
  - Output file contains only PUBLIC addresses (safe to share)
"""

import argparse
import getpass
import sys
from pathlib import Path

try:
    from bip_utils import (
        Bip39SeedGenerator, Bip39MnemonicValidator, Bip39Languages,
        Bip44, Bip44Coins, Bip44Changes,
        Bip49, Bip49Coins,
        Bip84, Bip84Coins,
        Bip86, Bip86Coins,
        Bip32Slip10Secp256k1,
        Secp256k1PublicKey,
        P2PKHAddrEncoder,
    )
except ImportError:
    print("ERROR: Library 'bip_utils' tidak terinstall.")
    print("Install dulu: pip install bip_utils mnemonic")
    sys.exit(1)


def derive_all(mnemonic, passphrase, gap_limit=50, num_accounts=3):
    """
    Derive addresses across many paths and accounts.
    Returns dict: { 'path_label': [addresses, ...] }
    """
    seed = Bip39SeedGenerator(mnemonic).Generate(passphrase)
    results = {}

    # ========== BIP44 (Legacy) ==========
    for acct in range(num_accounts):
        for change in (Bip44Changes.CHAIN_EXT, Bip44Changes.CHAIN_INT):
            change_str = '0' if change == Bip44Changes.CHAIN_EXT else '1'
            label = f"BIP44 m/44'/0'/{acct}'/{change_str}"
            addrs = []
            try:
                ctx = Bip44.FromSeed(seed, Bip44Coins.BITCOIN)
                acct_ctx = ctx.Purpose().Coin().Account(acct).Change(change)
                for i in range(gap_limit):
                    addrs.append(acct_ctx.AddressIndex(i).PublicKey().ToAddress())
            except Exception:
                pass
            if addrs:
                results[label] = addrs

    # ========== BIP49 (P2SH-SegWit) ==========
    for acct in range(num_accounts):
        for change in (Bip44Changes.CHAIN_EXT, Bip44Changes.CHAIN_INT):
            change_str = '0' if change == Bip44Changes.CHAIN_EXT else '1'
            label = f"BIP49 m/49'/0'/{acct}'/{change_str}"
            addrs = []
            try:
                ctx = Bip49.FromSeed(seed, Bip49Coins.BITCOIN)
                acct_ctx = ctx.Purpose().Coin().Account(acct).Change(change)
                for i in range(gap_limit):
                    addrs.append(acct_ctx.AddressIndex(i).PublicKey().ToAddress())
            except Exception:
                pass
            if addrs:
                results[label] = addrs

    # ========== BIP84 (Native SegWit) ==========
    for acct in range(num_accounts):
        for change in (Bip44Changes.CHAIN_EXT, Bip44Changes.CHAIN_INT):
            change_str = '0' if change == Bip44Changes.CHAIN_EXT else '1'
            label = f"BIP84 m/84'/0'/{acct}'/{change_str}"
            addrs = []
            try:
                ctx = Bip84.FromSeed(seed, Bip84Coins.BITCOIN)
                acct_ctx = ctx.Purpose().Coin().Account(acct).Change(change)
                for i in range(gap_limit):
                    addrs.append(acct_ctx.AddressIndex(i).PublicKey().ToAddress())
            except Exception:
                pass
            if addrs:
                results[label] = addrs

    # ========== BIP86 (Taproot) ==========
    for acct in range(num_accounts):
        for change in (Bip44Changes.CHAIN_EXT, Bip44Changes.CHAIN_INT):
            change_str = '0' if change == Bip44Changes.CHAIN_EXT else '1'
            label = f"BIP86 m/86'/0'/{acct}'/{change_str} (Taproot)"
            addrs = []
            try:
                ctx = Bip86.FromSeed(seed, Bip86Coins.BITCOIN)
                acct_ctx = ctx.Purpose().Coin().Account(acct).Change(change)
                for i in range(gap_limit):
                    addrs.append(acct_ctx.AddressIndex(i).PublicKey().ToAddress())
            except Exception:
                pass
            if addrs:
                results[label] = addrs

    # ========== Electrum 2.x style m/0/x ==========
    for branch in (0, 1):
        label = f"Electrum-2.x m/{branch}"
        addrs = []
        try:
            ctx = Bip32Slip10Secp256k1.FromSeed(seed)
            for i in range(gap_limit):
                node = ctx.DerivePath(f"m/{branch}/{i}")
                pubkey_bytes = node.PublicKey().RawCompressed().ToBytes()
                addr = P2PKHAddrEncoder.EncodeKey(
                    Secp256k1PublicKey.FromBytes(pubkey_bytes),
                    net_ver=b'\x00',
                )
                addrs.append(addr)
        except Exception:
            pass
        if addrs:
            results[label] = addrs

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Derive Bitcoin addresses from a BIP39 seed phrase",
    )
    parser.add_argument("--gap", type=int, default=50,
                        help="Number of indexes per branch (default: 50)")
    parser.add_argument("--accounts", type=int, default=3,
                        help="Number of accounts to derive (default: 3)")
    parser.add_argument("--output", default="derived_addresses.txt",
                        help="Output file for addresses")
    args = parser.parse_args()

    print("=" * 70)
    print("  DERIVE ADDRESSES FROM SEED PHRASE")
    print("=" * 70)
    print()
    print("This tool derives ALL standard wallet addresses from your seed")
    print("so you can check which ones contain BTC.")
    print()
    print("Your seed phrase is NEVER saved to disk by this tool.")
    print()

    print("Paste your 12 or 24 word seed phrase (input is hidden):")
    try:
        mnemonic = getpass.getpass("Seed phrase: ").strip()
    except Exception:
        mnemonic = input("Seed phrase: ").strip()

    mnemonic = " ".join(mnemonic.lower().split())
    word_count = len(mnemonic.split())
    if word_count not in (12, 15, 18, 21, 24):
        print(f"ERROR: Word count is {word_count}. Must be 12, 15, 18, 21, or 24.")
        sys.exit(1)

    if not Bip39MnemonicValidator(Bip39Languages.ENGLISH).IsValid(mnemonic):
        print("ERROR: Seed phrase is not a valid BIP39 mnemonic.")
        print("Possible issues: typo, wrong word, or different language.")
        sys.exit(1)

    print("Seed phrase is valid BIP39")

    try:
        passphrase = getpass.getpass("BIP39 passphrase (Enter if none): ").strip()
    except Exception:
        passphrase = ""

    print()
    print(f"Deriving addresses ({args.gap} per branch, {args.accounts} accounts)...")
    results = derive_all(mnemonic, passphrase, args.gap, args.accounts)

    total = sum(len(v) for v in results.values())
    print(f"Derived {total} addresses across {len(results)} paths")
    print()

    out_path = Path(args.output)
    seen = set()
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(f"# Derived addresses for seed phrase (NOT included for security)\n")
        f.write(f"# Total paths: {len(results)}, total addresses: {total}\n\n")
        for path_label, addrs in results.items():
            f.write(f"# Path: {path_label}\n")
            for addr in addrs:
                if addr not in seen:
                    seen.add(addr)
                    f.write(f"{addr}\n")
            f.write("\n")

    print(f"Saved {len(seen)} unique addresses to: {out_path.resolve()}")
    print()
    print("Next step: check balances")
    print(f"  python check_balances.py {args.output}")
    print()
    print("REMEMBER: Delete this output file after recovery is complete.")


if __name__ == "__main__":
    main()
