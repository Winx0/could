#!/usr/bin/env python3
"""
Bitcoin Wallet Recovery - Address Finder
=========================================
Validates whether a given seed phrase, private key, or master key produces
the target Bitcoin address `1B8hgFxNK7ac2k5EtrAanxQPFcnfHLMcko`.

Tries ALL common derivation paths used by:
  - Blockchain.com (BIP44 Legacy)
  - Trust Wallet (BIP44/49/84)
  - Electrum (BIP32 m/0)
  - Bitcoin Core (legacy)
  - And many other wallets.

USAGE:
  python address_finder.py
  Then follow the interactive prompts.

SECURITY:
  - Run this ONLY on your local computer
  - Disconnect from internet for max safety
  - NEVER share output containing your seed/key with anyone
"""

import sys
import hashlib
from typing import List, Optional

TARGET_ADDRESS = "1B8hgFxNK7ac2k5EtrAanxQPFcnfHLMcko"

try:
    from bip_utils import (
        Bip39SeedGenerator, Bip39MnemonicValidator, Bip39Languages,
        Bip44, Bip44Coins, Bip44Changes,
        Bip49, Bip49Coins,
        Bip84, Bip84Coins,
        Bip32Slip10Secp256k1,
        WifDecoder, WifEncoder,
        P2PKHAddrEncoder, P2SHAddrEncoder, P2WPKHAddrEncoder,
        Secp256k1PrivateKey, Secp256k1PublicKey,
    )
except ImportError:
    print("ERROR: Library 'bip_utils' tidak terinstall.")
    print("Install dulu: pip install bip_utils mnemonic")
    sys.exit(1)


# ============================================================================
# DERIVATION PATHS to try
# ============================================================================

# Format: (label, address_count_to_try, change_branch)
# We try first 50 addresses on receive (0/x) and change (1/x) branch
ADDRESS_GAP = 50


def addresses_from_seed(seed_bytes: bytes, max_idx: int = ADDRESS_GAP) -> List[tuple]:
    """
    Generate all addresses from a seed using common wallet derivation paths.
    Returns list of (path_label, address) tuples.
    """
    results = []

    # ---- BIP44 Legacy P2PKH (1...) - Blockchain.com, Bitcoin Core, default Trust Wallet legacy ----
    try:
        bip44_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
        for change in (Bip44Changes.CHAIN_EXT, Bip44Changes.CHAIN_INT):
            change_label = "ext" if change == Bip44Changes.CHAIN_EXT else "int"
            for i in range(max_idx):
                acct = bip44_ctx.Purpose().Coin().Account(0).Change(change).AddressIndex(i)
                addr = acct.PublicKey().ToAddress()
                path = f"m/44'/0'/0'/{0 if change == Bip44Changes.CHAIN_EXT else 1}/{i}"
                results.append((f"BIP44 Legacy [{path}]", addr))
    except Exception as e:
        results.append((f"BIP44 ERROR: {e}", ""))

    # ---- BIP49 P2SH-SegWit (3...) - Trust Wallet, Ledger ----
    try:
        bip49_ctx = Bip49.FromSeed(seed_bytes, Bip49Coins.BITCOIN)
        for change in (Bip44Changes.CHAIN_EXT, Bip44Changes.CHAIN_INT):
            for i in range(max_idx):
                acct = bip49_ctx.Purpose().Coin().Account(0).Change(change).AddressIndex(i)
                addr = acct.PublicKey().ToAddress()
                path = f"m/49'/0'/0'/{0 if change == Bip44Changes.CHAIN_EXT else 1}/{i}"
                results.append((f"BIP49 P2SH-SegWit [{path}]", addr))
    except Exception as e:
        results.append((f"BIP49 ERROR: {e}", ""))

    # ---- BIP84 Native SegWit (bc1q...) - modern Trust Wallet, Electrum ----
    try:
        bip84_ctx = Bip84.FromSeed(seed_bytes, Bip84Coins.BITCOIN)
        for change in (Bip44Changes.CHAIN_EXT, Bip44Changes.CHAIN_INT):
            for i in range(max_idx):
                acct = bip84_ctx.Purpose().Coin().Account(0).Change(change).AddressIndex(i)
                addr = acct.PublicKey().ToAddress()
                path = f"m/84'/0'/0'/{0 if change == Bip44Changes.CHAIN_EXT else 1}/{i}"
                results.append((f"BIP84 Native SegWit [{path}]", addr))
    except Exception as e:
        results.append((f"BIP84 ERROR: {e}", ""))

    # ---- Electrum-style m/0/x (legacy Electrum 2.x with BIP39) ----
    try:
        bip32_ctx = Bip32Slip10Secp256k1.FromSeed(seed_bytes)
        for branch in (0, 1):
            for i in range(max_idx):
                node = bip32_ctx.DerivePath(f"m/{branch}/{i}")
                pubkey_bytes = node.PublicKey().RawCompressed().ToBytes()
                addr = P2PKHAddrEncoder.EncodeKey(
                    Secp256k1PublicKey.FromBytes(pubkey_bytes),
                    net_ver=b'\x00',
                )
                results.append((f"Electrum-legacy [m/{branch}/{i}]", addr))
    except Exception as e:
        results.append((f"Electrum-legacy ERROR: {e}", ""))

    return results


def check_seed_phrase(mnemonic: str, passphrase: str = "") -> Optional[tuple]:
    """
    Check if mnemonic produces target address. Returns (path, address) on hit.
    """
    mnemonic = " ".join(mnemonic.lower().strip().split())

    # Validate first
    try:
        if not Bip39MnemonicValidator(Bip39Languages.ENGLISH).IsValid(mnemonic):
            return ("INVALID_MNEMONIC", None)
    except Exception:
        return ("INVALID_MNEMONIC", None)

    seed = Bip39SeedGenerator(mnemonic).Generate(passphrase)
    addrs = addresses_from_seed(seed)

    for path, addr in addrs:
        if addr == TARGET_ADDRESS:
            return (path, addr)
    return None


def check_private_key_wif(wif: str) -> Optional[str]:
    """Check if WIF private key produces target address (any format)."""
    try:
        priv_bytes, _ = WifDecoder.Decode(wif)
        priv = Secp256k1PrivateKey.FromBytes(priv_bytes)
        pub = priv.PublicKey()

        # P2PKH
        addr_p2pkh = P2PKHAddrEncoder.EncodeKey(pub, net_ver=b'\x00')
        if addr_p2pkh == TARGET_ADDRESS:
            return f"P2PKH (Legacy)"

        # P2SH-P2WPKH (need to compute)
        # P2WPKH (Native SegWit)
        addr_p2wpkh = P2WPKHAddrEncoder.EncodeKey(pub, hrp='bc', wit_ver=0)
        if addr_p2wpkh == TARGET_ADDRESS:
            return f"P2WPKH (Native SegWit)"
    except Exception as e:
        return f"INVALID_WIF: {e}"
    return None


def check_private_key_hex(hex_key: str) -> Optional[str]:
    """Check if raw hex private key produces target address."""
    try:
        hex_key = hex_key.strip().replace("0x", "")
        priv_bytes = bytes.fromhex(hex_key)
        if len(priv_bytes) != 32:
            return f"INVALID_LENGTH: must be 32 bytes (64 hex chars), got {len(priv_bytes)}"

        priv = Secp256k1PrivateKey.FromBytes(priv_bytes)
        pub = priv.PublicKey()
        addr = P2PKHAddrEncoder.EncodeKey(pub, net_ver=b'\x00')
        if addr == TARGET_ADDRESS:
            return "P2PKH match!"
        return None
    except Exception as e:
        return f"ERROR: {e}"


# ============================================================================
# INTERACTIVE MENU
# ============================================================================

def main():
    print("=" * 70)
    print("  BITCOIN WALLET RECOVERY - Address Finder")
    print(f"  Target Address: {TARGET_ADDRESS}")
    print("=" * 70)
    print()
    print("Pilih metode recovery:")
    print("  1. Saya punya 12-kata seed phrase (BIP39)")
    print("  2. Saya punya 12-kata seed phrase tapi LUPA 1 KATA")
    print("  3. Saya punya private key (WIF format: starts with 5/K/L)")
    print("  4. Saya punya private key (hex format: 64 hex chars)")
    print("  5. Cek apakah saya punya 'fragmen' kata yang benar")
    print("  0. Keluar")
    print()

    choice = input("Pilihan [0-5]: ").strip()

    if choice == "1":
        recovery_full_seed()
    elif choice == "2":
        recovery_missing_one_word()
    elif choice == "3":
        recovery_wif()
    elif choice == "4":
        recovery_hex()
    elif choice == "5":
        recovery_check_words()
    else:
        print("Bye!")


def recovery_full_seed():
    print("\n--- Mode: Seed Phrase Lengkap ---")
    print("Input 12 kata seed phrase Anda (dipisah spasi):")
    mnemonic = input("> ").strip()
    passphrase = input("Passphrase BIP39 (kosongkan kalau tidak ada): ").strip()

    print("\nChecking semua derivation paths (BIP44/49/84 + Electrum)...")
    result = check_seed_phrase(mnemonic, passphrase)

    if result is None:
        print("\nX  Seed phrase TIDAK menghasilkan address target.")
        print("   Coba: passphrase berbeda? typo? atau seed phrase salah.")
    elif result[0] == "INVALID_MNEMONIC":
        print("\nX  Seed phrase TIDAK VALID (gagal checksum BIP39).")
        print("   Pastikan urutan kata benar dan tidak ada typo.")
    else:
        path, addr = result
        print(f"\n✓✓✓ MATCH FOUND! ✓✓✓")
        print(f"   Path: {path}")
        print(f"   Address: {addr}")
        print(f"\n   Anda bisa import seed phrase ini ke Electrum/Sparrow")
        print(f"   dengan derivation path tsb untuk akses dana.")


def recovery_missing_one_word():
    print("\n--- Mode: Lupa 1 Kata dari 12 ---")
    print("Tulis 12 kata, ganti yang lupa dengan tanda '?'")
    print("Contoh: abandon ability ? ... about absorb")
    mnemonic = input("> ").strip().lower().split()

    if len(mnemonic) != 12:
        print(f"X  Harus tepat 12 kata. Anda input {len(mnemonic)} kata.")
        return

    if mnemonic.count("?") != 1:
        print("X  Harus tepat 1 tanda '?' untuk kata yang lupa.")
        return

    miss_idx = mnemonic.index("?")
    passphrase = input("Passphrase BIP39 (kosongkan kalau tidak ada): ").strip()

    # Load BIP39 wordlist
    from mnemonic import Mnemonic
    wordlist = Mnemonic("english").wordlist

    print(f"\nMencoba 2048 kata BIP39 di posisi {miss_idx + 1}...")
    found = False
    for i, word in enumerate(wordlist):
        candidate = mnemonic.copy()
        candidate[miss_idx] = word
        try:
            result = check_seed_phrase(" ".join(candidate), passphrase)
            if result and result[0] not in ("INVALID_MNEMONIC",):
                path, addr = result
                if addr == TARGET_ADDRESS:
                    print(f"\n✓✓✓ MATCH! Kata yang hilang: '{word}'")
                    print(f"   Path: {path}")
                    print(f"   Seed: {' '.join(candidate)}")
                    found = True
                    break
        except Exception:
            pass
        if (i + 1) % 256 == 0:
            print(f"  ... checked {i+1}/2048 words")

    if not found:
        print("\nX  Tidak ada kata yang cocok. Mungkin lupa lebih dari 1 kata,")
        print("   atau ada typo di kata lain, atau passphrase salah.")


def recovery_wif():
    print("\n--- Mode: WIF Private Key ---")
    print("Format WIF biasanya mulai dengan: 5 (uncompressed) atau K/L (compressed)")
    wif = input("Paste WIF: ").strip()
    result = check_private_key_wif(wif)
    if result and "INVALID" not in result:
        print(f"\n✓✓✓ MATCH! Type: {result}")
    else:
        print(f"\nX  Tidak match. Detail: {result}")


def recovery_hex():
    print("\n--- Mode: Hex Private Key ---")
    print("Paste 64 hex chars (32 bytes):")
    hex_key = input("> ").strip()
    result = check_private_key_hex(hex_key)
    if result == "P2PKH match!":
        print(f"\n✓✓✓ MATCH!")
    else:
        print(f"\nX  Result: {result}")


def recovery_check_words():
    print("\n--- Mode: Cek Fragmen Kata ---")
    print("Masukkan kata-kata yang Anda ingat (urutan tidak penting),")
    print("dipisah spasi atau koma:")
    raw = input("> ").strip().lower().replace(",", " ")
    user_words = raw.split()

    from mnemonic import Mnemonic
    wordlist = set(Mnemonic("english").wordlist)

    valid = [w for w in user_words if w in wordlist]
    invalid = [w for w in user_words if w not in wordlist]

    print(f"\n  Kata valid BIP39 ({len(valid)}): {valid}")
    if invalid:
        print(f"  Kata TIDAK ada di BIP39 ({len(invalid)}): {invalid}")
        print("  ^ Mungkin typo atau bukan BIP39 standard?")

    if len(valid) >= 11:
        print("\n  >> Anda hampir lengkap! Pakai mode 2 (lupa 1 kata) untuk brute-force")
    elif len(valid) >= 8:
        print(f"\n  >> Anda perlu cari {12 - len(valid)} kata lagi.")
        print("     Brute-force {12-len(valid)} kata terlalu lama (>2048^missing)")
    else:
        print(f"\n  >> Hanya {len(valid)} kata yang valid. Recovery brute-force tidak feasible.")


if __name__ == "__main__":
    main()
