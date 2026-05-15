#!/usr/bin/env python3
"""
Bitcoin Wallet Recovery - wallet.dat Inspector v2
==================================================
Extracts addresses + records from a Bitcoin Core wallet.dat file
WITHOUT requiring the password.

Supports BOTH BDB Hash AND BDB BTree formats (Bitcoin Core uses BTree).
Uses raw byte pattern scanning to find wallet records regardless of
the underlying BDB structure - more robust than struct-aware parsers.

This is a SAFE READ-ONLY operation - it only reads the file structure.

It tells you:
  1. Whether wallet.dat contains the TARGET address (1B8hg...LMcko)
  2. List of all addresses present in the wallet
  3. Whether the wallet is encrypted (has master key) or not
  4. Wallet metadata if available

USAGE:
  python wallet_dat_inspect.py path/to/wallet.dat
  python wallet_dat_inspect.py "E:\\DATA DARI DOWNLOAD\\wallet.dat"

SECURITY:
  - Run on YOUR OWN computer
  - Read-only operation, doesn't modify wallet.dat
  - Does NOT extract decryption keys (that requires password)
"""

import argparse
import hashlib
import re
import struct
import sys
from pathlib import Path

TARGET_ADDRESS = "1B8hgFxNK7ac2k5EtrAanxQPFcnfHLMcko"

# ============================================================================
# Address utilities
# ============================================================================

BASE58_ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def base58_encode(data):
    """Standard Base58Check encoding."""
    n = int.from_bytes(data, 'big')
    encoded = b''
    while n > 0:
        n, r = divmod(n, 58)
        encoded = BASE58_ALPHABET[r:r+1] + encoded
    for byte in data:
        if byte == 0:
            encoded = b'1' + encoded
        else:
            break
    return encoded.decode('ascii')


def hash160_to_p2pkh(hash160):
    versioned = b'\x00' + hash160
    checksum = hashlib.sha256(hashlib.sha256(versioned).digest()).digest()[:4]
    return base58_encode(versioned + checksum)


def hash160_to_p2sh(hash160):
    versioned = b'\x05' + hash160
    checksum = hashlib.sha256(hashlib.sha256(versioned).digest()).digest()[:4]
    return base58_encode(versioned + checksum)


def pubkey_to_p2pkh(pubkey_bytes):
    sha = hashlib.sha256(pubkey_bytes).digest()
    h160 = hashlib.new('ripemd160', sha).digest()
    return hash160_to_p2pkh(h160)


# Validation regex for Bitcoin legacy/p2sh addresses
ADDR_REGEX = re.compile(r'^[13][1-9A-HJ-NP-Za-km-z]{25,33}$')


def is_valid_btc_address(s):
    if not isinstance(s, str):
        return False
    if not ADDR_REGEX.match(s):
        return False
    try:
        n = 0
        for c in s.encode():
            idx = BASE58_ALPHABET.find(c)
            if idx < 0:
                return False
            n = n * 58 + idx
        b = n.to_bytes(25, 'big')
        leading_zeros = 0
        for c in s:
            if c == '1':
                leading_zeros += 1
            else:
                break
        b = b'\x00' * leading_zeros + b[leading_zeros:]
        if len(b) != 25:
            return False
        payload, checksum = b[:21], b[21:]
        expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        return expected == checksum
    except Exception:
        return False


# ============================================================================
# RAW BYTE SCANNER - works for both BDB Hash and BTree
# ============================================================================

def scan_wallet_records(data):
    """Scan raw wallet.dat bytes for known Bitcoin Core record patterns."""
    results = {
        'name_records': {},
        'purpose_records': {},
        'addresses_from_pubkey': set(),
        'ckey_count': 0,
        'key_count': 0,
        'mkey_count': 0,
        'tx_count': 0,
        'pool_count': 0,
        'hdchain_count': 0,
        'master_keys': [],
        'all_addresses': set(),
    }

    # Pattern: "name" record  -> 0x04 "name" <addr_len_byte> <address ASCII> <label_len> <label>
    pattern_name = re.compile(rb'\x04name([\x21-\x25])([13][1-9A-HJ-NP-Za-km-z]{25,33})')
    for m in pattern_name.finditer(data):
        addr_len_byte = m.group(1)[0]
        addr_bytes = m.group(2)
        addr = addr_bytes.decode('ascii', errors='ignore')
        if abs(addr_len_byte - len(addr)) > 5:
            continue
        if not is_valid_btc_address(addr):
            continue
        label_start = m.end()
        label = ''
        if label_start < len(data):
            label_len = data[label_start]
            if 0 < label_len < 100:
                label_bytes = data[label_start + 1:label_start + 1 + label_len]
                try:
                    candidate = label_bytes.decode('utf-8', errors='replace')
                    if all(32 <= ord(c) < 127 or c in '\n\t' for c in candidate[:50]):
                        label = candidate
                except Exception:
                    pass
        results['name_records'][addr] = label
        results['all_addresses'].add(addr)

    # Pattern: "purpose"
    pattern_purpose = re.compile(rb'\x07purpose([\x21-\x25])([13][1-9A-HJ-NP-Za-km-z]{25,33})')
    for m in pattern_purpose.finditer(data):
        addr = m.group(2).decode('ascii', errors='ignore')
        if not is_valid_btc_address(addr):
            continue
        purp_start = m.end()
        if purp_start < len(data):
            plen = data[purp_start]
            if 0 < plen < 30:
                purp = data[purp_start + 1:purp_start + 1 + plen].decode('ascii', errors='ignore')
                if purp.isalnum() or purp in ('send', 'receive', 'change'):
                    results['purpose_records'][addr] = purp
        results['all_addresses'].add(addr)

    # Pattern: "ckey" - encrypted private key
    pattern_ckey_compressed = re.compile(rb'\x04ckey\x21([\x02\x03][\x00-\xff]{32})', re.DOTALL)
    for m in pattern_ckey_compressed.finditer(data):
        pubkey = m.group(1)
        addr = pubkey_to_p2pkh(pubkey)
        results['addresses_from_pubkey'].add(addr)
        results['all_addresses'].add(addr)
        results['ckey_count'] += 1

    pattern_ckey_uncompressed = re.compile(rb'\x04ckey\x41(\x04[\x00-\xff]{64})', re.DOTALL)
    for m in pattern_ckey_uncompressed.finditer(data):
        pubkey = m.group(1)
        addr = pubkey_to_p2pkh(pubkey)
        results['addresses_from_pubkey'].add(addr)
        results['all_addresses'].add(addr)
        results['ckey_count'] += 1

    # Pattern: "key" - unencrypted private key
    pattern_key_compressed = re.compile(rb'\x03key\x21([\x02\x03][\x00-\xff]{32})', re.DOTALL)
    for m in pattern_key_compressed.finditer(data):
        pubkey = m.group(1)
        addr = pubkey_to_p2pkh(pubkey)
        results['addresses_from_pubkey'].add(addr)
        results['all_addresses'].add(addr)
        results['key_count'] += 1

    pattern_key_uncompressed = re.compile(rb'\x03key\x41(\x04[\x00-\xff]{64})', re.DOTALL)
    for m in pattern_key_uncompressed.finditer(data):
        pubkey = m.group(1)
        addr = pubkey_to_p2pkh(pubkey)
        results['addresses_from_pubkey'].add(addr)
        results['all_addresses'].add(addr)
        results['key_count'] += 1

    # Pattern: "mkey" - master encryption key
    pattern_mkey = re.compile(rb'\x04mkey')
    for m in pattern_mkey.finditer(data):
        pos = m.start()
        offset = pos + 5  # skip "\x04mkey"
        offset += 1  # skip 1-byte ID
        if offset + 100 > len(data):
            continue
        try:
            ckey_len = data[offset]
            if ckey_len != 48:
                continue
            crypted_key = data[offset + 1:offset + 1 + ckey_len]
            offset += 1 + ckey_len
            salt_len = data[offset]
            if salt_len not in (8, 16):
                continue
            salt = data[offset + 1:offset + 1 + salt_len]
            offset += 1 + salt_len
            method = struct.unpack('<I', data[offset:offset+4])[0]
            iters = struct.unpack('<I', data[offset+4:offset+8])[0]
            if iters < 100 or iters > 10000000:
                continue
            results['master_keys'].append({
                'salt': salt.hex(),
                'method': method,
                'iterations': iters,
                'encrypted_master_key_preview': crypted_key.hex()[:32] + '...',
            })
            results['mkey_count'] += 1
        except Exception:
            continue

    # Pattern: "pool"
    results['pool_count'] = len(re.findall(rb'\x04pool', data))

    # Pattern: "tx" record
    results['tx_count'] = len(re.findall(rb'\x02tx[\x00-\xff]{32}', data, re.DOTALL))

    # Pattern: "hdchain"
    results['hdchain_count'] = len(re.findall(rb'\x07hdchain', data))

    # Pattern: All valid Bitcoin addresses anywhere
    catchall = re.compile(rb'[13][1-9A-HJ-NP-Za-km-z]{25,33}')
    for m in catchall.finditer(data):
        candidate = m.group(0).decode('ascii', errors='ignore')
        if is_valid_btc_address(candidate):
            results['all_addresses'].add(candidate)

    return results


# ============================================================================
# MAIN
# ============================================================================

def detect_format(data):
    """Detect BDB format by reading magic number at offset 12."""
    if len(data) < 16:
        return ("Unknown (file too small)", None)
    magic_le = struct.unpack('<I', data[12:16])[0]
    magic_be = struct.unpack('>I', data[12:16])[0]
    formats = {
        0x00061561: 'BDB Hash (legacy Bitcoin Core)',
        0x00053162: 'BDB BTree (modern Bitcoin Core)',
        0x00042253: 'BDB Recno',
        0x00042254: 'BDB Queue',
    }
    if magic_le in formats:
        return (formats[magic_le], magic_le)
    if magic_be in formats:
        return (formats[magic_be] + ' (big-endian)', magic_be)
    return (f'Unknown (magic_le={magic_le:#x}, magic_be={magic_be:#x})', None)


def analyze(filepath):
    print(f"Reading: {filepath}")
    with open(filepath, 'rb') as f:
        data = f.read()
    print(f"File size: {len(data):,} bytes")

    fmt, magic = detect_format(data)
    print(f"BDB Format: {fmt}")
    print()

    print("Scanning for wallet records (raw byte pattern matching)...")
    results = scan_wallet_records(data)

    print()
    print("=" * 70)
    print("WALLET ANALYSIS REPORT")
    print("=" * 70)
    encrypted = results['mkey_count'] > 0 or results['ckey_count'] > 0
    print(f"Encrypted: {'YES' if encrypted else 'NO'}")
    print(f"Master keys found (mkey): {results['mkey_count']}")
    print(f"Encrypted private keys (ckey): {results['ckey_count']}")
    print(f"Unencrypted private keys (key): {results['key_count']}")
    print(f"Address labels (name): {len(results['name_records'])}")
    print(f"Address purposes: {len(results['purpose_records'])}")
    print(f"Pool keys (pre-generated): {results['pool_count']}")
    print(f"Transactions (tx): {results['tx_count']}")
    print(f"HD chain records: {results['hdchain_count']}")
    print(f"Total unique addresses found: {len(results['all_addresses'])}")
    print()

    if results['master_keys']:
        print("MASTER KEY DETAILS (for password recovery):")
        for i, mk in enumerate(results['master_keys']):
            print(f"  Master key #{i + 1}:")
            print(f"    Method: {mk['method']} (0=AES-256-CBC default)")
            print(f"    Iterations: {mk['iterations']:,}")
            print(f"    Salt (hex): {mk['salt']}")
        print()

    print("=" * 70)
    print(f"CHECKING FOR TARGET ADDRESS: {TARGET_ADDRESS}")
    print("=" * 70)
    print()
    if TARGET_ADDRESS in results['all_addresses']:
        print(f"  *** TARGET ADDRESS FOUND IN THIS WALLET! ***")
        print()
        if TARGET_ADDRESS in results['name_records']:
            label = results['name_records'][TARGET_ADDRESS]
            print(f"  Label: '{label}'")
        if TARGET_ADDRESS in results['purpose_records']:
            print(f"  Purpose: {results['purpose_records'][TARGET_ADDRESS]}")
        if TARGET_ADDRESS in results['addresses_from_pubkey']:
            if encrypted:
                print(f"  Status: Private key found, ENCRYPTED")
                print(f"          Need wallet password to decrypt.")
            else:
                print(f"  Status: Private key found, UNENCRYPTED")
                print(f"          Can be exported with bitcoin-cli or pywallet.")
        else:
            print(f"  Status: Address known but private key location not auto-detected.")
            print(f"          May still be present; try Bitcoin Core with this wallet.")
    else:
        print(f"  Target address NOT found in this wallet's records.")
        print(f"  Possible reasons:")
        print(f"    - Wallet was used at different time / for different addresses")
        print(f"    - Address may be in HD-derived pool (not yet 'used')")
        print(f"    - This is a different wallet than the one with target address")
    print()

    print(f"Sample addresses in wallet (first 30):")
    sorted_addrs = sorted(results['all_addresses'])
    for addr in sorted_addrs[:30]:
        label = results['name_records'].get(addr, '')
        marker = '   <<< TARGET' if addr == TARGET_ADDRESS else ''
        label_str = f' [{label}]' if label else ''
        print(f"  {addr}{label_str}{marker}")

    if len(sorted_addrs) > 30:
        print(f"  ... and {len(sorted_addrs) - 30} more")

    out_file = Path("wallet_dat_addresses.txt")
    with open(out_file, 'w', encoding='utf-8') as f:
        f.write(f"# All addresses extracted from {filepath}\n")
        f.write(f"# File size: {len(data)} bytes\n")
        f.write(f"# Encrypted: {encrypted}\n")
        f.write(f"# Target ({TARGET_ADDRESS}) found: {TARGET_ADDRESS in results['all_addresses']}\n\n")
        for addr in sorted_addrs:
            label = results['name_records'].get(addr, '')
            purpose = results['purpose_records'].get(addr, '')
            f.write(f"{addr}\t{label}\t{purpose}\n")
    print()
    print(f"Full address list saved to: {out_file.resolve()}")
    print(f"REVIEW PRIVATELY then DELETE this file.")


def main():
    parser = argparse.ArgumentParser(description="Inspect Bitcoin Core wallet.dat (any BDB format)")
    parser.add_argument("wallet_file", help="Path to wallet.dat")
    args = parser.parse_args()

    wallet_path = Path(args.wallet_file)
    if not wallet_path.exists():
        print(f"File not found: {wallet_path}")
        sys.exit(1)

    if wallet_path.stat().st_size < 1024:
        print(f"WARNING: File is very small ({wallet_path.stat().st_size} bytes)")
        print(f"Likely empty or corrupted")
        sys.exit(1)

    analyze(wallet_path)


if __name__ == "__main__":
    main()
