#!/usr/bin/env python3
"""
Bitcoin Wallet Recovery - wallet.dat Inspector
================================================
Extracts addresses + encrypted private keys from a Bitcoin Core
wallet.dat file WITHOUT requiring the password.

This is a SAFE READ-ONLY operation - it only reads the file structure.

It tells you:
  1. Whether wallet.dat contains the TARGET address (1B8hg...LMcko)
  2. List of all addresses present in the wallet
  3. Whether the wallet is encrypted (has master key) or not
  4. Wallet metadata (version, encryption status)

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
import struct
import sys
from pathlib import Path

TARGET_ADDRESS = "1B8hgFxNK7ac2k5EtrAanxQPFcnfHLMcko"

# ============================================================================
# Berkeley DB parser (minimal, just for reading wallet.dat)
# ============================================================================

class BSDDB:
    """Minimal Berkeley DB hash reader for wallet.dat."""

    def __init__(self, filepath):
        self.filepath = Path(filepath)
        self.records = []  # list of (key_bytes, value_bytes)

    def read(self):
        """Parse the BDB file and extract all records."""
        with open(self.filepath, 'rb') as f:
            data = f.read()

        if len(data) < 256:
            raise ValueError("File too small to be a valid wallet.dat")

        # BDB magic: 0x00061561 (hash db) at offset 12
        magic = struct.unpack('<I', data[12:16])[0]
        if magic != 0x00061561:
            # Try big endian
            magic = struct.unpack('>I', data[12:16])[0]
            if magic != 0x00061561:
                raise ValueError(f"Not a Berkeley DB hash file (magic={magic:#x})")

        # Page size at offset 20
        page_size = struct.unpack('<I', data[20:24])[0]
        if page_size not in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536):
            raise ValueError(f"Invalid page size: {page_size}")

        # Iterate over pages
        num_pages = len(data) // page_size
        for pageno in range(num_pages):
            page_start = pageno * page_size
            page = data[page_start:page_start + page_size]
            if len(page) < 26:
                continue
            # Page type at offset 25
            page_type = page[25]
            # Type 13 = HHASH page
            if page_type != 13:
                continue
            # Number of entries at offset 20 (2 bytes)
            num_entries = struct.unpack('<H', page[20:22])[0]
            # HOFFSET at 22 (2 bytes)
            # Index entries start at 26, each is 2 bytes (offset within page)
            index_offsets = []
            for i in range(num_entries):
                off_pos = 26 + i * 2
                if off_pos + 2 > len(page):
                    break
                off = struct.unpack('<H', page[off_pos:off_pos+2])[0]
                index_offsets.append(off)

            # Walk pairs (key, value) in alternating order
            current_key = None
            for i, off in enumerate(index_offsets):
                if off + 3 > len(page):
                    continue
                hdr_type = page[off + 2]
                if hdr_type == 1:  # HKEYDATA
                    rec_len = struct.unpack('<H', page[off:off+2])[0]
                    payload = page[off+3:off+3+rec_len]
                    if i % 2 == 0:
                        current_key = payload
                    else:
                        if current_key is not None:
                            self.records.append((current_key, payload))
                            current_key = None
                elif hdr_type == 3:  # HOFFPAGE - data spans multiple pages
                    # Skip for now (rarely contains addresses)
                    if i % 2 == 0:
                        current_key = b''
                    else:
                        current_key = None

        return self.records


# ============================================================================
# Bitcoin Core wallet record parsers
# ============================================================================

def parse_varint(data, offset):
    """Parse a Bitcoin/BDB compact varint."""
    if offset >= len(data):
        return 0, offset
    n = data[offset]
    if n < 253:
        return n, offset + 1
    elif n == 253:
        return struct.unpack('<H', data[offset+1:offset+3])[0], offset + 3
    elif n == 254:
        return struct.unpack('<I', data[offset+1:offset+5])[0], offset + 5
    else:
        return struct.unpack('<Q', data[offset+1:offset+9])[0], offset + 9


def parse_string(data, offset):
    """Parse a length-prefixed string."""
    length, new_offset = parse_varint(data, offset)
    s = data[new_offset:new_offset + length]
    return s, new_offset + length


def hash160_to_p2pkh_address(hash160):
    """Convert 20-byte hash160 to P2PKH address (mainnet, prefix 1...)."""
    if len(hash160) != 20:
        return None
    versioned = b'\x00' + hash160
    checksum = hashlib.sha256(hashlib.sha256(versioned).digest()).digest()[:4]
    full = versioned + checksum
    return base58_encode(full)


def hash160_to_p2sh_address(hash160):
    """Convert 20-byte hash160 to P2SH address (mainnet, prefix 3...)."""
    if len(hash160) != 20:
        return None
    versioned = b'\x05' + hash160
    checksum = hashlib.sha256(hashlib.sha256(versioned).digest()).digest()[:4]
    full = versioned + checksum
    return base58_encode(full)


def pubkey_to_address(pubkey_bytes):
    """Convert compressed/uncompressed public key to P2PKH address."""
    sha = hashlib.sha256(pubkey_bytes).digest()
    h160 = hashlib.new('ripemd160', sha).digest()
    return hash160_to_p2pkh_address(h160)


def base58_encode(data):
    """Standard Base58Check encoding."""
    alphabet = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    n = int.from_bytes(data, 'big')
    encoded = b''
    while n > 0:
        n, r = divmod(n, 58)
        encoded = alphabet[r:r+1] + encoded
    # Leading zeros become '1'
    for byte in data:
        if byte == 0:
            encoded = b'1' + encoded
        else:
            break
    return encoded.decode('ascii')


# ============================================================================
# WALLET RECORD ANALYZER
# ============================================================================

def analyze_wallet(filepath):
    """Read wallet.dat and extract structured info."""
    print(f"Reading: {filepath}")
    db = BSDDB(filepath)
    try:
        records = db.read()
    except Exception as e:
        print(f"ERROR parsing BDB structure: {e}")
        print("This may not be a valid wallet.dat or it may be corrupted.")
        return

    print(f"Total records: {len(records)}")
    print()

    # Categorize records
    types = {}
    addresses_found = set()
    encrypted_keys = []
    unencrypted_keys = []
    master_keys = []
    purposes = {}  # address -> label
    name_records = {}  # address -> name
    pool_keys = []
    has_mkey = False
    wallet_version = None

    for key, value in records:
        try:
            kname, koffset = parse_string(key, 0)
            ktype = kname.decode('ascii', errors='replace')
        except Exception:
            continue

        types[ktype] = types.get(ktype, 0) + 1

        # ---- "key" record: pubkey -> private key ----
        if ktype == 'key':
            try:
                pubkey, _ = parse_string(key, koffset)
                addr = pubkey_to_address(pubkey)
                if addr:
                    addresses_found.add(addr)
                    unencrypted_keys.append({'pubkey': pubkey.hex(), 'address': addr})
            except Exception:
                pass

        # ---- "ckey" record: pubkey -> ENCRYPTED private key ----
        elif ktype == 'ckey':
            try:
                pubkey, _ = parse_string(key, koffset)
                addr = pubkey_to_address(pubkey)
                if addr:
                    addresses_found.add(addr)
                    encrypted_keys.append({
                        'pubkey': pubkey.hex(),
                        'address': addr,
                        'encrypted_priv': value.hex()[:64] + '...'
                    })
            except Exception:
                pass

        # ---- "mkey" record: master encryption key (PBKDF2 salt + iter + encrypted master key) ----
        elif ktype == 'mkey':
            has_mkey = True
            try:
                if len(value) >= 8:
                    # Format varies; basic parse
                    crypted_key_len, off = parse_varint(value, 0)
                    crypted_key = value[off:off + crypted_key_len]
                    off += crypted_key_len
                    salt_len, off = parse_varint(value, off)
                    salt = value[off:off + salt_len]
                    off += salt_len
                    # method
                    if off + 4 <= len(value):
                        method = struct.unpack('<I', value[off:off+4])[0]
                        off += 4
                    else:
                        method = 0
                    if off + 4 <= len(value):
                        iters = struct.unpack('<I', value[off:off+4])[0]
                    else:
                        iters = 0
                    master_keys.append({
                        'encrypted_master_key': crypted_key.hex()[:32] + '...',
                        'salt': salt.hex(),
                        'derivation_method': method,
                        'iterations': iters,
                    })
            except Exception:
                pass

        # ---- "name" record: address -> human label ----
        elif ktype == 'name':
            try:
                addr_str, _ = parse_string(key, koffset)
                label, _ = parse_string(value, 0)
                addr = addr_str.decode('ascii', errors='replace')
                addresses_found.add(addr)
                name_records[addr] = label.decode('utf-8', errors='replace')
            except Exception:
                pass

        # ---- "purpose" record: address -> "send" or "receive" ----
        elif ktype == 'purpose':
            try:
                addr_str, _ = parse_string(key, koffset)
                purpose, _ = parse_string(value, 0)
                addr = addr_str.decode('ascii', errors='replace')
                addresses_found.add(addr)
                purposes[addr] = purpose.decode('ascii', errors='replace')
            except Exception:
                pass

        # ---- "pool" record: pre-generated keys for change addresses ----
        elif ktype == 'pool':
            try:
                pool_keys.append(key.hex()[:32])
            except Exception:
                pass

        # ---- "version" record ----
        elif ktype == 'version':
            try:
                if len(value) >= 4:
                    wallet_version = struct.unpack('<I', value[:4])[0]
            except Exception:
                pass

    # ---- REPORT ----
    print("=" * 70)
    print("WALLET ANALYSIS REPORT")
    print("=" * 70)
    print(f"Wallet version: {wallet_version}")
    print(f"Encrypted: {'YES (has mkey)' if has_mkey else 'NO (plain wallet)'}")
    print(f"Master keys: {len(master_keys)}")
    print(f"Unencrypted private keys ('key' records): {len(unencrypted_keys)}")
    print(f"Encrypted private keys ('ckey' records): {len(encrypted_keys)}")
    print(f"Total unique addresses found: {len(addresses_found)}")
    print(f"Pool keys (pre-generated): {len(pool_keys)}")
    print(f"Address labels: {len(name_records)}")
    print()

    print("Record types in wallet:")
    for t, count in sorted(types.items(), key=lambda x: -x[1]):
        print(f"  {t}: {count}")
    print()

    # Show master key details (these are needed for password cracking later)
    if master_keys:
        print("MASTER KEY DETAILS (for password recovery):")
        for i, mk in enumerate(master_keys):
            print(f"  Master key #{i + 1}:")
            print(f"    Method: {mk['derivation_method']} (0=AES, 1=AES-256-CBC)")
            print(f"    Iterations: {mk['iterations']:,}")
            print(f"    Salt: {mk['salt']}")
            print(f"    Encrypted master key (first 16 bytes): {mk['encrypted_master_key']}")
        print()

    # ---- TARGET CHECK ----
    print("=" * 70)
    print(f"CHECKING FOR TARGET ADDRESS: {TARGET_ADDRESS}")
    print("=" * 70)
    if TARGET_ADDRESS in addresses_found:
        print()
        print(f"  *** TARGET ADDRESS FOUND IN THIS WALLET! ***")
        print()
        if TARGET_ADDRESS in name_records:
            print(f"  Label: {name_records[TARGET_ADDRESS]}")
        if TARGET_ADDRESS in purposes:
            print(f"  Purpose: {purposes[TARGET_ADDRESS]}")
        # Check if encrypted or not
        for k in unencrypted_keys:
            if k['address'] == TARGET_ADDRESS:
                print(f"  ** Private key UNENCRYPTED - can be exported directly! **")
                print(f"     Pubkey: {k['pubkey']}")
                break
        for k in encrypted_keys:
            if k['address'] == TARGET_ADDRESS:
                print(f"  Private key is ENCRYPTED. Need wallet password to decrypt.")
                print(f"  Pubkey: {k['pubkey']}")
                break
    else:
        print()
        print(f"  Target address NOT found in this wallet's stored addresses.")
        print(f"  But it might still be present as a pool key (HD-derived) or pubkey.")
        print(f"  Total addresses scanned: {len(addresses_found)}")
    print()

    # Show first 20 addresses for context
    print("Sample addresses in wallet (first 20):")
    for addr in sorted(addresses_found)[:20]:
        label = name_records.get(addr, '')
        marker = '  <<< TARGET' if addr == TARGET_ADDRESS else ''
        print(f"  {addr}  {label}{marker}")

    print()
    print(f"Total unique addresses: {len(addresses_found)}")

    # Save full address list
    out_file = Path("wallet_dat_addresses.txt")
    with open(out_file, 'w') as f:
        f.write(f"# All addresses extracted from {filepath}\n")
        f.write(f"# Wallet encrypted: {has_mkey}\n")
        f.write(f"# Target ({TARGET_ADDRESS}) found: {TARGET_ADDRESS in addresses_found}\n\n")
        for addr in sorted(addresses_found):
            label = name_records.get(addr, '')
            f.write(f"{addr}\t{label}\n")
    print(f"\nFull address list saved to: {out_file.resolve()}")
    print("REMEMBER: Delete this file after review!")

    return {
        'encrypted': has_mkey,
        'master_keys': master_keys,
        'addresses': addresses_found,
        'target_found': TARGET_ADDRESS in addresses_found,
    }


def main():
    parser = argparse.ArgumentParser(description="Inspect Bitcoin Core wallet.dat")
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

    analyze_wallet(wallet_path)


if __name__ == "__main__":
    main()
