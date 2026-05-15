#!/usr/bin/env python3
"""
Bitcoin Wallet Recovery - Local File Scanner
=============================================
Scans your computer for files that might contain seed phrases, private keys,
wallet backups, or anything related to Bitcoin recovery.

USAGE:
  python local_search.py /path/to/scan
  python local_search.py ~          (scan home dir)
  python local_search.py "C:\\"      (Windows whole drive - SLOW)

What it finds:
  - Files containing 12 or 24 BIP39 words in sequence
  - Files containing WIF private keys (5/K/L starts)
  - Files containing hex private keys (64 hex chars)
  - Wallet files (wallet.dat, wallet.aes.json, default_wallet, etc.)
  - Filenames containing "seed", "recovery", "wallet", "btc", etc.

SAFETY:
  - Read-only operation, doesn't modify any file
  - Run on YOUR OWN computer, offline if possible
  - Output written to recovery_findings.txt - REVIEW PRIVATELY then DELETE
"""

import os
import re
import sys
import json
from pathlib import Path

try:
    from mnemonic import Mnemonic
    BIP39_WORDS = set(Mnemonic("english").wordlist)
except ImportError:
    print("Run: pip install mnemonic")
    sys.exit(1)


# ============================================================================
# PATTERNS
# ============================================================================

# WIF private key (compressed/uncompressed mainnet)
WIF_PATTERN = re.compile(r'\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b')

# Hex 64 (32 bytes) - potential raw private key
HEX64_PATTERN = re.compile(r'\b[0-9a-fA-F]{64}\b')

# Bitcoin Legacy address
BTC_ADDR_PATTERN = re.compile(r'\b[13][1-9A-HJ-NP-Za-km-z]{25,34}\b')

# xprv extended private key
XPRV_PATTERN = re.compile(r'\bxprv[0-9A-Za-z]{107,108}\b')

# Suspicious filenames
SUSPICIOUS_FILENAMES = [
    'wallet.dat', 'wallet.aes.json', 'default_wallet', 'electrum.dat',
    'wallet_backup', 'seed.txt', 'seed.json', 'recovery.txt',
    'mnemonic.txt', 'private_key.txt', 'btc_wallet', 'bitcoin_backup',
]

SUSPICIOUS_KEYWORDS = re.compile(
    r'(seed|mnemonic|recovery.?phrase|private.?key|wallet|bitcoin|btc|'
    r'blockchain\.com|trust.?wallet|electrum|bip39|bip44)',
    re.IGNORECASE,
)

# Skip these directories (huge & irrelevant)
SKIP_DIRS = {
    'node_modules', '.git', '__pycache__', '.cache', 'AppData/Local/Temp',
    'Library/Caches', '.npm', '.gradle', 'venv', '.venv', 'env',
    'site-packages', 'dist-packages', '.local/share/Trash',
}

# File extensions to read (text-based)
READABLE_EXTS = {
    '.txt', '.md', '.json', '.csv', '.log', '.html', '.htm', '.xml',
    '.yaml', '.yml', '.cfg', '.conf', '.ini', '.rtf', '.tex',
    '.py', '.js', '.ts', '.java', '.c', '.cpp', '.go', '.rb', '.php',
    '.bak', '.old', '.swp', '',
}

# Maximum file size to scan content (10 MB)
MAX_FILE_SIZE = 10 * 1024 * 1024


# ============================================================================
# SCANNERS
# ============================================================================

def find_bip39_sequences(text: str) -> list:
    """Find sequences of 12, 18, or 24 valid BIP39 words in text."""
    # Tokenize: get all alphabetic tokens
    tokens = re.findall(r'\b[a-zA-Z]+\b', text.lower())

    findings = []
    for length in (24, 18, 12):
        for i in range(len(tokens) - length + 1):
            seq = tokens[i:i + length]
            if all(w in BIP39_WORDS for w in seq):
                findings.append((length, " ".join(seq)))
    return findings


def scan_file_content(filepath: Path) -> dict:
    """Scan one file for sensitive patterns. Returns dict of findings."""
    findings = {
        'bip39_seeds': [],
        'wif_keys': [],
        'hex_keys': [],
        'xprv_keys': [],
        'btc_addresses': [],
    }

    try:
        size = filepath.stat().st_size
        if size > MAX_FILE_SIZE:
            return findings
        with open(filepath, 'rb') as f:
            raw = f.read()
        # Try to decode as text
        try:
            text = raw.decode('utf-8', errors='ignore')
        except Exception:
            return findings
    except (PermissionError, OSError):
        return findings

    # Check seed phrases
    seeds = find_bip39_sequences(text)
    if seeds:
        findings['bip39_seeds'] = seeds[:5]  # cap to avoid spam

    # Check WIF
    wifs = WIF_PATTERN.findall(text)
    if wifs:
        findings['wif_keys'] = list(set(wifs))[:5]

    # Check hex 64
    hex64 = HEX64_PATTERN.findall(text)
    # Filter out obvious non-keys (e.g. all-zero, all-f, common hashes)
    hex64_filtered = [h for h in hex64 if len(set(h.lower())) > 4]
    if hex64_filtered:
        findings['hex_keys'] = list(set(hex64_filtered))[:5]

    # Check xprv
    xprvs = XPRV_PATTERN.findall(text)
    if xprvs:
        findings['xprv_keys'] = list(set(xprvs))[:3]

    # Check BTC addresses (just to flag any)
    addrs = BTC_ADDR_PATTERN.findall(text)
    # Filter to plausible-looking ones
    addrs_filtered = list(set([a for a in addrs if len(a) >= 26]))
    if addrs_filtered:
        findings['btc_addresses'] = addrs_filtered[:10]

    return findings


def scan_directory(root: Path, output_file: Path):
    """Walk a directory tree and scan suspicious files."""
    print(f"Scanning: {root}")
    print(f"Output: {output_file}")
    print("This may take several minutes for large directories...\n")

    out = open(output_file, 'w', encoding='utf-8')
    out.write(f"# Recovery Findings Report\n")
    out.write(f"# Scanned: {root}\n")
    out.write(f"# DO NOT SHARE THIS FILE - DELETE AFTER USE\n\n")

    total_files = 0
    suspicious_files = 0
    matched_files = 0

    for dirpath, dirs, files in os.walk(root):
        # Skip noisy dirs
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith('.')]

        for fname in files:
            filepath = Path(dirpath) / fname
            total_files += 1

            if total_files % 5000 == 0:
                print(f"  ... scanned {total_files} files, {matched_files} matches")

            # 1. Filename match
            fname_lower = fname.lower()
            is_suspicious_name = (
                any(s in fname_lower for s in SUSPICIOUS_FILENAMES)
                or SUSPICIOUS_KEYWORDS.search(fname_lower)
            )

            if is_suspicious_name:
                suspicious_files += 1
                out.write(f"\n[SUSPICIOUS FILENAME] {filepath}\n")

            # 2. Content scan (only readable extensions or small files)
            ext = filepath.suffix.lower()
            should_scan = is_suspicious_name or ext in READABLE_EXTS

            if not should_scan:
                continue

            findings = scan_file_content(filepath)
            has_match = any(findings.values())

            if has_match:
                matched_files += 1
                out.write(f"\n=== MATCH: {filepath} ===\n")
                if findings['bip39_seeds']:
                    out.write(f"  BIP39 SEED PHRASES FOUND ({len(findings['bip39_seeds'])}):\n")
                    for length, seed in findings['bip39_seeds']:
                        out.write(f"    [{length} words] {seed}\n")
                if findings['wif_keys']:
                    out.write(f"  WIF PRIVATE KEYS:\n")
                    for k in findings['wif_keys']:
                        out.write(f"    {k}\n")
                if findings['hex_keys']:
                    out.write(f"  POTENTIAL HEX KEYS (64 chars):\n")
                    for k in findings['hex_keys']:
                        out.write(f"    {k}\n")
                if findings['xprv_keys']:
                    out.write(f"  XPRV EXTENDED KEYS:\n")
                    for k in findings['xprv_keys']:
                        out.write(f"    {k}\n")
                if findings['btc_addresses']:
                    out.write(f"  BTC ADDRESSES MENTIONED:\n")
                    for a in findings['btc_addresses']:
                        marker = "  <-- TARGET!" if a == "1B8hgFxNK7ac2k5EtrAanxQPFcnfHLMcko" else ""
                        out.write(f"    {a}{marker}\n")
                out.flush()

    out.write(f"\n\n--- SUMMARY ---\n")
    out.write(f"Total files scanned: {total_files}\n")
    out.write(f"Suspicious filenames: {suspicious_files}\n")
    out.write(f"Files with matches: {matched_files}\n")
    out.close()

    print(f"\n=== DONE ===")
    print(f"Total files scanned: {total_files}")
    print(f"Suspicious filenames: {suspicious_files}")
    print(f"Files with potential matches: {matched_files}")
    print(f"\nReview output: {output_file}")
    print("REMEMBER: Delete this file after review!")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        print("\nUsage: python local_search.py <path_to_scan>")
        print("Example: python local_search.py ~")
        sys.exit(0)

    target = Path(sys.argv[1]).expanduser().resolve()
    if not target.exists():
        print(f"Path does not exist: {target}")
        sys.exit(1)

    output = Path("recovery_findings.txt").resolve()
    scan_directory(target, output)


if __name__ == "__main__":
    main()
