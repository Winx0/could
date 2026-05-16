#!/usr/bin/env python3
"""
Smart Wallet ID Extractor
==========================
Improved version of extract_wallet_id.py that uses CONTEXT-AWARE filtering
to reduce false positives.

Key improvement vs original:
  - Original: ANY UUID in a file mentioning "blockchain.com"
  - Smart:    ONLY UUIDs within +/-300 chars of the string "blockchain.com"

This typically reduces 1000+ noisy UUIDs to 5-15 high-probability candidates.

USAGE:
  python extract_wallet_id_smart.py
  python extract_wallet_id_smart.py --browser "C:\\path\\to\\Chrome\\User Data"
  python extract_wallet_id_smart.py --grep "C:\\path\\to\\folder"

OUTPUT:
  Sorted by score (proximity + frequency)
  Top candidates = most likely real Wallet IDs
"""

import argparse
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

# UUID v4 strict (Blockchain.com format)
UUID_V4 = re.compile(
    rb'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',
    re.IGNORECASE,
)

# Strings indicating Blockchain.com context
BC_KEYWORDS = [
    b'blockchain.com',
    b'blockchain.info',
    b'wallet.aes.json',
    b'blockchain-luxembourg',
    b'login.blockchain',
    b'/wallet/',  # API endpoint
    b'guid',
]

# Proximity window
DEFAULT_PROXIMITY = 300


def find_keyword_positions(data):
    """Find all byte positions where Blockchain.com keywords appear."""
    positions = []
    lower = data.lower()
    for kw in BC_KEYWORDS:
        kw_lower = kw.lower()
        start = 0
        while True:
            pos = lower.find(kw_lower, start)
            if pos == -1:
                break
            positions.append((pos, len(kw_lower), kw_lower))
            start = pos + 1
    return positions


def extract_smart(data, proximity=DEFAULT_PROXIMITY):
    """
    Extract UUIDs that appear within `proximity` bytes of any
    Blockchain.com keyword. Returns dict {uuid: hits_count}.
    """
    keyword_positions = find_keyword_positions(data)
    if not keyword_positions:
        return {}

    candidates = defaultdict(int)

    for kw_pos, kw_len, _ in keyword_positions:
        window_start = max(0, kw_pos - proximity)
        window_end = min(len(data), kw_pos + kw_len + proximity)
        window = data[window_start:window_end]

        for match in UUID_V4.finditer(window):
            uuid_str = match.group(0).decode('ascii', errors='ignore').lower()
            candidates[uuid_str] += 1

    return dict(candidates)


def common_browser_paths():
    """Default browser localStorage locations."""
    home = Path.home()
    paths = [
        home / 'AppData/Local/Google/Chrome/User Data',
        home / 'AppData/Local/BraveSoftware/Brave-Browser/User Data',
        home / 'AppData/Local/Microsoft/Edge/User Data',
        home / 'AppData/Roaming/Mozilla/Firefox/Profiles',
        home / '.config/google-chrome',
        home / '.config/chromium',
        home / '.config/BraveSoftware/Brave-Browser',
        home / 'Library/Application Support/Google/Chrome',
        home / 'Library/Application Support/Firefox/Profiles',
    ]
    return [p for p in paths if p.exists()]


def scan_directory(root, proximity, extensions=None):
    """Walk directory and scan all relevant files."""
    if extensions is None:
        extensions = ('.ldb', '.log', '.sqlite', '.localstorage', '.json',
                      '.txt', '.eml', '.html', '.htm')
    skip_dirs = {'GPUCache', 'Code Cache', 'Service Worker', 'CacheStorage',
                 'File System', 'blob_storage', 'node_modules'}

    results = defaultdict(lambda: {'hits': 0, 'sources': set()})
    files_scanned = 0
    files_with_bc = 0

    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for fname in files:
            ext = Path(fname).suffix.lower()
            no_ext = ext == ''
            if not (ext in extensions or no_ext or fname == 'CURRENT'):
                continue
            fpath = Path(dirpath) / fname
            try:
                size = fpath.stat().st_size
                if size > 100_000_000:  # skip huge files
                    continue
                with open(fpath, 'rb') as f:
                    data = f.read()
            except (PermissionError, OSError):
                continue

            files_scanned += 1
            if files_scanned % 500 == 0:
                print(f"    ... scanned {files_scanned} files, {files_with_bc} with blockchain.com mentions")

            if not any(kw in data.lower() for kw in BC_KEYWORDS):
                continue
            files_with_bc += 1

            candidates = extract_smart(data, proximity)
            for uuid_str, hits in candidates.items():
                results[uuid_str]['hits'] += hits
                results[uuid_str]['sources'].add(str(fpath))

    return dict(results), files_scanned, files_with_bc


def main():
    parser = argparse.ArgumentParser(
        description="Smart Wallet ID extractor (context-aware)",
    )
    parser.add_argument('--browser', help='Specific browser profile path')
    parser.add_argument('--grep', help='Search any directory recursively')
    parser.add_argument('--scan', action='store_true',
                        help='Auto-scan common browser paths')
    parser.add_argument('--proximity', type=int, default=DEFAULT_PROXIMITY,
                        help=f'Bytes around keyword (default {DEFAULT_PROXIMITY})')
    parser.add_argument('--output', default='smart_wallet_ids.txt',
                        help='Output file with ranked candidates')
    args = parser.parse_args()

    if not (args.browser or args.grep or args.scan):
        # Default: auto-scan
        args.scan = True

    paths = []
    if args.browser:
        paths.append(Path(args.browser).expanduser())
    if args.grep:
        paths.append(Path(args.grep).expanduser())
    if args.scan:
        paths.extend(common_browser_paths())

    if not paths:
        print("ERROR: No paths to scan")
        sys.exit(1)

    print("=" * 70)
    print("SMART WALLET ID EXTRACTOR")
    print("=" * 70)
    print(f"Proximity window: +/-{args.proximity} bytes around 'blockchain.com'")
    print(f"Scanning {len(paths)} location(s):")
    for p in paths:
        print(f"  {p}")
    print()

    all_results = defaultdict(lambda: {'hits': 0, 'sources': set()})
    total_scanned = 0
    total_with_bc = 0

    for p in paths:
        if not p.exists():
            print(f"  Skip {p} (not found)")
            continue
        print(f"\nScanning: {p}")
        results, scanned, with_bc = scan_directory(p, args.proximity)
        total_scanned += scanned
        total_with_bc += with_bc
        for uuid_str, info in results.items():
            all_results[uuid_str]['hits'] += info['hits']
            all_results[uuid_str]['sources'].update(info['sources'])

    # Score: hits + 5 per unique source
    ranked = sorted(
        all_results.items(),
        key=lambda x: -(x[1]['hits'] + 5 * len(x[1]['sources']))
    )

    print()
    print("=" * 70)
    print(f"DONE")
    print("=" * 70)
    print(f"Files scanned: {total_scanned:,}")
    print(f"Files with blockchain.com mentions: {total_with_bc:,}")
    print(f"Unique candidate Wallet IDs: {len(ranked)}")
    print()

    if not ranked:
        print("No candidate Wallet IDs found in blockchain.com context.")
        return

    print(f"TOP 30 CANDIDATES (sorted by relevance score):")
    print(f"{'Score':>6} {'Hits':>5} {'Sources':>8}  Wallet ID")
    print("-" * 70)
    for uuid_str, info in ranked[:30]:
        score = info['hits'] + 5 * len(info['sources'])
        print(f"{score:>6} {info['hits']:>5} {len(info['sources']):>8}  {uuid_str}")

    # Save full report
    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(f"# Smart Wallet ID candidates (sorted by score)\n")
        f.write(f"# Files scanned: {total_scanned}\n")
        f.write(f"# Files with blockchain.com: {total_with_bc}\n")
        f.write(f"# Proximity window: {args.proximity} bytes\n\n")
        for uuid_str, info in ranked:
            score = info['hits'] + 5 * len(info['sources'])
            f.write(f"{uuid_str}\tscore={score}\thits={info['hits']}\tsources={len(info['sources'])}\n")

    print()
    print(f"Full report: {Path(args.output).resolve()}")
    print()
    print("Next step:")
    print(f"  python wallet_id_check.py {args.output} --max 50 --save-payloads")


if __name__ == '__main__':
    main()
