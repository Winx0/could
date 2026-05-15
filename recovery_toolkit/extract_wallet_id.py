#!/usr/bin/env python3
"""
Bitcoin Wallet Recovery - Extract Blockchain.com Wallet IDs (GUIDs)
====================================================================
Discovers Wallet IDs (UUIDs) from various sources WITHOUT needing the password.

The Wallet ID is stored in PLAINTEXT in:
  - wallet.aes.json envelope (NOT inside the encrypted payload)
  - Browser localStorage (Chrome/Firefox/Brave/Edge)
  - Email inbox (search "Blockchain.com Wallet ID")

USAGE:
  # Extract from one or many wallet.aes.json files
  python extract_wallet_id.py wallet.aes.json
  python extract_wallet_id.py *.aes.json

  # Auto-scan computer for wallet files & browser storage
  python extract_wallet_id.py --scan

  # Scan specific browser profile
  python extract_wallet_id.py --browser ~/.config/google-chrome

  # Search any directory for wallet IDs
  python extract_wallet_id.py --grep ~/Documents

Note: This tool CANNOT find a Wallet ID from a Bitcoin address alone.
That mapping is private to Blockchain.com servers and not available externally.
This tool finds Wallet IDs that exist on YOUR computer.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

# UUID v4 pattern - what Blockchain.com Wallet IDs look like
UUID_PATTERN = re.compile(
    r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    re.IGNORECASE,
)


def extract_from_wallet_file(filepath: Path) -> dict:
    """
    Extract metadata from a wallet.aes.json file WITHOUT decrypting.
    The envelope JSON is plaintext; only the 'payload' field is encrypted.
    """
    info = {'file': str(filepath), 'wallet_id': None, 'version': None, 'extra': {}}
    try:
        with open(filepath, 'rb') as f:
            data = f.read(2_000_000)  # 2MB limit
        try:
            text = data.decode('utf-8')
        except UnicodeDecodeError:
            return info

        # Try parse as JSON envelope
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                if 'guid' in obj:
                    info['wallet_id'] = obj['guid']
                if 'version' in obj:
                    info['version'] = obj['version']
                for k in ('sharedKey', 'pbkdf2_iterations', 'language', 'options'):
                    if k in obj:
                        info['extra'][k] = obj[k] if k != 'sharedKey' else '[REDACTED]'
                return info
        except json.JSONDecodeError:
            pass

        # Fallback: regex search for UUID pattern in the file
        matches = UUID_PATTERN.findall(text)
        if matches:
            info['wallet_id'] = matches[0]
            info['extra']['note'] = 'extracted via regex (file not standard JSON)'
    except (PermissionError, OSError) as e:
        info['extra']['error'] = str(e)
    return info


def scan_browser_storage(browser_root: Path) -> list:
    """
    Scan browser localStorage / IndexedDB for Blockchain.com Wallet IDs.
    Looks at LevelDB log/SST files which contain the raw localStorage data.
    """
    findings = []
    if not browser_root.exists():
        return findings

    target_extensions = {'.log', '.ldb', '.sqlite', '.sqlite-wal'}
    target_filenames = {'CURRENT', 'localStorage', 'session'}

    for dirpath, dirs, files in os.walk(browser_root):
        dirs[:] = [d for d in dirs if d not in (
            'GPUCache', 'Code Cache', 'Service Worker', 'CacheStorage',
            'File System', 'blob_storage',
        )]
        for fname in files:
            ext = Path(fname).suffix.lower()
            if ext not in target_extensions and fname not in target_filenames:
                continue
            fpath = Path(dirpath) / fname
            try:
                if fpath.stat().st_size > 50_000_000:
                    continue
                with open(fpath, 'rb') as f:
                    raw = f.read()
                text = raw.decode('utf-8', errors='ignore')
                if 'blockchain.com' not in text.lower() and 'blockchain.info' not in text.lower():
                    continue
                uuids = set(UUID_PATTERN.findall(text))
                for u in uuids:
                    idx = text.lower().find(u.lower())
                    ctx = text[max(0, idx-100):idx+50] if idx >= 0 else ''
                    ctx = ''.join(c if 32 <= ord(c) < 127 else '.' for c in ctx)
                    findings.append({
                        'wallet_id': u,
                        'source': str(fpath),
                        'context': ctx[-150:],
                    })
            except (PermissionError, OSError):
                continue
    return findings


def grep_directory(root: Path) -> list:
    """Search any directory for files mentioning blockchain.com + UUID."""
    findings = []
    text_extensions = {
        '.txt', '.md', '.json', '.csv', '.log', '.html', '.htm', '.eml',
        '.mbox', '.xml', '.yaml', '.yml', '',
    }

    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in (
            'node_modules', '__pycache__', 'cache',
        )]
        for fname in files:
            fpath = Path(dirpath) / fname
            if fpath.suffix.lower() not in text_extensions:
                continue
            try:
                if fpath.stat().st_size > 20_000_000:
                    continue
                with open(fpath, 'rb') as f:
                    raw = f.read()
                text = raw.decode('utf-8', errors='ignore')
                if 'blockchain' not in text.lower():
                    continue
                uuids = set(UUID_PATTERN.findall(text))
                for u in uuids:
                    idx = text.lower().find(u.lower())
                    ctx = text[max(0, idx-100):idx+50] if idx >= 0 else ''
                    findings.append({
                        'wallet_id': u,
                        'source': str(fpath),
                        'context': ctx[-150:].replace('\n', ' '),
                    })
            except (PermissionError, OSError):
                continue
    return findings


def common_browser_paths():
    """Return list of common browser localStorage paths to check."""
    home = Path.home()
    paths = [
        # Chrome / Brave / Edge / Chromium - Linux
        home / ".config/google-chrome/Default/Local Storage/leveldb",
        home / ".config/chromium/Default/Local Storage/leveldb",
        home / ".config/BraveSoftware/Brave-Browser/Default/Local Storage/leveldb",
        home / ".config/microsoft-edge/Default/Local Storage/leveldb",
        # Chrome / Brave - macOS
        home / "Library/Application Support/Google/Chrome/Default/Local Storage/leveldb",
        home / "Library/Application Support/BraveSoftware/Brave-Browser/Default/Local Storage/leveldb",
        # Chrome / Brave / Edge - Windows
        home / "AppData/Local/Google/Chrome/User Data/Default/Local Storage/leveldb",
        home / "AppData/Local/BraveSoftware/Brave-Browser/User Data/Default/Local Storage/leveldb",
        home / "AppData/Local/Microsoft/Edge/User Data/Default/Local Storage/leveldb",
        # Firefox profiles
        home / ".mozilla/firefox",
        home / "Library/Application Support/Firefox/Profiles",
        home / "AppData/Roaming/Mozilla/Firefox/Profiles",
    ]
    return [p for p in paths if p.exists()]


def main():
    parser = argparse.ArgumentParser(
        description="Extract Blockchain.com Wallet IDs from local sources",
    )
    parser.add_argument("wallet_files", nargs='*', help="Path(s) to wallet.aes.json file(s)")
    parser.add_argument("--scan", action='store_true', help="Auto-scan home directory for wallet files & browser storage")
    parser.add_argument("--browser", help="Scan a specific browser profile path")
    parser.add_argument("--grep", help="Search directory for files mentioning Blockchain.com + UUID")
    args = parser.parse_args()

    all_wallet_ids = set()
    sources_per_id = {}

    # 1. Process specific wallet files (also handle glob in case shell didn't expand)
    for wf in args.wallet_files:
        candidates = list(Path('.').glob(wf)) if any(c in wf for c in '*?[') else [Path(wf)]
        for path in candidates:
            if not path.exists():
                continue
            info = extract_from_wallet_file(path)
            print(f"\n--- {info['file']} ---")
            if info['wallet_id']:
                print(f"  Wallet ID: {info['wallet_id']}")
                all_wallet_ids.add(info['wallet_id'])
                sources_per_id.setdefault(info['wallet_id'], []).append(str(path))
            else:
                print(f"  No Wallet ID found in this file.")
            if info['version']:
                print(f"  Version: {info['version']}")
            for k, v in info['extra'].items():
                print(f"  {k}: {v}")

    # 2. Browser scan
    if args.scan or args.browser:
        if args.browser:
            browser_paths = [Path(args.browser).expanduser()]
        else:
            browser_paths = common_browser_paths()

        print("\n=== Scanning Browser Storage ===")
        for bp in browser_paths:
            if not bp.exists():
                continue
            print(f"  Browser: {bp}")
            findings = scan_browser_storage(bp)
            for f in findings:
                print(f"    [MATCH] {f['wallet_id']}")
                print(f"      Source: {f['source']}")
                print(f"      Context: ...{f['context']}...")
                all_wallet_ids.add(f['wallet_id'])
                sources_per_id.setdefault(f['wallet_id'], []).append(f['source'])

    # 3. Auto-scan home dir for wallet files
    if args.scan:
        print("\n=== Searching for wallet.aes.json files in home directory ===")
        home = Path.home()
        try:
            for filepath in home.rglob('*.aes.json'):
                info = extract_from_wallet_file(filepath)
                print(f"  Found: {filepath}")
                if info['wallet_id']:
                    print(f"    Wallet ID: {info['wallet_id']}")
                    all_wallet_ids.add(info['wallet_id'])
                    sources_per_id.setdefault(info['wallet_id'], []).append(str(filepath))
        except (PermissionError, OSError) as e:
            print(f"  Error scanning: {e}")

    # 4. Grep mode
    if args.grep:
        print(f"\n=== Searching {args.grep} for Blockchain.com mentions ===")
        findings = grep_directory(Path(args.grep).expanduser())
        for f in findings:
            print(f"  Wallet ID: {f['wallet_id']}")
            print(f"    Source: {f['source']}")
            print(f"    Context: ...{f['context']}...")
            all_wallet_ids.add(f['wallet_id'])
            sources_per_id.setdefault(f['wallet_id'], []).append(f['source'])

    # Summary
    print(f"\n\n{'='*70}")
    print(f"SUMMARY: Found {len(all_wallet_ids)} unique Wallet ID(s)")
    print(f"{'='*70}")
    for wid in sorted(all_wallet_ids):
        print(f"\n  Wallet ID: {wid}")
        for src in sources_per_id.get(wid, []):
            print(f"    Source: {src}")

    if all_wallet_ids:
        print("\nNext steps:")
        print(f"  1. Login at https://login.blockchain.com using each Wallet ID")
        print(f"  2. Or use the matching wallet.aes.json file with blockchain_decrypt.py")
        print(f"  3. Cross-reference with your email inbox for 'Wallet ID' emails")
    else:
        print("\nNo Wallet IDs found.")
        print("Try: python extract_wallet_id.py --scan  (full home dir scan)")


if __name__ == "__main__":
    main()
