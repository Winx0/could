#!/usr/bin/env python3
"""
Bitcoin Wallet Recovery - Find Blockchain.com Wallet Files
===========================================================
Helps locate Blockchain.com wallet.aes.json files across your computer.

USAGE:
  python find_wallet_files.py
  python find_wallet_files.py /custom/path/to/scan

It searches:
  - Common Blockchain.com download paths
  - Browser localStorage (Chrome/Firefox/Edge/Brave)
  - Downloads/Documents/Desktop folders
  - Files matching wallet.aes.json or *.aes.json
  - JSON files containing 'guid' + 'payload' keys (Blockchain.com format)

Output: list of candidate files printed to console.
"""

import json
import os
import sys
from pathlib import Path

# Blockchain.com browser localStorage paths (relative to user home)
BROWSER_PATHS = [
    # Chrome/Brave
    ".config/google-chrome/Default/Local Storage/leveldb",
    ".config/chromium/Default/Local Storage/leveldb",
    ".config/BraveSoftware/Brave-Browser/Default/Local Storage/leveldb",
    # macOS Chrome
    "Library/Application Support/Google/Chrome/Default/Local Storage/leveldb",
    "Library/Application Support/BraveSoftware/Brave-Browser/Default/Local Storage/leveldb",
    # Firefox
    ".mozilla/firefox",
    "Library/Application Support/Firefox/Profiles",
    # Windows  
    "AppData/Local/Google/Chrome/User Data/Default/Local Storage/leveldb",
    "AppData/Roaming/Mozilla/Firefox/Profiles",
]

# Common download locations
COMMON_PATHS = [
    "Downloads",
    "Documents",
    "Desktop",
    "OneDrive",
    "OneDrive/Documents",
    "Dropbox",
    "Google Drive",
]

# File patterns
WALLET_FILE_NAMES = [
    "wallet.aes.json",
    "wallet.json",
    "blockchain_wallet",
]


def is_blockchain_wallet_json(filepath: Path) -> bool:
    """Check if a JSON file looks like Blockchain.com wallet format."""
    try:
        if filepath.stat().st_size > 5_000_000:  # >5MB unlikely
            return False
        with open(filepath, 'rb') as f:
            data = f.read(50000)  # first 50KB
        # Quick text check
        try:
            text = data.decode('utf-8')
        except UnicodeDecodeError:
            return False
        # Has GUID + payload structure
        if '"payload"' in text and ('"guid"' in text or '"version"' in text):
            return True
        # Try parse
        try:
            obj = json.loads(text)
            if isinstance(obj, dict) and "payload" in obj:
                return True
        except Exception:
            pass
    except Exception:
        return False
    return False


def scan(root: Path, found: list, depth: int = 0, max_depth: int = 8):
    """Recursively scan for wallet files."""
    if depth > max_depth:
        return
    try:
        for entry in root.iterdir():
            try:
                if entry.is_file():
                    name_lower = entry.name.lower()
                    # Filename match
                    if any(p in name_lower for p in WALLET_FILE_NAMES):
                        found.append((entry, "filename match"))
                        continue
                    # JSON files - check content
                    if name_lower.endswith(".json") or name_lower.endswith(".aes"):
                        if is_blockchain_wallet_json(entry):
                            found.append((entry, "content match (Blockchain.com format)"))
                elif entry.is_dir():
                    # Skip noisy dirs
                    if entry.name.startswith('.') and entry.name not in (
                        '.config', '.mozilla', '.dropbox', '.local'
                    ):
                        continue
                    if entry.name in (
                        'node_modules', '__pycache__', 'cache', 'Cache',
                        'CacheStorage', 'Code Cache', 'GPUCache',
                    ):
                        continue
                    scan(entry, found, depth + 1, max_depth)
            except (PermissionError, OSError):
                continue
    except (PermissionError, OSError):
        return


def main():
    if len(sys.argv) > 1:
        roots = [Path(p).expanduser().resolve() for p in sys.argv[1:]]
    else:
        # Auto-scan common locations
        home = Path.home()
        roots = [home / sub for sub in COMMON_PATHS if (home / sub).exists()]
        # Also check browser storage
        for bp in BROWSER_PATHS:
            full = home / bp
            if full.exists():
                roots.append(full)
        if not roots:
            roots = [home]

    print(f"Scanning for Blockchain.com wallet files...")
    for r in roots:
        print(f"  - {r}")
    print()

    found = []
    for root in roots:
        if not root.exists():
            continue
        scan(root, found)

    if not found:
        print("\nNo wallet files found in scanned locations.")
        print("\nTry scanning specific paths:")
        print("  python find_wallet_files.py ~/somewhere /other/path")
        return

    print(f"\nFound {len(found)} candidate file(s):\n")
    for i, (path, reason) in enumerate(found, 1):
        size = path.stat().st_size
        print(f"  [{i}] {path}")
        print(f"      Reason: {reason} | Size: {size:,} bytes")

    print()
    print("Next step:")
    print("  python blockchain_decrypt.py <path-to-wallet.aes.json>")


if __name__ == "__main__":
    main()
