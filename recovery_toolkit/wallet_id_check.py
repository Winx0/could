#!/usr/bin/env python3
"""
Bitcoin Wallet Recovery - Wallet ID Validator (Blockchain.com)
================================================================
Validates a list of UUIDs against Blockchain.com's PUBLIC wallet endpoint
to filter false positives from REAL Wallet IDs.

Useful after running extract_wallet_id.py which can produce many false
positives (UUIDs from other websites in browser localStorage shared
with Blockchain.com).

USAGE:
  # Use the extract_wallet_id.py output as input
  python wallet_id_check.py wallet_ids_list.txt

  # Limit how many to test (default: all)
  python wallet_id_check.py wallet_ids_list.txt --max 200

  # Custom rate limit (default: 5 seconds between requests)
  python wallet_id_check.py wallet_ids_list.txt --delay 7

  # Save encrypted payloads of REAL wallets for offline decryption
  python wallet_id_check.py wallet_ids_list.txt --save-payloads

WHAT IT DOES:
  1. Reads UUIDs from input file (any text format)
  2. Filters to valid UUID v4 (Blockchain.com format) - eliminates UUID v7
     (which is a 2024 standard not used by Blockchain.com)
  3. For each candidate, queries the public Blockchain.com endpoint
  4. Marks each as REAL / NOT_FOUND / ERROR
  5. Resumable (saves progress every 10 requests)

ETHICS / SAFETY:
  - Only run on UUIDs you have legitimate reason to verify
  - Rate-limited to respect Blockchain.com servers
  - Auto-stops on rate limiting (HTTP 429)
  - Knowing a Wallet ID does NOT grant access (still need email/password)
  - The script saves only public metadata + encrypted payloads
"""

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# UUID v4 strict format (Blockchain.com uses this format)
UUID_V4 = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
    re.IGNORECASE,
)

# Generic UUID extractor (any version)
UUID_ANY = re.compile(
    r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    re.IGNORECASE,
)

# Blockchain.com endpoint for fetching encrypted wallet payload
WALLET_ENDPOINT = "https://login.blockchain.com/wallet/{guid}?format=json"


def parse_input_file(path):
    """Extract all UUIDs from input file.

    Handles multiple encodings:
      - UTF-8 (Linux/Mac)
      - UTF-16 LE (Windows PowerShell '>' redirect default)
      - UTF-16 BE (less common)
      - CP1252 (legacy Windows)

    Returns (v4_uuids, other_uuids).
    """
    raw = Path(path).read_bytes()

    # Strip BOM if present
    if raw.startswith(b'\xff\xfe'):
        text = raw[2:].decode('utf-16-le', errors='replace')
    elif raw.startswith(b'\xfe\xff'):
        text = raw[2:].decode('utf-16-be', errors='replace')
    elif raw.startswith(b'\xef\xbb\xbf'):
        text = raw[3:].decode('utf-8', errors='replace')
    else:
        # No BOM. Try encodings in order of likelihood.
        text = ''
        best_count = 0
        for enc in ('utf-8', 'utf-16-le', 'utf-16-be', 'cp1252', 'latin-1'):
            try:
                decoded = raw.decode(enc, errors='strict')
                count = len(UUID_ANY.findall(decoded))
                if count > best_count:
                    best_count = count
                    text = decoded
            except UnicodeDecodeError:
                continue
        if not text:
            text = raw.decode('utf-8', errors='replace')

    ids = set(m.lower() for m in UUID_ANY.findall(text))
    v4 = [u for u in ids if UUID_V4.match(u)]
    other = [u for u in ids if not UUID_V4.match(u)]
    return v4, other


def check_wallet_id(guid, timeout=15):
    """Check if a Wallet ID exists at Blockchain.com."""
    url = WALLET_ENDPOINT.format(guid=guid)
    req = urllib.request.Request(
        url,
        headers={
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; recovery)',
            'Accept': 'application/json, text/html;q=0.9',
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            code = resp.getcode()
            data = resp.read()
            ct = resp.headers.get('Content-Type', '')

            if 'application/json' in ct.lower():
                try:
                    obj = json.loads(data)
                    if isinstance(obj, dict) and 'payload' in obj:
                        return {
                            'status': 'REAL',
                            'http_code': code,
                            'has_payload': True,
                            'version': obj.get('version'),
                            'payload_size': len(data),
                            'raw_payload': data,
                        }
                    return {
                        'status': 'JSON_NO_PAYLOAD',
                        'http_code': code,
                        'response': str(obj)[:200],
                    }
                except json.JSONDecodeError:
                    return {'status': 'INVALID_JSON', 'http_code': code}
            else:
                # Got HTML - usually means generic login page (= maybe not real)
                size = len(data)
                # Heuristic: if response includes the GUID in body, may be real
                if guid.encode() in data:
                    return {'status': 'HTML_WITH_GUID', 'http_code': code, 'size': size}
                return {'status': 'HTML_GENERIC', 'http_code': code, 'size': size}

    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {'status': 'NOT_FOUND', 'http_code': 404}
        elif e.code == 429:
            return {'status': 'RATE_LIMITED', 'http_code': 429}
        elif e.code == 500:
            return {'status': 'SERVER_ERROR', 'http_code': 500}
        else:
            return {'status': f'HTTP_{e.code}', 'http_code': e.code}
    except urllib.error.URLError as e:
        return {'status': 'NETWORK_ERROR', 'error': str(e)}
    except Exception as e:
        return {'status': f'ERROR_{type(e).__name__}', 'error': str(e)}


def load_progress(progress_file):
    """Load previous progress to resume."""
    if Path(progress_file).exists():
        try:
            return json.loads(Path(progress_file).read_text())
        except Exception:
            return {}
    return {}


def save_progress(progress_file, data):
    """Save current progress."""
    Path(progress_file).write_text(json.dumps(data, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description="Validate Wallet IDs against Blockchain.com",
    )
    parser.add_argument("input_file", help="File containing UUIDs (one per line, or extract_wallet_id.py output)")
    parser.add_argument("--max", type=int, default=0,
                        help="Max IDs to check (default: 0 = all). Recommend <300 per session.")
    parser.add_argument("--delay", type=float, default=5.0,
                        help="Seconds between requests (default: 5.0)")
    parser.add_argument("--save-payloads", action="store_true",
                        help="Save encrypted payloads of REAL wallets to ./payloads/")
    parser.add_argument("--output", default="wallet_id_results.txt",
                        help="Output report file")
    parser.add_argument("--progress", default=".wallet_id_progress.json",
                        help="Progress file for resume capability")
    args = parser.parse_args()

    in_file = Path(args.input_file)
    if not in_file.exists():
        print(f"File not found: {in_file}")
        sys.exit(1)

    print(f"Reading: {in_file}")
    v4_ids, other_ids = parse_input_file(in_file)
    print(f"  UUID v4 (Blockchain.com format): {len(v4_ids)}")
    print(f"  Other UUID versions (filtered out): {len(other_ids)}")
    print()

    if not v4_ids:
        print("No valid UUID v4 found. These are typically not Blockchain.com Wallet IDs.")
        sys.exit(0)

    # Apply max limit
    candidates = sorted(v4_ids)
    if args.max > 0 and len(candidates) > args.max:
        print(f"Limiting to first {args.max} (sorted) of {len(candidates)} UUID v4")
        candidates = candidates[:args.max]

    # Estimate
    est_minutes = (len(candidates) * args.delay) / 60
    print(f"Will check {len(candidates)} Wallet IDs at {args.delay}s/each")
    print(f"Estimated time: {est_minutes:.1f} minutes")
    print()
    print("WARNING: This makes one HTTP request per Wallet ID to Blockchain.com.")
    print("Be respectful - excessive checking may cause IP rate limits.")
    print()
    confirm = input("Continue? (yes/no): ").strip().lower()
    if confirm not in ('yes', 'y'):
        print("Aborted.")
        sys.exit(0)

    # Resume if previous progress
    progress = load_progress(args.progress)
    if progress:
        print(f"Resuming from previous progress: {len(progress)} already checked")

    results = dict(progress)
    payloads_dir = Path("payloads")
    if args.save_payloads:
        payloads_dir.mkdir(exist_ok=True)

    real_ids = []
    rate_limit_hit = False

    for i, guid in enumerate(candidates):
        if guid in results:
            # Already checked
            if results[guid].get('status') == 'REAL':
                real_ids.append(guid)
            continue

        print(f"  [{i + 1}/{len(candidates)}] {guid}...", end=' ', flush=True)
        result = check_wallet_id(guid)
        status = result.get('status', 'UNKNOWN')

        # Don't save raw payload bytes in JSON progress
        progress_entry = {k: v for k, v in result.items() if k != 'raw_payload'}
        results[guid] = progress_entry

        if status == 'REAL':
            real_ids.append(guid)
            print(f"REAL (size={result.get('payload_size', '?')} bytes)")
            if args.save_payloads and 'raw_payload' in result:
                pf = payloads_dir / f"{guid}.aes.json"
                pf.write_bytes(result['raw_payload'])
                print(f"      Saved: {pf}")
        elif status == 'NOT_FOUND':
            print("NOT_FOUND")
        elif status == 'RATE_LIMITED':
            print("RATE_LIMITED - stopping")
            rate_limit_hit = True
            break
        else:
            print(f"{status}")

        # Save progress periodically
        if (i + 1) % 10 == 0:
            save_progress(args.progress, results)

        time.sleep(args.delay)

    # Final save
    save_progress(args.progress, results)

    # Write report
    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(f"# Wallet ID validation report\n")
        f.write(f"# Source: {in_file}\n")
        f.write(f"# Total checked: {len(results)}\n")
        f.write(f"# REAL Wallet IDs found: {len(real_ids)}\n")
        if rate_limit_hit:
            f.write(f"# (Stopped early due to rate limiting)\n")
        f.write("\n")

        f.write("=" * 70 + "\n")
        f.write("REAL WALLET IDs (login at https://login.blockchain.com)\n")
        f.write("=" * 70 + "\n")
        for guid in real_ids:
            r = results[guid]
            f.write(f"  {guid}  size={r.get('payload_size', '?')} version={r.get('version', '?')}\n")

        f.write("\n")
        f.write("=" * 70 + "\n")
        f.write("STATUS BREAKDOWN\n")
        f.write("=" * 70 + "\n")
        status_counts = {}
        for guid, r in results.items():
            s = r.get('status', 'UNKNOWN')
            status_counts[s] = status_counts.get(s, 0) + 1
        for s, c in sorted(status_counts.items(), key=lambda x: -x[1]):
            f.write(f"  {s}: {c}\n")

    print()
    print("=" * 70)
    print(f"DONE")
    print("=" * 70)
    print(f"Total checked: {len(results)}")
    print(f"REAL Wallet IDs found: {len(real_ids)}")
    print(f"Status breakdown:")
    for s, c in sorted(status_counts.items(), key=lambda x: -x[1]):
        print(f"  {s}: {c}")
    print()
    print(f"Report: {Path(args.output).resolve()}")
    if args.save_payloads:
        print(f"Payloads saved to: {payloads_dir.resolve()}/")
        print()
        print("Next step: try decrypt with blockchain_decrypt.py")
        print(f"  python blockchain_decrypt.py payloads/<guid>.aes.json")


if __name__ == "__main__":
    main()
