#!/usr/bin/env python3
"""
Bitcoin Wallet Recovery - Balance Checker
==========================================
Checks on-chain balance for all addresses in your wallet_dat_addresses.txt
(or any file with one address per line).

Reports ONLY addresses with non-zero history (received or current balance).
Uses mempool.space public API (no API key needed, rate-limited).

USAGE:
  python check_balances.py wallet_dat_addresses.txt
  python check_balances.py addresses.txt --output balances_found.txt

ETHICS:
  This tool only queries PUBLIC blockchain data using addresses that you
  already extracted from YOUR OWN wallet. It does not access any private keys.
  Only use this on wallets you actually own.

PERFORMANCE:
  ~1 request per second to be respectful of public API.
  1,800 addresses takes ~30 minutes.
"""

import argparse
import json
import re
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

# Public mempool.space API endpoint
MEMPOOL_API = "https://mempool.space/api/address/{}"

# Validation
ADDR_REGEX = re.compile(r'^[13][1-9A-HJ-NP-Za-km-z]{25,33}$|^bc1[a-z0-9]{38,87}$')


def check_address(addr, timeout=15):
    """Query mempool.space for an address. Returns dict with balance info."""
    url = MEMPOOL_API.format(addr)
    req = urllib.request.Request(url, headers={'User-Agent': 'wallet-recovery-tool/1.0'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
        # mempool.space format
        funded = data.get('chain_stats', {}).get('funded_txo_sum', 0)
        spent = data.get('chain_stats', {}).get('spent_txo_sum', 0)
        tx_count = data.get('chain_stats', {}).get('tx_count', 0)
        balance = funded - spent
        return {
            'address': addr,
            'balance_sats': balance,
            'total_received_sats': funded,
            'total_spent_sats': spent,
            'tx_count': tx_count,
            'error': None,
        }
    except urllib.error.HTTPError as e:
        if e.code == 429:  # Rate limited
            return {'address': addr, 'error': 'rate_limited'}
        return {'address': addr, 'error': f'http_{e.code}'}
    except (urllib.error.URLError, TimeoutError) as e:
        return {'address': addr, 'error': f'network: {e}'}
    except Exception as e:
        return {'address': addr, 'error': f'parse: {e}'}


def parse_addresses_file(filepath):
    """Read addresses from file, ignore comments and empty lines."""
    addresses = []
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # Take first column (in case file has tabs with labels)
            addr = line.split('\t')[0].strip()
            if ADDR_REGEX.match(addr):
                addresses.append(addr)
    return addresses


def main():
    parser = argparse.ArgumentParser(description="Check Bitcoin balances for a list of addresses")
    parser.add_argument("addresses_file", help="Path to file with addresses (one per line)")
    parser.add_argument("--output", default="balances_found.txt", help="Output file for results")
    parser.add_argument("--delay", type=float, default=1.1, help="Delay between requests (seconds)")
    parser.add_argument("--start", type=int, default=0, help="Resume from address index N")
    args = parser.parse_args()

    in_file = Path(args.addresses_file)
    if not in_file.exists():
        print(f"File not found: {in_file}")
        sys.exit(1)

    addresses = parse_addresses_file(in_file)
    print(f"Loaded {len(addresses)} addresses from {in_file}")
    print(f"Querying mempool.space (~{args.delay}s per address)")
    print(f"Estimated time: {len(addresses) * args.delay / 60:.1f} minutes")
    print(f"Output: {args.output}")
    print()

    if args.start > 0:
        print(f"Resuming from index {args.start}")
        addresses = addresses[args.start:]

    funded_addresses = []
    nonzero_balance = []
    errors = []

    out_path = Path(args.output)
    # Append mode if resuming
    mode = 'a' if args.start > 0 and out_path.exists() else 'w'
    with open(out_path, mode, encoding='utf-8') as out:
        if mode == 'w':
            out.write(f"# Balance check results for {in_file}\n")
            out.write(f"# Format: address | balance_BTC | received_BTC | tx_count\n\n")

        for i, addr in enumerate(addresses):
            result = check_address(addr)

            if result.get('error'):
                # Retry once on rate limit
                if result['error'] == 'rate_limited':
                    print(f"  [{i+1}/{len(addresses)}] {addr} - rate limited, sleeping 30s")
                    time.sleep(30)
                    result = check_address(addr)
                if result.get('error'):
                    errors.append((addr, result['error']))
                    print(f"  [{i+1}/{len(addresses)}] {addr} - ERROR: {result['error']}")
                    time.sleep(args.delay)
                    continue

            received = result['total_received_sats']
            balance = result['balance_sats']
            tx_count = result['tx_count']

            balance_btc = balance / 100_000_000
            received_btc = received / 100_000_000

            # Only log if address has any history
            if received > 0:
                funded_addresses.append(result)
                line = f"{addr}\t{balance_btc:.8f}\t{received_btc:.8f}\t{tx_count}\n"
                out.write(line)
                out.flush()

                marker = ""
                if balance > 0:
                    nonzero_balance.append(result)
                    marker = "  <<< HAS BALANCE!"
                else:
                    marker = "  (history but empty now)"

                print(f"  [{i+1}/{len(addresses)}] {addr}: bal={balance_btc:.8f} BTC, recv={received_btc:.8f} BTC, txs={tx_count}{marker}")
            else:
                if (i + 1) % 25 == 0:
                    print(f"  [{i+1}/{len(addresses)}] checked, {len(funded_addresses)} have history, {len(nonzero_balance)} have balance")

            time.sleep(args.delay)

    print()
    print("=" * 70)
    print("DONE")
    print("=" * 70)
    print(f"Total addresses scanned: {len(addresses)}")
    print(f"Addresses with history (any received): {len(funded_addresses)}")
    print(f"Addresses with CURRENT BALANCE: {len(nonzero_balance)}")
    print(f"Errors: {len(errors)}")
    print()

    if nonzero_balance:
        print("=" * 70)
        print("ADDRESSES WITH NON-ZERO BALANCE:")
        print("=" * 70)
        total_btc = 0
        for r in nonzero_balance:
            btc = r['balance_sats'] / 100_000_000
            total_btc += btc
            print(f"  {r['address']}  ->  {btc:.8f} BTC")
        print()
        print(f"  TOTAL BALANCE: {total_btc:.8f} BTC")
    else:
        print("No addresses with current balance.")

    print()
    print(f"Full results saved to: {out_path.resolve()}")


if __name__ == "__main__":
    main()
