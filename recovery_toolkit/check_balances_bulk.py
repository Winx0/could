#!/usr/bin/env python3
"""
Bitcoin Wallet Recovery - BULK Balance Checker (FAST)
======================================================
50x faster than check_balances.py - uses blockchain.info bulk API
that supports up to 50 addresses per request.

For 1,835 addresses: ~37 requests = ~3-5 minutes total.

USAGE:
  python check_balances_bulk.py wallet_dat_addresses.txt
  python check_balances_bulk.py derived_addresses.txt --output balances.txt

ETHICS:
  Only queries PUBLIC blockchain data. No private keys involved.
  Use only on wallets you own.
"""

import argparse
import json
import re
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
from pathlib import Path

# Bulk API: blockchain.info supports up to ~50 addresses per request
BLOCKCHAIN_INFO_BULK = "https://blockchain.info/balance?active={}&cors=true"
BATCH_SIZE = 50

# Validation - only legacy 1.../3... (blockchain.info bulk doesn't support bech32)
LEGACY_ADDR_REGEX = re.compile(r'^[13][1-9A-HJ-NP-Za-km-z]{25,33}$')
BECH32_ADDR_REGEX = re.compile(r'^bc1[a-z0-9]{38,87}$')


def check_batch(addresses, timeout=30):
    """Query blockchain.info with up to 50 addresses at once."""
    addr_str = '|'.join(addresses)
    url = BLOCKCHAIN_INFO_BULK.format(urllib.parse.quote(addr_str, safe='|'))
    req = urllib.request.Request(url, headers={'User-Agent': 'wallet-recovery-tool/1.0'})

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
        results = {}
        for addr, info in data.items():
            results[addr] = {
                'balance_sats': info.get('final_balance', 0),
                'total_received_sats': info.get('total_received', 0),
                'tx_count': info.get('n_tx', 0),
            }
        return results
    except urllib.error.HTTPError as e:
        if e.code == 429:
            return {'__error__': 'rate_limited'}
        return {'__error__': f'http_{e.code}'}
    except (urllib.error.URLError, TimeoutError) as e:
        return {'__error__': f'network: {e}'}
    except Exception as e:
        return {'__error__': f'parse: {e}'}


def parse_addresses_file(filepath):
    """Read legacy/p2sh addresses from file."""
    addresses_legacy = []
    addresses_bech32 = []
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            addr = line.split('\t')[0].strip()
            if LEGACY_ADDR_REGEX.match(addr):
                addresses_legacy.append(addr)
            elif BECH32_ADDR_REGEX.match(addr):
                addresses_bech32.append(addr)
    return addresses_legacy, addresses_bech32


def main():
    parser = argparse.ArgumentParser(description="FAST bulk balance checker")
    parser.add_argument("addresses_file", help="Path to address list file")
    parser.add_argument("--output", default="balances_bulk.txt", help="Output file")
    parser.add_argument("--delay", type=float, default=2.0,
                        help="Seconds between batches (default: 2.0)")
    args = parser.parse_args()

    in_file = Path(args.addresses_file)
    if not in_file.exists():
        print(f"File not found: {in_file}")
        sys.exit(1)

    legacy, bech32 = parse_addresses_file(in_file)
    print(f"Loaded {len(legacy)} legacy/p2sh addresses + {len(bech32)} bech32 addresses")

    if bech32:
        print(f"Note: {len(bech32)} bech32 addresses will be checked separately (slower).")

    total = len(legacy) + len(bech32)
    num_batches = (len(legacy) + BATCH_SIZE - 1) // BATCH_SIZE + len(bech32)
    estimated_min = (num_batches * args.delay) / 60
    print(f"Total batches: {num_batches}, estimated time: {estimated_min:.1f} minutes")
    print()

    # Process bulk batches for legacy
    funded = []  # has any history
    has_balance = []  # current balance > 0

    out_path = Path(args.output)
    with open(out_path, 'w', encoding='utf-8') as out:
        out.write(f"# Balance results for {in_file}\n")
        out.write(f"# Format: address\\tbalance_BTC\\treceived_BTC\\ttx_count\n\n")

        # Bulk legacy
        for i in range(0, len(legacy), BATCH_SIZE):
            batch = legacy[i:i + BATCH_SIZE]
            batch_num = i // BATCH_SIZE + 1
            total_batches = (len(legacy) + BATCH_SIZE - 1) // BATCH_SIZE
            print(f"  Batch {batch_num}/{total_batches}: checking {len(batch)} addresses...")

            results = check_batch(batch)

            if '__error__' in results:
                err = results['__error__']
                print(f"    ERROR: {err}")
                if err == 'rate_limited':
                    print(f"    Sleeping 60s then retrying...")
                    time.sleep(60)
                    results = check_batch(batch)
                    if '__error__' in results:
                        print(f"    Still failing, skipping batch")
                        time.sleep(args.delay)
                        continue

            for addr in batch:
                info = results.get(addr)
                if not info:
                    continue
                received = info['total_received_sats']
                balance = info['balance_sats']
                tx_count = info['tx_count']

                if received > 0:
                    bal_btc = balance / 100_000_000
                    recv_btc = received / 100_000_000
                    funded.append((addr, balance, received, tx_count))
                    out.write(f"{addr}\t{bal_btc:.8f}\t{recv_btc:.8f}\t{tx_count}\n")
                    out.flush()
                    if balance > 0:
                        has_balance.append((addr, balance, received, tx_count))
                        print(f"    [HIT!] {addr}: balance={bal_btc:.8f} BTC")
                    else:
                        print(f"    [history] {addr}: received={recv_btc:.8f} BTC, now empty")

            time.sleep(args.delay)

        # Bech32 - one at a time using mempool.space
        if bech32:
            print(f"\nChecking {len(bech32)} bech32 addresses (1 per request)...")
            for i, addr in enumerate(bech32):
                try:
                    url = f"https://mempool.space/api/address/{addr}"
                    req = urllib.request.Request(url, headers={'User-Agent': 'wallet-recovery-tool/1.0'})
                    with urllib.request.urlopen(req, timeout=15) as resp:
                        data = json.loads(resp.read())
                    funded_sat = data.get('chain_stats', {}).get('funded_txo_sum', 0)
                    spent_sat = data.get('chain_stats', {}).get('spent_txo_sum', 0)
                    tx_count = data.get('chain_stats', {}).get('tx_count', 0)
                    balance = funded_sat - spent_sat
                    if funded_sat > 0:
                        bal_btc = balance / 100_000_000
                        recv_btc = funded_sat / 100_000_000
                        funded.append((addr, balance, funded_sat, tx_count))
                        out.write(f"{addr}\t{bal_btc:.8f}\t{recv_btc:.8f}\t{tx_count}\n")
                        out.flush()
                        if balance > 0:
                            has_balance.append((addr, balance, funded_sat, tx_count))
                            print(f"  [HIT!] {addr}: balance={bal_btc:.8f} BTC")
                except Exception as e:
                    print(f"  [{i+1}] {addr}: error {e}")
                time.sleep(1.1)

    # Summary
    print()
    print("=" * 70)
    print("DONE")
    print("=" * 70)
    print(f"Total addresses scanned: {total}")
    print(f"Addresses with history (any received): {len(funded)}")
    print(f"Addresses with CURRENT BALANCE: {len(has_balance)}")
    print()

    if has_balance:
        print("=" * 70)
        print("ADDRESSES WITH NON-ZERO BALANCE:")
        print("=" * 70)
        total_btc = 0
        # Sort by balance descending
        has_balance.sort(key=lambda x: -x[1])
        for addr, bal_sat, recv_sat, txs in has_balance:
            bal_btc = bal_sat / 100_000_000
            total_btc += bal_btc
            print(f"  {addr}  ->  {bal_btc:.8f} BTC  ({txs} txs)")
        print()
        print(f"  TOTAL BALANCE: {total_btc:.8f} BTC  (~${total_btc * 79000:.2f} at $79k/BTC)")

    if funded and not has_balance:
        print()
        print("Addresses with history (already spent, balance = 0):")
        funded.sort(key=lambda x: -x[2])  # sort by total_received
        for addr, bal_sat, recv_sat, txs in funded[:20]:
            recv_btc = recv_sat / 100_000_000
            print(f"  {addr}  -> received={recv_btc:.8f} BTC, {txs} txs (now empty)")

    if not funded:
        print("No addresses with any history (received=0 for all).")
        print("This wallet appears to be unused.")

    print()
    print(f"Results saved to: {out_path.resolve()}")


if __name__ == "__main__":
    main()
