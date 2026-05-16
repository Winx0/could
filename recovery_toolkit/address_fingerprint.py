#!/usr/bin/env python3
"""
Bitcoin Address Fingerprint Tool
=================================
Analyzes a Bitcoin address by examining its "sister addresses" (other
recipients in the same funding transaction) to infer which wallet
software/service likely generated it.

How it works:
  1. Fetch funding transaction(s) for target address
  2. Get all OTHER outputs (sister addresses) in same tx
  3. For each sister, trace where their BTC was spent (if spent)
  4. Classify each spend destination by clustering it with known
     hot wallets (exchanges, custodial services)
  5. Aggregate distribution -> probability inference

Why this works:
  Mining pools, mixers, and airdrops typically pay batches of users
  who share demographic/behavioral patterns. If 60% of sister addresses
  funnel BTC to Binance, target user is likely also a Binance user.

USAGE:
  python address_fingerprint.py 1B8hgFxNK7ac2k5EtrAanxQPFcnfHLMcko

OUTPUT:
  - Distribution of spend destinations
  - Probability inference for wallet software / service

ETHICS:
  Uses only PUBLIC blockchain data. Does not access private keys.
  For your own address recovery investigation.
"""
import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

# Public APIs - no key needed
MEMPOOL_TX = "https://mempool.space/api/tx/{txid}"
MEMPOOL_ADDR = "https://mempool.space/api/address/{addr}"
MEMPOOL_ADDR_TXS = "https://mempool.space/api/address/{addr}/txs"

# Address patterns
LEGACY_PATTERN = re.compile(r'^1[1-9A-HJ-NP-Za-km-z]{25,33}$')
P2SH_PATTERN = re.compile(r'^3[1-9A-HJ-NP-Za-km-z]{25,33}$')
BECH32_PATTERN = re.compile(r'^bc1[a-z0-9]{38,87}$')


# =============================================================================
# Known service hot wallet address prefixes (from public blockchain analytics)
# These are well-documented exchange/service wallets we can match against
# =============================================================================
KNOWN_LABELS = {
    # Binance hot wallets (from on-chain clustering)
    "1NDyJtNTjmwk5xPNhjgAMu4HDHigtobu1s": "Binance",
    "bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h": "Binance Cold",
    "34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo": "Binance",
    "1LQv8aKtQoiY5M5zkaG8RWL7LMwNzVaVqR": "Binance",

    # Coinbase
    "3Cbq7aT1tY8kMxWLbitaG7yT6bPbKChq64": "Coinbase",
    "1FxkfJQLJTXpW6QmxGT6oF43ZH959ns8Cq": "Coinbase Pro",
    "1JhfvUSQHLGAJZTjFnpAjvP4z4zr6yePcb": "Coinbase",
    "bc1qd0z2kmphukmls0vrwh3wdwrjk5j5p7a4f9d6c4": "Coinbase",

    # Indodax (Indonesia exchange)
    "3LVXmJL7HuW8JGXfwNqPZSTC1ahoFJaBpo": "Indodax",
    "32EzGNNkuHWbmSBL6XpuuLCJjYXrTLhU4N": "Indodax",

    # Tokocrypto/Binance Indonesia
    "bc1qjasf9z3h7w3jspkhtgatgpyvvzgpa0duxwczd2": "Tokocrypto",

    # Kraken
    "3FupZp77ySr7jwoLYEJ9mwzJpvoNBXsBnE": "Kraken",
    "bc1qa5wkgaew2dkv56kfvj49j0av5nml45x9ek9hz6": "Kraken",

    # Bitfinex
    "1NRgC4ChMnjvHd4KgGm9JJWpbhNGFEKBz1": "Bitfinex",
    "bc1qgdjqv0av3q56jvd82tkdjpy7gdp9ut8tlqmgrpmv24sq90ecnvqqjwvw97": "Bitfinex",

    # OKX
    "1FzWLkAahHooV3kzTgyx6qsswXJ6sCXkSR": "OKX",

    # Huobi
    "1HckjUpRGcrrRAtFaaCAUaGjsPx9oYmLaZ": "Huobi",

    # Blockchain.com hot wallets (from leaked clustering data)
    "1HQ3Go3ggs8pFnXuHVHRytPCq5fGG8Hbhx": "Blockchain.com",
    "1NTMakcgVwQpMdGxRQnFKyb3G1FAJysSfz": "Blockchain.com",

    # Common known mixers (historic)
    "bc1q7cyrfmck2ffu2ud3rn5l5a8yv6f0chkp0zpemf": "Wasabi CoinJoin",
}

# Common service patterns based on transaction features
SERVICE_PATTERNS = {
    'binance_bulk': {
        'description': 'Binance bulk withdrawal pattern',
        'indicators': ['many_outputs', 'segwit_change'],
    },
    'coinbase_payout': {
        'description': 'Coinbase batch payout',
        'indicators': ['p2sh_segwit_outputs'],
    },
    'mining_pool': {
        'description': 'Mining pool batch payout',
        'indicators': ['many_outputs_small_amounts'],
    },
}


def fetch_json(url, timeout=15, retries=3):
    """Fetch JSON from URL with retry."""
    for attempt in range(retries):
        try:
            req = urllib.request.Request(
                url,
                headers={'User-Agent': 'fingerprint-tool/1.0'}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code == 429:
                time.sleep(15)  # rate limit cooldown
                continue
            if attempt < retries - 1:
                time.sleep(2)
                continue
            return None
        except Exception:
            if attempt < retries - 1:
                time.sleep(2)
                continue
            return None
    return None


def get_funding_tx(addr):
    """Get the first transaction that funded this address."""
    print(f"  Fetching tx history for {addr}...")
    txs = fetch_json(MEMPOOL_ADDR_TXS.format(addr=addr))
    if not txs:
        return None
    # Find oldest tx where this address is in vout (received)
    funding_txs = []
    for tx in reversed(txs):  # oldest first
        for vout in tx.get('vout', []):
            if vout.get('scriptpubkey_address') == addr:
                funding_txs.append(tx)
                break
    if funding_txs:
        return funding_txs[0]
    return None


def get_sister_addresses(funding_tx, target_addr):
    """Extract all OTHER output addresses from funding transaction."""
    sisters = []
    for vout in funding_tx.get('vout', []):
        addr = vout.get('scriptpubkey_address')
        if addr and addr != target_addr:
            sisters.append({
                'address': addr,
                'value_sat': vout.get('value', 0),
                'script_type': vout.get('scriptpubkey_type', 'unknown'),
            })
    return sisters


def classify_address(addr):
    """Determine address type based on prefix."""
    if not addr:
        return 'unknown'
    if LEGACY_PATTERN.match(addr):
        return 'legacy_p2pkh'
    if P2SH_PATTERN.match(addr):
        return 'p2sh_segwit'
    if BECH32_PATTERN.match(addr):
        return 'native_segwit'
    return 'unknown'


def trace_spend_destination(addr, max_hops=2):
    """
    For an address that has been spent FROM, find where it sent BTC.
    Returns list of destination addresses (from first spending tx).
    """
    txs = fetch_json(MEMPOOL_ADDR_TXS.format(addr=addr))
    if not txs:
        return None, None

    # Find first tx where THIS addr is in vin (spent FROM)
    for tx in reversed(txs):  # oldest first
        for vin in tx.get('vin', []):
            prevout = vin.get('prevout', {})
            if prevout.get('scriptpubkey_address') == addr:
                # This tx spent from our addr
                destinations = []
                for vout in tx.get('vout', []):
                    dest = vout.get('scriptpubkey_address')
                    if dest and dest != addr:  # exclude change back to self
                        destinations.append({
                            'address': dest,
                            'value_sat': vout.get('value', 0),
                            'script_type': vout.get('scriptpubkey_type', 'unknown'),
                        })
                return tx.get('txid'), destinations
    return None, None  # never spent


def label_destination(dest_addr):
    """Label a destination address with known service if possible."""
    if dest_addr in KNOWN_LABELS:
        return KNOWN_LABELS[dest_addr]
    # Could extend with API call to WalletExplorer, etc.
    return None


def fingerprint_analysis(target_addr, sample_size=50, delay=1.5):
    """Main analysis pipeline."""
    print("=" * 70)
    print("ADDRESS FINGERPRINT ANALYSIS")
    print("=" * 70)
    print(f"Target: {target_addr}")
    print(f"Format: {classify_address(target_addr)}")
    print()

    # Step 1: Get funding transaction
    print("Step 1: Fetching funding transaction...")
    funding_tx = get_funding_tx(target_addr)
    if not funding_tx:
        print("ERROR: Could not fetch funding tx")
        return None

    funding_txid = funding_tx.get('txid', '?')
    print(f"  Funding TXID: {funding_txid}")
    print(f"  Outputs in tx: {len(funding_tx.get('vout', []))}")
    print(f"  Inputs in tx: {len(funding_tx.get('vin', []))}")
    print()

    # Step 2: Get sister addresses
    print("Step 2: Extracting sister addresses...")
    sisters = get_sister_addresses(funding_tx, target_addr)
    print(f"  Total sisters: {len(sisters)}")

    # Distribution of script types in sisters
    sister_script_types = Counter(s['script_type'] for s in sisters)
    print(f"  Sister address types:")
    for stype, count in sister_script_types.most_common():
        print(f"    {stype}: {count}")

    # Distribution of amounts
    amounts = [s['value_sat'] / 1e8 for s in sisters]
    if amounts:
        print(f"  Amount distribution: "
              f"min={min(amounts):.8f}, "
              f"max={max(amounts):.8f}, "
              f"avg={sum(amounts)/len(amounts):.8f} BTC")
    print()

    # Step 3: Sample N sister addresses for spend tracing
    if len(sisters) > sample_size:
        print(f"Step 3: Tracing spend for {sample_size} sample sister addresses...")
        # Take spread sample (every Nth + first/last)
        step = max(1, len(sisters) // sample_size)
        sample = sisters[::step][:sample_size]
    else:
        print(f"Step 3: Tracing spend for all {len(sisters)} sisters...")
        sample = sisters

    print(f"  (delay={delay}s per request to respect API rate limits)")
    print()

    spend_results = []
    spent_count = 0
    unspent_count = 0
    destination_labels = Counter()
    destination_script_types = Counter()
    unique_destinations = set()

    for i, sister in enumerate(sample, 1):
        if i % 5 == 0:
            print(f"  ... traced {i}/{len(sample)} | "
                  f"spent={spent_count} unspent={unspent_count}")
        addr = sister['address']
        spend_txid, destinations = trace_spend_destination(addr)
        time.sleep(delay)

        if destinations is None:
            unspent_count += 1
            spend_results.append({
                'sister': addr,
                'spent': False,
            })
        else:
            spent_count += 1
            for dest in destinations:
                dest_addr = dest['address']
                unique_destinations.add(dest_addr)
                destination_script_types[dest['script_type']] += 1
                label = label_destination(dest_addr)
                if label:
                    destination_labels[label] += 1
                else:
                    destination_labels['Unlabeled'] += 1
            spend_results.append({
                'sister': addr,
                'spent': True,
                'spend_txid': spend_txid,
                'destinations': destinations,
            })

    print()

    # Step 4: Aggregate analysis
    print("=" * 70)
    print("FINGERPRINT REPORT")
    print("=" * 70)
    print()
    print(f"Sample size: {len(sample)} of {len(sisters)} sister addresses")
    print(f"Spent (have outgoing tx): {spent_count}")
    print(f"Still unspent (HODL): {unspent_count}")
    print(f"Unique destination addresses: {len(unique_destinations)}")
    print()

    if spent_count == 0:
        print("WARNING: All sample sisters are UNSPENT.")
        print("This is a strong signal that source is mining pool / airdrop")
        print("(many users HODL their small payouts).")
        print()
    else:
        print("DESTINATION SCRIPT TYPES (where sisters spent BTC):")
        for stype, count in destination_script_types.most_common():
            pct = count / sum(destination_script_types.values()) * 100
            print(f"  {stype:25s} {count:5d} ({pct:.1f}%)")
        print()

        print("DESTINATION SERVICE LABELS:")
        total_labeled = sum(destination_labels.values())
        for label, count in destination_labels.most_common():
            pct = count / total_labeled * 100 if total_labeled else 0
            print(f"  {label:25s} {count:5d} ({pct:.1f}%)")
        print()

    # Step 5: Inference
    print("=" * 70)
    print("PROBABILITY INFERENCE")
    print("=" * 70)
    print()

    # Heuristic scoring
    scores = {
        'Trust Wallet (mobile)': 0,
        'Blockchain.com': 0,
        'Mining pool payout (NiceHash, F2Pool)': 0,
        'Mixer service (ChipMixer, Wasabi)': 0,
        'Exchange withdrawal (Binance/Coinbase)': 0,
        'Paper/brain wallet': 0,
        'Other custodial service': 0,
    }

    # Heuristic 1: Format compatibility
    target_fmt = classify_address(target_addr)
    if target_fmt == 'legacy_p2pkh':
        # Legacy compatible with all wallets
        scores['Blockchain.com'] += 10
        scores['Trust Wallet (mobile)'] += 5
        scores['Paper/brain wallet'] += 10
        scores['Other custodial service'] += 5
    elif target_fmt == 'p2sh_segwit':
        scores['Trust Wallet (mobile)'] += 15
        scores['Blockchain.com'] += 10
    elif target_fmt == 'native_segwit':
        scores['Trust Wallet (mobile)'] += 5

    # Heuristic 2: Number of outputs in funding tx
    n_outputs = len(funding_tx.get('vout', []))
    if n_outputs >= 100:
        scores['Mining pool payout (NiceHash, F2Pool)'] += 30
        scores['Mixer service (ChipMixer, Wasabi)'] += 20
    elif n_outputs >= 20:
        scores['Mining pool payout (NiceHash, F2Pool)'] += 15
        scores['Exchange withdrawal (Binance/Coinbase)'] += 10

    # Heuristic 3: Unspent ratio of sisters
    if spent_count + unspent_count > 0:
        unspent_ratio = unspent_count / (spent_count + unspent_count)
        if unspent_ratio > 0.7:
            # Most sisters HODL = small payout pattern
            scores['Mining pool payout (NiceHash, F2Pool)'] += 15
            scores['Paper/brain wallet'] += 10
        elif unspent_ratio < 0.3:
            # Most sisters spent = active traders
            scores['Exchange withdrawal (Binance/Coinbase)'] += 10
            scores['Trust Wallet (mobile)'] += 5

    # Heuristic 4: Destination labels
    bc_dest = destination_labels.get('Blockchain.com', 0)
    if bc_dest > 5:
        scores['Blockchain.com'] += bc_dest * 3

    binance_dest = destination_labels.get('Binance', 0)
    if binance_dest > 5:
        scores['Exchange withdrawal (Binance/Coinbase)'] += binance_dest * 3

    coinbase_dest = destination_labels.get('Coinbase', 0)
    if coinbase_dest > 5:
        scores['Exchange withdrawal (Binance/Coinbase)'] += coinbase_dest * 3

    # Heuristic 5: Destination script type analysis
    legacy_dest = destination_script_types.get('p2pkh', 0)
    segwit_dest = destination_script_types.get('p2wpkh', 0)
    if segwit_dest > legacy_dest * 2:
        # Mostly segwit destinations = modern users
        scores['Trust Wallet (mobile)'] += 5
        scores['Exchange withdrawal (Binance/Coinbase)'] += 5

    # Normalize to %
    total = sum(scores.values()) or 1
    print("Inference (probability based on heuristics):")
    print()
    sorted_scores = sorted(scores.items(), key=lambda x: -x[1])
    for service, score in sorted_scores:
        pct = score / total * 100
        bar = '█' * int(pct / 2)
        print(f"  {service:45s} {pct:5.1f}% {bar}")
    print()

    # Strongest hypothesis
    top = sorted_scores[0]
    print(f"STRONGEST HYPOTHESIS: {top[0]} ({top[1] / total * 100:.1f}%)")
    print()

    return {
        'target': target_addr,
        'funding_txid': funding_txid,
        'sister_count': len(sisters),
        'sample_size': len(sample),
        'spent_count': spent_count,
        'unspent_count': unspent_count,
        'destination_labels': dict(destination_labels),
        'destination_script_types': dict(destination_script_types),
        'inference_scores': scores,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Fingerprint Bitcoin address by analyzing sister addresses"
    )
    parser.add_argument('address', help='Target Bitcoin address')
    parser.add_argument('--sample-size', type=int, default=50,
                        help='Number of sister addresses to trace (default 50)')
    parser.add_argument('--delay', type=float, default=1.5,
                        help='Seconds between API requests (default 1.5)')
    parser.add_argument('--output', default='fingerprint_report.json',
                        help='Save full report as JSON')
    args = parser.parse_args()

    if classify_address(args.address) == 'unknown':
        print(f"ERROR: '{args.address}' is not a valid Bitcoin address")
        sys.exit(1)

    result = fingerprint_analysis(args.address, args.sample_size, args.delay)

    if result:
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2, default=str)
        print(f"Full report saved to: {Path(args.output).resolve()}")


if __name__ == '__main__':
    main()
