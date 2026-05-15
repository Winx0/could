#!/usr/bin/env python3
"""
BIP39 Puzzle Solver
====================
Solves BIP39 mnemonic puzzles by trying combinations of candidate words and
all valid orderings, then checking against a target Bitcoin address.

Designed for PUBLIC BOUNTY puzzles where:
  - You have N candidate words extracted from puzzle clues
  - You don't know the order
  - Some slots may be unknown (need to be brute-forced from BIP39 wordlist)
  - You have a target address that valid mnemonic must derive

USAGE:
  # Mode 1: All 12 words known, just need to permute order
  python bip39_puzzle_solver.py \\
      --known moon,tower,food,this,subject,real,black,only,breeze,coin,two,second \\
      --target 1KfZGvwZxsvSmemoCmEV75uqcNzYBHjkHZ

  # Mode 2: 9 known + 3 unknown slots from a candidate pool
  python bip39_puzzle_solver.py \\
      --known moon,tower,food,this,subject,real,black,only,breeze \\
      --candidates coin,two,second,gold,three,eight,twenty \\
      --slots 3 \\
      --target 1KfZGvwZxsvSmemoCmEV75uqcNzYBHjkHZ

  # Mode 3: 11 known + 1 unknown (full BIP39 wordlist for missing)
  python bip39_puzzle_solver.py \\
      --known moon,tower,food,this,subject,real,black,only,breeze,coin,two \\
      --slots 1 \\
      --target 1KfZGvwZxsvSmemoCmEV75uqcNzYBHjkHZ

PERFORMANCE NOTES:
  - 12 known + permute: ~100 minutes feasible
  - 11 known + 1 missing + permute: ~54000 hours (GPU recommended)
  - For >1 missing slot, narrow candidates first via puzzle hints

ETHICS:
  Use ONLY on PUBLIC bounty puzzles where the funds are intended for
  whoever solves them. Examples: 0.2 BTC BLM puzzle (stsh_n, Oct 2020,
  posted on Reddit, listed on privatekeys.pw).
"""

import argparse
import itertools
import sys
import time
from pathlib import Path

try:
    from mnemonic import Mnemonic
    from bip_utils import (
        Bip39SeedGenerator, Bip39MnemonicValidator, Bip39Languages,
        Bip44, Bip44Coins, Bip44Changes,
        Bip49, Bip49Coins,
        Bip84, Bip84Coins,
        Bip32Slip10Secp256k1,
        Secp256k1PublicKey,
        P2PKHAddrEncoder,
    )
except ImportError:
    print("ERROR: pip install mnemonic bip_utils")
    sys.exit(1)


def derive_first_address_fast(mnemonic):
    """Fast derive ONLY the first BIP44 receive address (most common).
    Returns single address string. ~10x faster than multi-path derive.
    """
    seed = Bip39SeedGenerator(mnemonic).Generate("")
    ctx = Bip44.FromSeed(seed, Bip44Coins.BITCOIN)
    return ctx.Purpose().Coin().Account(0).Change(
        Bip44Changes.CHAIN_EXT
    ).AddressIndex(0).PublicKey().ToAddress()


def derive_addresses(mnemonic, max_per_path=3):
    """Derive addresses across major BIPs (slower, more thorough).
    Returns set of addresses for comparison.
    """
    seed = Bip39SeedGenerator(mnemonic).Generate("")
    addrs = set()

    try:
        ctx44 = Bip44.FromSeed(seed, Bip44Coins.BITCOIN)
        for change in (Bip44Changes.CHAIN_EXT,):
            for i in range(max_per_path):
                addrs.add(
                    ctx44.Purpose().Coin().Account(0).Change(change)
                    .AddressIndex(i).PublicKey().ToAddress()
                )
    except Exception:
        pass

    try:
        ctx49 = Bip49.FromSeed(seed, Bip49Coins.BITCOIN)
        for change in (Bip44Changes.CHAIN_EXT,):
            for i in range(max_per_path):
                addrs.add(
                    ctx49.Purpose().Coin().Account(0).Change(change)
                    .AddressIndex(i).PublicKey().ToAddress()
                )
    except Exception:
        pass

    try:
        ctx84 = Bip84.FromSeed(seed, Bip84Coins.BITCOIN)
        for change in (Bip44Changes.CHAIN_EXT,):
            for i in range(max_per_path):
                addrs.add(
                    ctx84.Purpose().Coin().Account(0).Change(change)
                    .AddressIndex(i).PublicKey().ToAddress()
                )
    except Exception:
        pass

    try:
        ctx32 = Bip32Slip10Secp256k1.FromSeed(seed)
        for branch in (0,):
            for i in range(max_per_path):
                node = ctx32.DerivePath(f"m/{branch}/{i}")
                pubkey_bytes = node.PublicKey().RawCompressed().ToBytes()
                addr = P2PKHAddrEncoder.EncodeKey(
                    Secp256k1PublicKey.FromBytes(pubkey_bytes),
                    net_ver=b'\x00',
                )
                addrs.add(addr)
    except Exception:
        pass

    return addrs


def main():
    parser = argparse.ArgumentParser(description="BIP39 Mnemonic Puzzle Solver")
    parser.add_argument("--known", required=True,
                        help="Comma-separated known words")
    parser.add_argument("--candidates", default="",
                        help="Comma-separated candidate pool for unknown slots")
    parser.add_argument("--slots", type=int, default=0,
                        help="Number of unknown slots (0 = just permute known)")
    parser.add_argument("--target", required=True,
                        help="Target Bitcoin address to match")
    parser.add_argument("--length", type=int, default=12,
                        help="Total mnemonic length (default 12)")
    parser.add_argument("--max-per-path", type=int, default=3,
                        help="Address indexes to derive per BIP path (default 3)")
    parser.add_argument("--fast", action="store_true",
                        help="Fast mode: only check first BIP44 receive address (10x faster)")
    parser.add_argument("--output", default="puzzle_solution.txt",
                        help="Save solution to this file")
    args = parser.parse_args()

    known = [w.strip().lower() for w in args.known.split(",") if w.strip()]
    candidates = [w.strip().lower() for w in args.candidates.split(",") if w.strip()]

    mnemo = Mnemonic("english")
    wl = set(mnemo.wordlist)

    print("=" * 70)
    print("BIP39 PUZZLE SOLVER")
    print("=" * 70)
    print(f"Known words ({len(known)}): {known}")
    print(f"Target address: {args.target}")
    print(f"Total length: {args.length}")
    print(f"Unknown slots: {args.slots}")
    if candidates:
        print(f"Candidate pool ({len(candidates)}): {candidates}")
    print()

    # Validate known words against BIP39
    invalid = [w for w in known if w not in wl]
    if invalid:
        print(f"ERROR: These known words are NOT in BIP39: {invalid}")
        sys.exit(1)
    print(f"All {len(known)} known words are valid BIP39")

    if candidates:
        cand_invalid = [w for w in candidates if w not in wl]
        if cand_invalid:
            print(f"WARNING: These candidates are NOT in BIP39 (skipped): {cand_invalid}")
            candidates = [w for w in candidates if w in wl]

    # Sanity check
    if len(known) + args.slots != args.length:
        print(f"ERROR: known({len(known)}) + slots({args.slots}) != length({args.length})")
        sys.exit(1)

    validator = Bip39MnemonicValidator(Bip39Languages.ENGLISH)
    target = args.target

    # Build the slot fillers
    if args.slots == 0:
        slot_combinations = [tuple()]
    elif candidates:
        # Combinations from candidate pool (without replacement)
        slot_combinations = list(itertools.combinations(candidates, args.slots))
        print(f"Slot fill combinations from candidates: {len(slot_combinations)}")
    else:
        # Full BIP39 brute force (might be very slow for >1 slot)
        if args.slots > 1:
            print(f"WARNING: {args.slots} slots × 2048^{args.slots} = {2048**args.slots:,}")
            confirm = input("This may take very long. Continue? (yes/no): ").strip().lower()
            if confirm not in ('yes', 'y'):
                sys.exit(0)
        slot_combinations = list(itertools.combinations(sorted(wl), args.slots))
        print(f"Full BIP39 slot combinations: {len(slot_combinations):,}")

    # For each slot combination, create the candidate word set, then permute
    total_word_sets = len(slot_combinations)
    print(f"\nWord sets to test: {total_word_sets:,}")
    print(f"Permutations per set: {args.length}! / 16 (only ~1/16 pass checksum)")
    print(f"Estimated total tests: {total_word_sets * 30_000_000 // 16:,}")
    print()
    print("Starting search...")
    print()

    start = time.time()
    perms_tested = 0
    valid_mnemonics = 0
    last_print = start

    for set_idx, slot_words in enumerate(slot_combinations):
        word_set = list(known) + list(slot_words)

        for perm in itertools.permutations(word_set):
            perms_tested += 1
            phrase = " ".join(perm)

            try:
                if not validator.IsValid(phrase):
                    continue
            except Exception:
                continue

            valid_mnemonics += 1

            # Derive address(es) for comparison
            try:
                if args.fast:
                    first_addr = derive_first_address_fast(phrase)
                    matched = (first_addr == target)
                    addrs = {first_addr}
                else:
                    addrs = derive_addresses(phrase, args.max_per_path)
                    matched = (target in addrs)
            except Exception:
                continue

            if matched:
                elapsed = time.time() - start
                print()
                print("=" * 70)
                print("    SOLUTION FOUND!")
                print("=" * 70)
                print(f"Mnemonic: {phrase}")
                print(f"Time elapsed: {elapsed:.1f}s")
                print(f"Permutations tested: {perms_tested:,}")
                print(f"Valid mnemonics found: {valid_mnemonics:,}")
                print()
                print("Verify by importing this mnemonic into Electrum / Sparrow")
                print(f"and checking that {target} appears in the wallet addresses.")
                print()

                with open(args.output, 'w') as f:
                    f.write(f"BIP39 Puzzle Solution\n")
                    f.write(f"=====================\n")
                    f.write(f"Target address: {target}\n")
                    f.write(f"Mnemonic: {phrase}\n")
                    f.write(f"Found at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Time elapsed: {elapsed:.1f}s\n")
                    f.write(f"Permutations tested: {perms_tested:,}\n")
                print(f"Solution saved to: {Path(args.output).resolve()}")
                sys.exit(0)

            now = time.time()
            if now - last_print > 5:
                rate = perms_tested / (now - start)
                pct_done = (set_idx + 1) / total_word_sets * 100 if total_word_sets > 1 else perms_tested / 30_000_000 * 100
                print(f"  ... set {set_idx+1}/{total_word_sets} | "
                      f"perms={perms_tested:,} | valid={valid_mnemonics:,} | "
                      f"{rate:,.0f}/s | progress~{pct_done:.2f}%")
                last_print = now

    elapsed = time.time() - start
    print()
    print("=" * 70)
    print("SEARCH COMPLETE - No solution found")
    print("=" * 70)
    print(f"Time elapsed: {elapsed:.1f}s ({elapsed/60:.1f} min)")
    print(f"Permutations tested: {perms_tested:,}")
    print(f"Valid mnemonics tested against target: {valid_mnemonics:,}")
    print()
    print("Possible reasons:")
    print("  - Target address derived from non-standard path/index")
    print("  - One or more known words is wrong")
    print("  - Need to expand candidate pool for unknown slots")
    print("  - Mnemonic length is not 12 (try 15, 18, 21, 24)")


if __name__ == "__main__":
    main()
