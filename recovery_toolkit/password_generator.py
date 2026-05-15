#!/usr/bin/env python3
"""
Bitcoin Wallet Recovery - Password Candidate Generator
=======================================================
Generates a list of password candidates from base words you remember.

USAGE:
  python password_generator.py
  Then follow prompts. Output saved to candidates.txt

EXAMPLE INPUT:
  Base words: john, password, bitcoin
  Numbers/years: 1990, 2020, 123, 1234
  Symbols: !, @, #
  
EXAMPLE OUTPUT (candidates.txt):
  john
  John
  john1990
  John1990!
  password2020
  bitcoin@123
  ... etc (thousands of variations)
"""

import itertools
import sys
from pathlib import Path


def case_variations(word: str) -> list:
    """Return common case variations: lower, Title, UPPER, lEET."""
    if not word:
        return [""]
    variations = {
        word.lower(),
        word.upper(),
        word.capitalize(),
        word,  # original
    }
    # Common leet substitutions (limited to avoid explosion)
    leet = word.lower()
    for src, dst in [('a', '@'), ('e', '3'), ('i', '1'), ('o', '0'), ('s', '$')]:
        leet = leet.replace(src, dst)
    if leet != word.lower():
        variations.add(leet)
    return list(variations)


def generate_candidates(
    base_words: list,
    numbers: list,
    symbols: list,
    use_two_word_combos: bool = True,
    max_candidates: int = 200000,
) -> set:
    """Generate password candidates by combining base words, numbers, symbols."""
    cands = set()

    # 1. Base words alone (with case variations)
    for w in base_words:
        for cv in case_variations(w):
            cands.add(cv)

    # 2. word + number
    for w in base_words:
        for n in numbers:
            for cv in case_variations(w):
                cands.add(f"{cv}{n}")
                cands.add(f"{n}{cv}")

    # 3. word + number + symbol
    for w in base_words:
        for n in numbers:
            for s in symbols:
                for cv in case_variations(w):
                    cands.add(f"{cv}{n}{s}")
                    cands.add(f"{cv}{s}{n}")
                    cands.add(f"{s}{cv}{n}")

    # 4. word + symbol
    for w in base_words:
        for s in symbols:
            for cv in case_variations(w):
                cands.add(f"{cv}{s}")
                cands.add(f"{s}{cv}")

    # 5. Two-word combos
    if use_two_word_combos and len(base_words) >= 2:
        for w1, w2 in itertools.permutations(base_words, 2):
            for cv1 in case_variations(w1):
                for cv2 in case_variations(w2):
                    cands.add(f"{cv1}{cv2}")
                    for n in numbers:
                        cands.add(f"{cv1}{cv2}{n}")
                        cands.add(f"{cv1}{n}{cv2}")
                    for s in symbols:
                        cands.add(f"{cv1}{s}{cv2}")
                        cands.add(f"{cv1}{cv2}{s}")
                    if len(cands) > max_candidates:
                        return cands

    return cands


def main():
    print("=" * 70)
    print("  PASSWORD CANDIDATE GENERATOR")
    print("=" * 70)
    print("Tujuan: bikin file daftar password kemungkinan untuk brute-force")
    print()
    print("TIPS untuk recall password 2020:")
    print("  - Pikirkan password yang Anda PAKAI di service lain di tahun itu")
    print("  - Nama pet, nama pasangan, kombinasi tanggal lahir")
    print("  - Pattern khas Anda (suka ada '!' di belakang? prefix nama?)")
    print()

    print("\n[1/4] Base words (kata-kata yang mungkin ada di password Anda)")
    print("Contoh: bitcoin, john, password, mywallet, satoshi")
    print("Pisah dengan koma:")
    raw = input("> ").strip()
    base_words = [w.strip() for w in raw.split(",") if w.strip()]

    print("\n[2/4] Numbers/years (angka yang sering Anda pakai)")
    print("Contoh: 1990, 2020, 123, 1234, 12345, 666")
    print("Pisah dengan koma:")
    raw = input("> ").strip()
    numbers = [n.strip() for n in raw.split(",") if n.strip()]
    if not numbers:
        numbers = [""]  # so word-alone variations still appear

    print("\n[3/4] Symbols (simbol yang sering Anda pakai)")
    print("Default: ! @ # $ . _")
    print("Pisah dengan spasi (atau Enter untuk default):")
    raw = input("> ").strip()
    if raw:
        symbols = raw.split()
    else:
        symbols = ['!', '@', '#', '$', '.', '_']
    symbols.append("")  # also try without symbol

    print("\n[4/4] Output filename:")
    raw = input("> [candidates.txt]: ").strip()
    output_file = Path(raw or "candidates.txt")

    print("\nGenerating...")
    cands = generate_candidates(base_words, numbers, symbols)
    print(f"Generated {len(cands)} unique candidates")

    # Sort by length so shorter (more common) ones tried first
    sorted_cands = sorted(cands, key=lambda x: (len(x), x))
    with open(output_file, 'w') as f:
        for c in sorted_cands:
            f.write(c + "\n")

    print(f"\nSaved to: {output_file.resolve()}")
    print(f"\nNext step: python blockchain_decrypt.py wallet.aes.json --candidates {output_file}")


if __name__ == "__main__":
    main()
