"""Isolated AIL adapter. Does not resolve domains or download suffix lists."""

import argparse
import math
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    # Use the installed, versioned PSL snapshot rather than silently changing
    # generation when an online suffix list changes or is unavailable.
    import tldextract
    tldextract.extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
    from ail_typo_squatting import runAll
    from .domains import parse_domains

    args.output.mkdir(parents=True, exist_ok=True)
    for seed in parse_domains(args.input.read_text(encoding="utf-8")):
        runAll(seed, math.inf, "text", str(args.output), keeporiginal=True)


if __name__ == "__main__":
    main()
