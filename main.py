#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from eseal.client import DigiCertAPIError
from eseal.config import ConfigError, load_config
from eseal.lookup import HashEntryLookupError, format_hash_entry
from eseal.test_flow import run_test_mode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="DigiCert eSeal CSC API CLI",
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run test mode: list, info, authorize, sign/extend loop",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config.yaml"),
        help="Path to YAML config (default: config.yaml)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Extra debug output (e.g. SAD values in logs)",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=None,
        metavar="N",
        help="Override test.loop_iterations from config (minimum 4)",
    )
    parser.add_argument(
        "--hashes-per-batch",
        type=int,
        default=None,
        metavar="N",
        help="Override test.hashes_per_batch from config",
    )
    parser.add_argument(
        "--get-hash-entry",
        type=int,
        metavar="N",
        default=None,
        help=(
            "Look up entry N (1-based) from aligned hashes.json and signatures.json"
        ),
    )
    args = parser.parse_args(argv)

    if args.get_hash_entry is not None:
        try:
            config = load_config(
                args.config,
                loop_iterations=args.iterations,
                hashes_per_batch=args.hashes_per_batch,
            )
        except ConfigError as e:
            print(f"Configuration error: {e}", file=sys.stderr)
            return 1
        try:
            print(format_hash_entry(config.test.state_dir, args.get_hash_entry))
        except HashEntryLookupError as e:
            print(f"Lookup error: {e}", file=sys.stderr)
            return 1
        return 0

    if not args.test:
        parser.print_help()
        print("\nExamples:")
        print("  python main.py --test --config config.yaml")
        print("  python main.py --get-hash-entry 26 --config config.yaml")
        return 1

    try:
        config = load_config(
            args.config,
            loop_iterations=args.iterations,
            hashes_per_batch=args.hashes_per_batch,
        )
    except ConfigError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        return 1

    if args.iterations is not None or args.hashes_per_batch is not None:
        t = config.test
        print(
            f"Using test sizing: {t.loop_iterations} iterations × "
            f"{t.hashes_per_batch} hashes/batch (CLI overrides)"
        )

    try:
        run_test_mode(config, verbose=True, debug=args.verbose)
    except DigiCertAPIError as e:
        print(f"API error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
