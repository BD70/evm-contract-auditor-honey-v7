#!/usr/bin/env python3
"""
evm-decon: EVM Bytecode Deconstructor CLI

Converts raw EVM smart contract bytecode into a structured,
human-readable format optimized for pattern matching and analysis.

Usage:
    python -m evm_decon --hex 0x6080604052...
    python -m evm_decon --file contract.bin
    python -m evm_decon --file contract.bin --format semantic
    python -m evm_decon --file contract.bin --format json
"""

from __future__ import annotations
import argparse
import sys

from .pipeline import (
    BytecodeInputError,
    PipelineOptions,
    analyze_bytecode,
    load_bytecode_from_file,
    render_output,
)


def main() -> int:
    from evm_core.deprecation import emit_soft_deprecation
    emit_soft_deprecation("evm_decon")
    parser = argparse.ArgumentParser(
        prog="evm-decon",
        description="EVM Bytecode Deconstructor — Convert hex bytecode to structured analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 -m evm_decon --hex 0x6080604052348015...
  python3 -m evm_decon --file contract.bin --format semantic
  python3 -m evm_decon --file contract.bin --format json
  python3 -m evm_decon --file contract.bin --format json --no-resolve
        """,
    )

    # Input sources (mutually exclusive)
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "--hex",
        type=str,
        help="Raw bytecode hex string (with or without 0x prefix)",
    )
    input_group.add_argument(
        "--file",
        type=str,
        help="Path to file containing bytecode hex",
    )

    # Output options
    parser.add_argument(
        "--format", "-f",
        choices=["json", "semantic"],
        default="semantic",
        help="Output format: semantic human report or json audit behavior document (default: semantic)",
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        help="Write output to file instead of stdout",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Include raw views (pseudocode, loops, boilerplate) in semantic output",
    )
    parser.add_argument(
        "--debug-dump",
        action="store_true",
        help="Internal development only: emit raw diagnostic analysis JSON instead of the production audit JSON",
    )
    parser.add_argument(
        "--profiles-dir",
        "--profile-dir",
        dest="profile_dirs",
        metavar="DIR",
        action="append",
        default=[],
        help=(
            "Directory containing contract profile JSON files. "
            "Every *.json file is loaded recursively. Can be passed multiple times."
        ),
    )
    parser.add_argument(
        "--no-profiles",
        action="store_true",
        help="Disable default data profile loading.",
    )

    # Analysis options
    parser.add_argument(
        "--no-resolve",
        action="store_true",
        help="Skip 4byte.directory API calls (offline mode)",
    )
    parser.add_argument(
        "--no-blocks",
        action="store_true",
        help="Skip basic block analysis",
    )
    parser.add_argument(
        "--no-assembly",
        action="store_true",
        help="Skip full assembly listing in output",
    )
    parser.add_argument(
        "--no-deep",
        action="store_true",
        help="Skip deep analysis (stack sim, CFG, pseudocode)",
    )

    args = parser.parse_args()

    try:
        bytecode_hex = args.hex if args.hex else load_bytecode_from_file(args.file)
        options = PipelineOptions(
            no_resolve=args.no_resolve,
            no_profiles=args.no_profiles,
            profile_dirs=args.profile_dirs or [],
            no_blocks=args.no_blocks,
            no_assembly=args.no_assembly,
            no_deep=args.no_deep,
            verbose=args.verbose,
            debug_dump=args.debug_dump,
        )
        is_quiet = args.format == "json"
        progress = None if is_quiet else lambda message: print(f"  {message}", file=sys.stderr)
        artifacts = analyze_bytecode(bytecode_hex, options=options, progress=progress)
        result = render_output(artifacts, args.format, options)
    except BytecodeInputError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.output:
        with open(args.output, "w") as f:
            f.write(result)
        print(f"\n  ✅ Output written to {args.output}", file=sys.stderr)
        return 0

    if not is_quiet:
        print("", file=sys.stderr)
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
