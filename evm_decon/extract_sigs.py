"""
CLI entrypoint for extracting function signatures from Solidity files.
"""

from __future__ import annotations
import argparse
import os
import sys
from .sol_parser import extract_signatures_from_sol
from .sig_db import insert_signatures, get_db_stats

def process_file(filepath: str) -> int:
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading {filepath}: {e}", file=sys.stderr)
        return 0
        
    sigs = extract_signatures_from_sol(content)
    
    count = 0
    for hex_sig, text_sig in sigs.items():
        insert_signatures(hex_sig, [text_sig], source="local_extraction:" + os.path.basename(filepath))
        count += 1
        
    return count

def main():
    parser = argparse.ArgumentParser(description="Extract EVM signatures from Solidity files.")
    parser.add_argument("path", help="Path to a .sol file or directory")
    args = parser.parse_args()
    
    path = args.path
    if not os.path.exists(path):
        print(f"Error: Path does not exist: {path}", file=sys.stderr)
        sys.exit(1)
        
    print(f"Scanning {path} for signatures...")
    
    total_added = 0
    if os.path.isfile(path):
        total_added += process_file(path)
    elif os.path.isdir(path):
        for root, _, files in os.walk(path):
            for file in files:
                if file.endswith(".sol"):
                    total_added += process_file(os.path.join(root, file))
                    
    print(f"Extracted {total_added} function signatures from source.")
    print(f"Total entries in local SQLite database: {get_db_stats()}")

if __name__ == "__main__":
    main()
