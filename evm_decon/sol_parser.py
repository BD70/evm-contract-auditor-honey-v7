"""
Solidity file parser for signature extraction.
"""

from __future__ import annotations
import re
from .keccak import get_selector

TYPE_ALIASES = {
    "uint": "uint256",
    "int": "int256",
    "byte": "bytes1"
}

# Matches "function FuncName(type name, type name)"
FUNC_REGEX = re.compile(r'\b(?:function)\s+([a-zA-Z0-9_]+)\s*\(([^)]*)\)')

def normalize_type(raw_type: str) -> str:
    """
    Given 'uint256 memory x' -> 'uint256'
    """
    for mod in [" memory", " storage", " calldata", " indexed"]:
        raw_type = raw_type.replace(mod, "")
    
    raw_type = raw_type.strip()
    if not raw_type:
        return ""
        
    parts = raw_type.split()
    if not parts:
        return ""
        
    type_part = parts[0]
    
    if len(parts) > 1 and parts[0] == "address" and parts[1].startswith("payable"):
        type_part = "address" + parts[1].replace("payable", "")
        
    base = type_part
    array_suffix = ""
    if "[" in type_part:
        idx = type_part.index("[")
        base = type_part[:idx]
        array_suffix = type_part[idx:]
        
    if base in TYPE_ALIASES:
        base = TYPE_ALIASES[base]
        
    return base + array_suffix

def extract_signatures_from_sol(source_code: str) -> dict[str, str]:
    """
    Given solidity source code, extracts functions their 
    computed 4-byte selectors.
    
    Returns map of hex_selector -> text_signature
    """
    signatures = {}
    
    # Strip comments to avoid false positives
    source_code = re.sub(r'//.*', '', source_code)
    source_code = re.sub(r'/\*.*?\*/', '', source_code, flags=re.DOTALL)
    
    matches = FUNC_REGEX.findall(source_code)
    for func_name, args_str in matches:
        args = []
        if args_str.strip():
            raw_args = args_str.split(',')
            for ra in raw_args:
                norm = normalize_type(ra)
                if norm:
                    args.append(norm)
                    
        text_sig = f"{func_name}({','.join(args)})"
        hex_sel = get_selector(text_sig)
        
        signatures[hex_sel] = text_sig
        
    return signatures
