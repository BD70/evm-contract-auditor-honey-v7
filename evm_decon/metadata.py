"""
Solidity CBOR metadata extractor.

Parses the CBOR-encoded metadata that Solidity appends at the end of runtime bytecode.
Extracts compiler version, IPFS/Swarm hash, and experimental flags.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Any
import struct


@dataclass
class CompilerInfo:
    name: str               # "solc", "vyper", "unknown"
    version: Optional[str]  # e.g. "0.8.20"
    raw_version: Optional[bytes]


@dataclass
class MetadataResult:
    found: bool
    compiler: Optional[CompilerInfo]
    hash_protocol: Optional[str]   # "ipfs", "bzzr0", "bzzr1"
    hash_value: Optional[str]      # hex-encoded hash
    cbor_length: int
    cbor_raw: Optional[bytes]
    metadata_start_offset: int     # byte offset where metadata begins
    experimental: bool
    raw_decoded: Optional[dict]    # full decoded CBOR map
    errors: list[str] = field(default_factory=list)


def _decode_cbor_simple(data: bytes) -> Optional[dict]:
    """
    Minimal CBOR map decoder — enough to handle Solidity metadata.

    We avoid the cbor2 dependency by implementing just enough CBOR
    decoding for the simple maps that Solidity produces.

    Solidity metadata is always a CBOR map with string keys and
    byte/string values. Format:
      a2 = map with 2 entries
      a3 = map with 3 entries
      64 = text string of length 4
      ...
    """
    if not data or len(data) < 2:
        return None

    try:
        pos = 0
        result = {}

        # First byte should be a map marker (0xa0 - 0xb7 for small maps)
        major = (data[pos] & 0xe0) >> 5  # top 3 bits
        additional = data[pos] & 0x1f     # bottom 5 bits

        if major != 5:  # Major type 5 = map
            return None

        num_pairs = additional
        pos += 1

        for _ in range(num_pairs):
            if pos >= len(data):
                break

            # Decode key (should be a text string, major type 3)
            key_major = (data[pos] & 0xe0) >> 5
            key_len = data[pos] & 0x1f

            if key_major != 3:  # Not a text string
                # Try byte string (major type 2)
                if key_major == 2:
                    key_len_actual = key_len
                    pos += 1
                    if pos + key_len_actual > len(data):
                        break
                    key = data[pos:pos + key_len_actual].decode("utf-8", errors="replace")
                    pos += key_len_actual
                else:
                    break
            else:
                if key_len <= 23:
                    key_len_actual = key_len
                    pos += 1
                elif key_len == 24:
                    pos += 1
                    key_len_actual = data[pos]
                    pos += 1
                else:
                    break

                if key_major == 3:
                    if pos + key_len_actual > len(data):
                        break
                    key = data[pos:pos + key_len_actual].decode("utf-8", errors="replace")
                    pos += key_len_actual

            # Decode value
            if pos >= len(data):
                break

            val_major = (data[pos] & 0xe0) >> 5
            val_additional = data[pos] & 0x1f

            if val_major == 2:  # Byte string
                if val_additional <= 23:
                    val_len = val_additional
                    pos += 1
                elif val_additional == 24:
                    pos += 1
                    val_len = data[pos]
                    pos += 1
                elif val_additional == 25:
                    pos += 1
                    val_len = struct.unpack(">H", data[pos:pos + 2])[0]
                    pos += 2
                else:
                    break

                if pos + val_len > len(data):
                    break
                result[key] = data[pos:pos + val_len]
                pos += val_len

            elif val_major == 3:  # Text string
                if val_additional <= 23:
                    val_len = val_additional
                    pos += 1
                elif val_additional == 24:
                    pos += 1
                    val_len = data[pos]
                    pos += 1
                else:
                    break

                if pos + val_len > len(data):
                    break
                result[key] = data[pos:pos + val_len].decode("utf-8", errors="replace")
                pos += val_len

            elif val_major == 7:  # Simple values (true/false/null)
                if val_additional == 20:
                    result[key] = False
                elif val_additional == 21:
                    result[key] = True
                elif val_additional == 22:
                    result[key] = None
                pos += 1

            elif val_major == 0:  # Unsigned integer
                if val_additional <= 23:
                    result[key] = val_additional
                    pos += 1
                elif val_additional == 24:
                    pos += 1
                    result[key] = data[pos]
                    pos += 1
                elif val_additional == 25:
                    pos += 1
                    result[key] = struct.unpack(">H", data[pos:pos + 2])[0]
                    pos += 2
                else:
                    pos += 1
            else:
                pos += 1

        return result if result else None

    except (IndexError, struct.error):
        return None


def extract_metadata(bytecode_hex: str) -> MetadataResult:
    """
    Extract Solidity compiler metadata from the end of bytecode.

    Solidity appends CBOR-encoded metadata at the end of runtime bytecode.
    The last 2 bytes indicate the length of the CBOR section.
    """
    # Normalize
    hex_str = bytecode_hex.strip()
    if hex_str.startswith("0x") or hex_str.startswith("0X"):
        hex_str = hex_str[2:]
    hex_str = hex_str.replace(" ", "").replace("\n", "")

    try:
        bytecode = bytes.fromhex(hex_str)
    except ValueError:
        return MetadataResult(
            found=False, compiler=None, hash_protocol=None,
            hash_value=None, cbor_length=0, cbor_raw=None,
            metadata_start_offset=0, experimental=False,
            raw_decoded=None, errors=["Invalid hex"]
        )

    if len(bytecode) < 4:
        return MetadataResult(
            found=False, compiler=None, hash_protocol=None,
            hash_value=None, cbor_length=0, cbor_raw=None,
            metadata_start_offset=0, experimental=False,
            raw_decoded=None, errors=["Bytecode too short for metadata"]
        )

    # Read last 2 bytes as CBOR length (big-endian)
    cbor_length = int.from_bytes(bytecode[-2:], "big")

    if cbor_length == 0 or cbor_length + 2 > len(bytecode):
        return MetadataResult(
            found=False, compiler=None, hash_protocol=None,
            hash_value=None, cbor_length=cbor_length, cbor_raw=None,
            metadata_start_offset=0, experimental=False,
            raw_decoded=None, errors=["CBOR length invalid or exceeds bytecode"]
        )

    # Extract CBOR data
    cbor_start = len(bytecode) - 2 - cbor_length
    cbor_data = bytecode[cbor_start:-2]

    # Verify it looks like a CBOR map (first byte should be 0xa1-0xa7)
    if not cbor_data or (cbor_data[0] & 0xe0) >> 5 != 5:
        return MetadataResult(
            found=False, compiler=None, hash_protocol=None,
            hash_value=None, cbor_length=cbor_length, cbor_raw=cbor_data,
            metadata_start_offset=cbor_start, experimental=False,
            raw_decoded=None, errors=["CBOR data doesn't start with map marker"]
        )

    # Try to decode
    decoded = _decode_cbor_simple(cbor_data)

    if decoded is None:
        # Fallback: try with cbor2 if available
        try:
            import cbor2
            decoded = cbor2.loads(cbor_data)
        except Exception:
            return MetadataResult(
                found=False, compiler=None, hash_protocol=None,
                hash_value=None, cbor_length=cbor_length, cbor_raw=cbor_data,
                metadata_start_offset=cbor_start, experimental=False,
                raw_decoded=None, errors=["Failed to decode CBOR"]
            )

    # Extract compiler info
    compiler = None
    if "solc" in decoded:
        raw_ver = decoded["solc"]
        if isinstance(raw_ver, bytes) and len(raw_ver) == 3:
            version = f"{raw_ver[0]}.{raw_ver[1]}.{raw_ver[2]}"
        elif isinstance(raw_ver, bytes):
            version = raw_ver.hex()
        else:
            version = str(raw_ver)
        compiler = CompilerInfo(name="solc", version=version, raw_version=raw_ver if isinstance(raw_ver, bytes) else None)

    # Extract hash
    hash_protocol = None
    hash_value = None

    if "ipfs" in decoded:
        hash_protocol = "ipfs"
        raw_hash = decoded["ipfs"]
        if isinstance(raw_hash, bytes):
            hash_value = raw_hash.hex()
        else:
            hash_value = str(raw_hash)
    elif "bzzr1" in decoded:
        hash_protocol = "bzzr1"
        raw_hash = decoded["bzzr1"]
        hash_value = raw_hash.hex() if isinstance(raw_hash, bytes) else str(raw_hash)
    elif "bzzr0" in decoded:
        hash_protocol = "bzzr0"
        raw_hash = decoded["bzzr0"]
        hash_value = raw_hash.hex() if isinstance(raw_hash, bytes) else str(raw_hash)

    # Check experimental flag
    experimental = bool(decoded.get("experimental", False))

    # Convert bytes values to hex strings for JSON serialization
    serializable_decoded = {}
    for k, v in decoded.items():
        if isinstance(v, bytes):
            serializable_decoded[k] = v.hex()
        else:
            serializable_decoded[k] = v

    return MetadataResult(
        found=True,
        compiler=compiler,
        hash_protocol=hash_protocol,
        hash_value=hash_value,
        cbor_length=cbor_length,
        cbor_raw=cbor_data,
        metadata_start_offset=cbor_start,
        experimental=experimental,
        raw_decoded=serializable_decoded,
    )
