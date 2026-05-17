"""
Pure Python minimal Keccak-256 implementation for zero-dependency extraction.

Ethereum uses the original Keccak padding (0x01), whereas Python's standard 
library `hashlib.sha3_256` uses the NIST SHA-3 padding (0x06).
"""

from __future__ import annotations
from typing import Union


class Keccak256:
    """
    A pure-Python implementation of Keccak-256 optimized for short strings (function signatures).
    """

    RC = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
        0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
    ]

    ROTATIONS = [
        [0, 36, 3, 41, 18],
        [1, 44, 10, 45, 2],
        [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56],
        [27, 20, 39, 8, 14]
    ]

    def __init__(self):
        self.state = [[0] * 5 for _ in range(5)]
        self.buffer = bytearray()
        self.capacity_bytes = 64
        self.rate_bytes = 136  # 1088 / 8

    def _rol(self, value: int, shift: int) -> int:
        return ((value << shift) | (value >> (64 - shift))) & 0xFFFFFFFFFFFFFFFF

    def _keccak_f1600(self):
        s = self.state
        for round_idx in range(24):
            # Theta
            c = [s[x][0] ^ s[x][1] ^ s[x][2] ^ s[x][3] ^ s[x][4] for x in range(5)]
            d = [c[(x - 1) % 5] ^ self._rol(c[(x + 1) % 5], 1) for x in range(5)]
            for x in range(5):
                for y in range(5):
                    s[x][y] ^= d[x]

            # Rho and Pi
            b = [[0] * 5 for _ in range(5)]
            for x in range(5):
                for y in range(5):
                    b[y][(2 * x + 3 * y) % 5] = self._rol(s[x][y], self.ROTATIONS[x][y])

            # Chi
            for x in range(5):
                for y in range(5):
                    s[x][y] = b[x][y] ^ (~b[(x + 1) % 5][y] & b[(x + 2) % 5][y])

            # Iota
            s[0][0] ^= self.RC[round_idx]
        self.state = s

    def update(self, data: Union[bytes, str]):
        if isinstance(data, str):
            data = data.encode("utf-8")
        
        self.buffer.extend(data)
        while len(self.buffer) >= self.rate_bytes:
            block = self.buffer[:self.rate_bytes]
            self.buffer = self.buffer[self.rate_bytes:]
            
            # XOR block into state
            for i in range(self.rate_bytes // 8):
                val = int.from_bytes(block[i*8:(i+1)*8], "little")
                self.state[i % 5][i // 5] ^= val
                
            self._keccak_f1600()

    def digest(self) -> bytes:
        # Create a copy of state and buffer so digest() doesn't mutate object
        hash_state = [[row[i] for i in range(5)] for row in self.state]
        buf = bytearray(self.buffer)
        
        # Keccak padding (0x01)
        buf.append(0x01)
        while len(buf) < self.rate_bytes - 1:
            buf.append(0x00)
        buf.append(0x80)  # Final byte of padding
        
        # XOR last block
        for i in range(self.rate_bytes // 8):
            val = int.from_bytes(buf[i*8:(i+1)*8], "little")
            hash_state[i % 5][i // 5] ^= val
            
        # Run final permutation inline
        s = hash_state
        for round_idx in range(24):
            c = [s[x][0] ^ s[x][1] ^ s[x][2] ^ s[x][3] ^ s[x][4] for x in range(5)]
            d = [c[(x - 1) % 5] ^ (((c[(x + 1) % 5] << 1) | (c[(x + 1) % 5] >> 63)) & 0xFFFFFFFFFFFFFFFF) for x in range(5)]
            for x in range(5):
                for y in range(5):
                    s[x][y] ^= d[x]
            b = [[0] * 5 for _ in range(5)]
            for x in range(5):
                for y in range(5):
                    # Manual rol inline
                    v = s[x][y]
                    sh = self.ROTATIONS[x][y]
                    b[y][(2 * x + 3 * y) % 5] = ((v << sh) | (v >> (64 - sh))) & 0xFFFFFFFFFFFFFFFF if sh else v
            for x in range(5):
                for y in range(5):
                    s[x][y] = b[x][y] ^ (~b[(x + 1) % 5][y] & b[(x + 2) % 5][y])
            s[0][0] ^= self.RC[round_idx]
        
        # Extract 256 bits (32 bytes)
        out = bytearray()
        for i in range(4): # 256 / 64 = 4 words
            out.extend(s[i % 5][i // 5].to_bytes(8, "little"))
        return bytes(out)

    def hexdigest(self) -> str:
        return self.digest().hex()


def keccak256(data: Union[bytes, str]) -> bytes:
    """Helper for one-shot keccak256 bytes."""
    k = Keccak256()
    k.update(data)
    return k.digest()


def keccak256_hex(data: Union[bytes, str]) -> str:
    """Helper for one-shot keccak256 hex string without 0x prefix."""
    k = Keccak256()
    k.update(data)
    return k.hexdigest()


def get_selector(signature: str) -> str:
    """
    Returns the EVM 4-byte selector string (e.g., "0xa9059cbb") 
    for a given text signature.
    """
    full_hash = keccak256_hex(signature.strip())
    return "0x" + full_hash[:8]
