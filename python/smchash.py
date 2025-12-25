"""
smcHash - High-performance hash function

Passes all 188 SMHasher3 quality tests. Includes a PRNG that passes BigCrush/PractRand.

Usage:
    from smchash import smchash, smchash_seeded, smc_rand
    
    h = smchash(b"Hello, World!")
    h = smchash_seeded(b"Hello", 12345)
    
    seed = [42]  # Use list for mutable reference
    r = smc_rand(seed)
"""

import struct

# Secret constants: odd, 32 bits set, pairwise hamming distance = 32, prime
SMC_SECRET = (
    0x9ad1e8e2aa5a5c4b,
    0xaaaad2335647d21b,
    0xb8ac35e269d1b495,
    0xa98d653cb2b4c959,
    0x71a5b853b43ca68b,
    0x2b55934dc35c9655,
    0x746ae48ed4d41e4d,
    0xa3d8c38e78aaa6a9,
    0x1bca69c565658bc3,
)

_MASK64 = 0xFFFFFFFFFFFFFFFF


def _mix(a: int, b: int) -> int:
    """128-bit multiply, XOR high and low halves"""
    r = a * b
    return ((r & _MASK64) ^ (r >> 64)) & _MASK64


def _mum(a: int, b: int) -> tuple[int, int]:
    """Multiply-update-mix: returns (lo ^ hi, hi)"""
    r = a * b
    lo = r & _MASK64
    hi = (r >> 64) & _MASK64
    return (lo ^ hi, hi)


def _read64(data: bytes, offset: int = 0) -> int:
    """Read little-endian uint64"""
    return struct.unpack_from('<Q', data, offset)[0]


def _read32(data: bytes, offset: int = 0) -> int:
    """Read little-endian uint32"""
    return struct.unpack_from('<I', data, offset)[0]


def smchash(data: bytes) -> int:
    """Compute smcHash of the given data"""
    return smchash_seeded(data, SMC_SECRET[0])


def smchash_seeded(data: bytes, seed: int) -> int:
    """Compute smcHash with a custom seed"""
    length = len(data)
    seed &= _MASK64

    if length <= 16:
        seed ^= _mix(seed ^ SMC_SECRET[0], SMC_SECRET[1] ^ length)

        if length >= 4:
            if length >= 8:
                a = _read64(data, 0)
                b = _read64(data, length - 8)
            else:
                a = _read32(data, 0)
                b = _read32(data, length - 4)
        elif length > 0:
            a = (data[0] << 56) | (data[length >> 1] << 32) | data[length - 1]
            b = 0
        else:
            a, b = 0, 0

        a = (a ^ SMC_SECRET[1]) & _MASK64
        b = (b ^ seed) & _MASK64
        a, b = _mum(a, b)
        return _mix(a ^ SMC_SECRET[8], b ^ SMC_SECRET[1] ^ length)

    seed ^= _mix(seed ^ SMC_SECRET[2], SMC_SECRET[1])
    i = length
    offset = 0

    # Bulk: 8 lanes = 128 bytes = 2 cache lines
    if length > 128:
        see1 = see2 = see3 = see4 = seed
        see5 = see6 = see7 = seed

        while i > 128:
            seed = _mix(_read64(data, offset) ^ SMC_SECRET[0], _read64(data, offset + 8) ^ seed)
            see1 = _mix(_read64(data, offset + 16) ^ SMC_SECRET[1], _read64(data, offset + 24) ^ see1)
            see2 = _mix(_read64(data, offset + 32) ^ SMC_SECRET[2], _read64(data, offset + 40) ^ see2)
            see3 = _mix(_read64(data, offset + 48) ^ SMC_SECRET[3], _read64(data, offset + 56) ^ see3)
            see4 = _mix(_read64(data, offset + 64) ^ SMC_SECRET[4], _read64(data, offset + 72) ^ see4)
            see5 = _mix(_read64(data, offset + 80) ^ SMC_SECRET[5], _read64(data, offset + 88) ^ see5)
            see6 = _mix(_read64(data, offset + 96) ^ SMC_SECRET[6], _read64(data, offset + 104) ^ see6)
            see7 = _mix(_read64(data, offset + 112) ^ SMC_SECRET[7], _read64(data, offset + 120) ^ see7)
            offset += 128
            i -= 128

        seed ^= see1 ^ see4 ^ see5
        see2 ^= see3 ^ see6 ^ see7
        seed ^= see2

    if i > 64:
        seed = _mix(_read64(data, offset) ^ SMC_SECRET[0], _read64(data, offset + 8) ^ seed)
        seed = _mix(_read64(data, offset + 16) ^ SMC_SECRET[1], _read64(data, offset + 24) ^ seed)
        seed = _mix(_read64(data, offset + 32) ^ SMC_SECRET[2], _read64(data, offset + 40) ^ seed)
        seed = _mix(_read64(data, offset + 48) ^ SMC_SECRET[3], _read64(data, offset + 56) ^ seed)
        offset += 64
        i -= 64

    if i > 32:
        seed = _mix(_read64(data, offset) ^ SMC_SECRET[0], _read64(data, offset + 8) ^ seed)
        seed = _mix(_read64(data, offset + 16) ^ SMC_SECRET[1], _read64(data, offset + 24) ^ seed)
        offset += 32
        i -= 32

    if i > 16:
        seed = _mix(_read64(data, offset) ^ SMC_SECRET[0], _read64(data, offset + 8) ^ seed)

    a = _read64(data, length - 16) ^ length
    b = _read64(data, length - 8)

    a = (a ^ SMC_SECRET[1]) & _MASK64
    b = (b ^ seed) & _MASK64
    a, b = _mum(a, b)
    return _mix(a ^ SMC_SECRET[8], b ^ SMC_SECRET[1] ^ length)


def smchash_secret(data: bytes, seed: int, secret: tuple[int, ...]) -> int:
    """Compute smcHash with custom secrets"""
    length = len(data)
    seed &= _MASK64

    if length <= 16:
        seed ^= _mix(seed ^ secret[0], secret[1] ^ length)

        if length >= 4:
            if length >= 8:
                a = _read64(data, 0)
                b = _read64(data, length - 8)
            else:
                a = _read32(data, 0)
                b = _read32(data, length - 4)
        elif length > 0:
            a = (data[0] << 56) | (data[length >> 1] << 32) | data[length - 1]
            b = 0
        else:
            a, b = 0, 0

        a = (a ^ secret[1]) & _MASK64
        b = (b ^ seed) & _MASK64
        a, b = _mum(a, b)
        return _mix(a ^ secret[8], b ^ secret[1] ^ length)

    seed ^= _mix(seed ^ secret[0], secret[1])
    i = length
    offset = 0

    if length > 128:
        see1 = see2 = see3 = see4 = seed
        see5 = see6 = see7 = seed

        while i > 128:
            seed = _mix(_read64(data, offset) ^ secret[0], _read64(data, offset + 8) ^ seed)
            see1 = _mix(_read64(data, offset + 16) ^ secret[1], _read64(data, offset + 24) ^ see1)
            see2 = _mix(_read64(data, offset + 32) ^ secret[2], _read64(data, offset + 40) ^ see2)
            see3 = _mix(_read64(data, offset + 48) ^ secret[3], _read64(data, offset + 56) ^ see3)
            see4 = _mix(_read64(data, offset + 64) ^ secret[4], _read64(data, offset + 72) ^ see4)
            see5 = _mix(_read64(data, offset + 80) ^ secret[5], _read64(data, offset + 88) ^ see5)
            see6 = _mix(_read64(data, offset + 96) ^ secret[6], _read64(data, offset + 104) ^ see6)
            see7 = _mix(_read64(data, offset + 112) ^ secret[7], _read64(data, offset + 120) ^ see7)
            offset += 128
            i -= 128

        seed ^= see1 ^ see4 ^ see5
        see2 ^= see3 ^ see6 ^ see7
        seed ^= see2

    if i > 64:
        seed = _mix(_read64(data, offset) ^ secret[0], _read64(data, offset + 8) ^ seed)
        seed = _mix(_read64(data, offset + 16) ^ secret[1], _read64(data, offset + 24) ^ seed)
        seed = _mix(_read64(data, offset + 32) ^ secret[2], _read64(data, offset + 40) ^ seed)
        seed = _mix(_read64(data, offset + 48) ^ secret[3], _read64(data, offset + 56) ^ seed)
        offset += 64
        i -= 64

    if i > 32:
        seed = _mix(_read64(data, offset) ^ secret[0], _read64(data, offset + 8) ^ seed)
        seed = _mix(_read64(data, offset + 16) ^ secret[1], _read64(data, offset + 24) ^ seed)
        offset += 32
        i -= 32

    if i > 16:
        seed = _mix(_read64(data, offset) ^ secret[0], _read64(data, offset + 8) ^ seed)

    a = _read64(data, length - 16) ^ length
    b = _read64(data, length - 8)

    a = (a ^ secret[1]) & _MASK64
    b = (b ^ seed) & _MASK64
    a, b = _mum(a, b)
    return _mix(a ^ secret[8], b ^ secret[1] ^ length)


def smc_rand(seed: list[int]) -> int:
    """PRNG - passes BigCrush and PractRand. Seed is a list[int] for mutability."""
    seed[0] = (seed[0] + SMC_SECRET[0]) & _MASK64
    return _mix(seed[0], seed[0] ^ SMC_SECRET[1])


if __name__ == "__main__":
    # Quick test
    h = smchash(b"Hello, World!")
    print(f"smchash('Hello, World!') = 0x{h:016x}")
    assert h == 0x25bb0982c5c0de6e, f"Expected 0x25bb0982c5c0de6e, got 0x{h:016x}"
    
    h2 = smchash_seeded(b"Hello, World!", 12345)
    print(f"smchash_seeded('Hello, World!', 12345) = 0x{h2:016x}")
    assert h2 == 0xd26cb494f911af5b, f"Expected 0xd26cb494f911af5b, got 0x{h2:016x}"
    
    print("All tests passed!")
