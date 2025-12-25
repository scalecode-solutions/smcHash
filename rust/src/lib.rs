//! smcHash - High-performance hash function
//!
//! Passes all 188 SMHasher3 quality tests. Includes a PRNG that passes BigCrush/PractRand.
//!
//! # Example
//! ```
//! use smchash::{smchash, smchash_seeded, smc_rand};
//!
//! let hash = smchash(b"Hello, World!");
//! let seeded = smchash_seeded(b"Hello", 12345);
//!
//! let mut seed = 42u64;
//! let random = smc_rand(&mut seed);
//! ```

#![no_std]

#[cfg(feature = "std")]
extern crate std;

/// Secret constants: odd, 32 bits set, pairwise hamming distance = 32, prime
const SMC_SECRET: [u64; 9] = [
    0x9ad1e8e2aa5a5c4b,
    0xaaaad2335647d21b,
    0xb8ac35e269d1b495,
    0xa98d653cb2b4c959,
    0x71a5b853b43ca68b,
    0x2b55934dc35c9655,
    0x746ae48ed4d41e4d,
    0xa3d8c38e78aaa6a9,
    0x1bca69c565658bc3,
];

/// 128-bit multiply, XOR high and low halves
#[inline(always)]
fn mix(a: u64, b: u64) -> u64 {
    let r = (a as u128) * (b as u128);
    (r as u64) ^ ((r >> 64) as u64)
}

/// Multiply-update-mix: modifies both values
#[inline(always)]
fn mum(a: &mut u64, b: &mut u64) {
    let r = (*a as u128) * (*b as u128);
    *a = (r as u64) ^ ((r >> 64) as u64);
    *b = (r >> 64) as u64;
}

/// Read little-endian u64
#[inline(always)]
fn read64(p: &[u8]) -> u64 {
    u64::from_le_bytes(p[..8].try_into().unwrap())
}

/// Read little-endian u32
#[inline(always)]
fn read32(p: &[u8]) -> u32 {
    u32::from_le_bytes(p[..4].try_into().unwrap())
}

/// Compute smcHash of the given data
#[inline]
pub fn smchash(data: &[u8]) -> u64 {
    smchash_seeded(data, SMC_SECRET[0])
}

/// Compute smcHash with a custom seed
pub fn smchash_seeded(data: &[u8], mut seed: u64) -> u64 {
    let mut p = data;
    let len = data.len();
    let a: u64;
    let b: u64;

    if len <= 16 {
        seed ^= mix(seed ^ SMC_SECRET[0], SMC_SECRET[1] ^ (len as u64));

        if len >= 4 {
            if len >= 8 {
                a = read64(p);
                b = read64(&p[len - 8..]);
            } else {
                a = read32(p) as u64;
                b = read32(&p[len - 4..]) as u64;
            }
        } else if len > 0 {
            a = ((p[0] as u64) << 56) | ((p[len >> 1] as u64) << 32) | (p[len - 1] as u64);
            b = 0;
        } else {
            a = 0;
            b = 0;
        }

        let mut a = a ^ SMC_SECRET[1];
        let mut b = b ^ seed;
        mum(&mut a, &mut b);
        return mix(a ^ SMC_SECRET[8], b ^ SMC_SECRET[1] ^ (len as u64));
    }

    seed ^= mix(seed ^ SMC_SECRET[2], SMC_SECRET[1]);
    let mut i = len;

    // Bulk: 8 lanes = 128 bytes = 2 cache lines
    if len > 128 {
        let mut see1 = seed;
        let mut see2 = seed;
        let mut see3 = seed;
        let mut see4 = seed;
        let mut see5 = seed;
        let mut see6 = seed;
        let mut see7 = seed;

        while i > 128 {
            seed = mix(read64(p) ^ SMC_SECRET[0], read64(&p[8..]) ^ seed);
            see1 = mix(read64(&p[16..]) ^ SMC_SECRET[1], read64(&p[24..]) ^ see1);
            see2 = mix(read64(&p[32..]) ^ SMC_SECRET[2], read64(&p[40..]) ^ see2);
            see3 = mix(read64(&p[48..]) ^ SMC_SECRET[3], read64(&p[56..]) ^ see3);
            see4 = mix(read64(&p[64..]) ^ SMC_SECRET[4], read64(&p[72..]) ^ see4);
            see5 = mix(read64(&p[80..]) ^ SMC_SECRET[5], read64(&p[88..]) ^ see5);
            see6 = mix(read64(&p[96..]) ^ SMC_SECRET[6], read64(&p[104..]) ^ see6);
            see7 = mix(read64(&p[112..]) ^ SMC_SECRET[7], read64(&p[120..]) ^ see7);
            p = &p[128..];
            i -= 128;
        }

        seed ^= see1 ^ see4 ^ see5;
        see2 ^= see3 ^ see6 ^ see7;
        seed ^= see2;
    }

    if i > 64 {
        seed = mix(read64(p) ^ SMC_SECRET[0], read64(&p[8..]) ^ seed);
        seed = mix(read64(&p[16..]) ^ SMC_SECRET[1], read64(&p[24..]) ^ seed);
        seed = mix(read64(&p[32..]) ^ SMC_SECRET[2], read64(&p[40..]) ^ seed);
        seed = mix(read64(&p[48..]) ^ SMC_SECRET[3], read64(&p[56..]) ^ seed);
        p = &p[64..];
        i -= 64;
    }
    if i > 32 {
        seed = mix(read64(p) ^ SMC_SECRET[0], read64(&p[8..]) ^ seed);
        seed = mix(read64(&p[16..]) ^ SMC_SECRET[1], read64(&p[24..]) ^ seed);
        p = &p[32..];
        i -= 32;
    }
    if i > 16 {
        seed = mix(read64(p) ^ SMC_SECRET[0], read64(&p[8..]) ^ seed);
    }

    a = read64(&data[len - 16..]) ^ (len as u64);
    b = read64(&data[len - 8..]);

    let mut a = a ^ SMC_SECRET[1];
    let mut b = b ^ seed;
    mum(&mut a, &mut b);
    mix(a ^ SMC_SECRET[8], b ^ SMC_SECRET[1] ^ (len as u64))
}

/// Compute smcHash with custom secrets
pub fn smchash_secret(data: &[u8], mut seed: u64, secret: &[u64; 9]) -> u64 {
    let mut p = data;
    let len = data.len();
    let a: u64;
    let b: u64;

    if len <= 16 {
        seed ^= mix(seed ^ secret[0], secret[1] ^ (len as u64));

        if len >= 4 {
            if len >= 8 {
                a = read64(p);
                b = read64(&p[len - 8..]);
            } else {
                a = read32(p) as u64;
                b = read32(&p[len - 4..]) as u64;
            }
        } else if len > 0 {
            a = ((p[0] as u64) << 56) | ((p[len >> 1] as u64) << 32) | (p[len - 1] as u64);
            b = 0;
        } else {
            a = 0;
            b = 0;
        }

        let mut a = a ^ secret[1];
        let mut b = b ^ seed;
        mum(&mut a, &mut b);
        return mix(a ^ secret[8], b ^ secret[1] ^ (len as u64));
    }

    seed ^= mix(seed ^ secret[0], secret[1]);
    let mut i = len;

    if len > 128 {
        let mut see1 = seed;
        let mut see2 = seed;
        let mut see3 = seed;
        let mut see4 = seed;
        let mut see5 = seed;
        let mut see6 = seed;
        let mut see7 = seed;

        while i > 128 {
            seed = mix(read64(p) ^ secret[0], read64(&p[8..]) ^ seed);
            see1 = mix(read64(&p[16..]) ^ secret[1], read64(&p[24..]) ^ see1);
            see2 = mix(read64(&p[32..]) ^ secret[2], read64(&p[40..]) ^ see2);
            see3 = mix(read64(&p[48..]) ^ secret[3], read64(&p[56..]) ^ see3);
            see4 = mix(read64(&p[64..]) ^ secret[4], read64(&p[72..]) ^ see4);
            see5 = mix(read64(&p[80..]) ^ secret[5], read64(&p[88..]) ^ see5);
            see6 = mix(read64(&p[96..]) ^ secret[6], read64(&p[104..]) ^ see6);
            see7 = mix(read64(&p[112..]) ^ secret[7], read64(&p[120..]) ^ see7);
            p = &p[128..];
            i -= 128;
        }

        seed ^= see1 ^ see4 ^ see5;
        see2 ^= see3 ^ see6 ^ see7;
        seed ^= see2;
    }

    if i > 64 {
        seed = mix(read64(p) ^ secret[0], read64(&p[8..]) ^ seed);
        seed = mix(read64(&p[16..]) ^ secret[1], read64(&p[24..]) ^ seed);
        seed = mix(read64(&p[32..]) ^ secret[2], read64(&p[40..]) ^ seed);
        seed = mix(read64(&p[48..]) ^ secret[3], read64(&p[56..]) ^ seed);
        p = &p[64..];
        i -= 64;
    }
    if i > 32 {
        seed = mix(read64(p) ^ secret[0], read64(&p[8..]) ^ seed);
        seed = mix(read64(&p[16..]) ^ secret[1], read64(&p[24..]) ^ seed);
        p = &p[32..];
        i -= 32;
    }
    if i > 16 {
        seed = mix(read64(p) ^ secret[0], read64(&p[8..]) ^ seed);
    }

    a = read64(&data[len - 16..]) ^ (len as u64);
    b = read64(&data[len - 8..]);

    let mut a = a ^ secret[1];
    let mut b = b ^ seed;
    mum(&mut a, &mut b);
    mix(a ^ secret[8], b ^ secret[1] ^ (len as u64))
}

/// PRNG - passes BigCrush and PractRand
#[inline]
pub fn smc_rand(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_add(SMC_SECRET[0]);
    mix(*seed, *seed ^ SMC_SECRET[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash() {
        let data = b"Hello, World!";
        let expected = 0x25bb0982c5c0de6eu64;
        assert_eq!(smchash(data), expected);
    }

    #[test]
    fn test_hash_seeded() {
        let data = b"Hello, World!";
        let expected = 0xd26cb494f911af5bu64;
        assert_eq!(smchash_seeded(data, 12345), expected);
    }

    #[test]
    fn test_hash_empty() {
        let result = smchash(b"");
        assert_ne!(result, 0);
    }

    #[test]
    fn test_rand() {
        let mut seed = 42u64;
        let r1 = smc_rand(&mut seed);
        let r2 = smc_rand(&mut seed);
        let r3 = smc_rand(&mut seed);
        assert_ne!(r1, r2);
        assert_ne!(r2, r3);
        assert_ne!(r1, r3);
    }

    #[test]
    fn test_different_lengths() {
        let lengths = [1, 2, 3, 4, 5, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129];
        let mut hashes = std::vec::Vec::new();
        
        for &len in &lengths {
            let data: std::vec::Vec<u8> = (0..len).map(|i| i as u8).collect();
            let h = smchash(&data);
            assert!(!hashes.contains(&h), "Collision at length {}", len);
            hashes.push(h);
        }
    }
}
