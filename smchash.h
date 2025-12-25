/*
 * smcHash - Cache-Line Native Hash Function
 * 
 * A high-performance hash function optimized for modern CPUs:
 * - Passes all 188 SMHasher3 quality tests
 * - Processes 128 bytes per iteration (2 cache lines) for bulk data
 * - 8 parallel lanes for maximum ILP on ARM64
 * - Proven 128-bit MUM (Multiply-XOR-Mix) construction
 * - Built-in PRNG (smc_rand) passes BigCrush/PractRand
 * 
 * Portable: Works on x86, x64, ARM, ARM64, RISC-V
 * Compilers: GCC, Clang, MSVC, ICC, TCC
 * 
 * Copyright (c) 2025 ScaleCode Solutions
 * MIT License
 */

#ifndef SMCHASH_H
#define SMCHASH_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------------
 * Compiler Compatibility
 * --------------------------------------------------------------------------- */
#ifdef _MSC_VER
  #define SMC_INLINE __forceinline
  #if defined(_M_X64) || defined(_M_ARM64)
    #include <intrin.h>
    #pragma intrinsic(_umul128)
    #define SMC_HAS_UMUL128 1
  #endif
#elif defined(__GNUC__) || defined(__clang__)
  #define SMC_INLINE static __inline__ __attribute__((always_inline))
#else
  #define SMC_INLINE static inline
#endif

/* ---------------------------------------------------------------------------
 * Endianness Detection
 * --------------------------------------------------------------------------- */
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  #define SMC_BIG_ENDIAN 1
#elif defined(__BIG_ENDIAN__) || defined(_M_PPC)
  #define SMC_BIG_ENDIAN 1
#else
  #define SMC_BIG_ENDIAN 0
#endif

#if SMC_BIG_ENDIAN
  #if defined(__GNUC__) || defined(__clang__)
    #define smc_bswap64(x) __builtin_bswap64(x)
    #define smc_bswap32(x) __builtin_bswap32(x)
  #elif defined(_MSC_VER)
    #define smc_bswap64(x) _byteswap_uint64(x)
    #define smc_bswap32(x) _byteswap_ulong(x)
  #else
    static inline uint64_t smc_bswap64(uint64_t x) {
      return ((x & 0xFF00000000000000ULL) >> 56) |
             ((x & 0x00FF000000000000ULL) >> 40) |
             ((x & 0x0000FF0000000000ULL) >> 24) |
             ((x & 0x000000FF00000000ULL) >> 8)  |
             ((x & 0x00000000FF000000ULL) << 8)  |
             ((x & 0x0000000000FF0000ULL) << 24) |
             ((x & 0x000000000000FF00ULL) << 40) |
             ((x & 0x00000000000000FFULL) << 56);
    }
    static inline uint32_t smc_bswap32(uint32_t x) {
      return ((x >> 24) & 0xFF) | ((x >> 8) & 0xFF00) |
             ((x << 8) & 0xFF0000) | ((x << 24) & 0xFF000000);
    }
  #endif
#endif

/* ---------------------------------------------------------------------------
 * Branch Hints
 * --------------------------------------------------------------------------- */
#if defined(__GNUC__) || defined(__clang__)
  #define SMC_LIKELY(x)   __builtin_expect(!!(x), 1)
  #define SMC_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
  #define SMC_LIKELY(x)   (x)
  #define SMC_UNLIKELY(x) (x)
#endif

/* ---------------------------------------------------------------------------
 * 32x32->64 Multiply (for 32-bit systems)
 * --------------------------------------------------------------------------- */
#if defined(_MSC_VER) && defined(_M_IX86)
  #define smc_mult32to64(x, y) __emulu((unsigned)(x), (unsigned)(y))
#else
  #define smc_mult32to64(x, y) ((uint64_t)(uint32_t)(x) * (uint64_t)(uint32_t)(y))
#endif

/* ---------------------------------------------------------------------------
 * Secret Constants
 * 
 * Properties: odd, 32 bits set, pairwise hamming distance = 32, prime
 * --------------------------------------------------------------------------- */
static const uint64_t SMC_SECRET[9] = {
    UINT64_C(0x9ad1e8e2aa5a5c4b),
    UINT64_C(0xaaaad2335647d21b),
    UINT64_C(0xb8ac35e269d1b495),
    UINT64_C(0xa98d653cb2b4c959),
    UINT64_C(0x71a5b853b43ca68b),
    UINT64_C(0x2b55934dc35c9655),
    UINT64_C(0x746ae48ed4d41e4d),
    UINT64_C(0xa3d8c38e78aaa6a9),
    UINT64_C(0x1bca69c565658bc3)
};

/* ---------------------------------------------------------------------------
 * Core Mixing Functions
 * --------------------------------------------------------------------------- */

/* MUM: Multiply-Update-Mix - modifies both inputs */
SMC_INLINE void smc_mum(uint64_t *A, uint64_t *B) {
#if defined(__SIZEOF_INT128__)
    __uint128_t r = (__uint128_t)(*A) * (*B);
    *A = (uint64_t)(r) ^ (uint64_t)(r >> 64);
    *B = (uint64_t)(r >> 64);
#elif defined(SMC_HAS_UMUL128)
    uint64_t hi;
    uint64_t lo = _umul128(*A, *B, &hi);
    *A = lo ^ hi;
    *B = hi;
#else
    uint64_t ha = *A >> 32, la = (uint32_t)*A;
    uint64_t hb = *B >> 32, lb = (uint32_t)*B;
    uint64_t rh = smc_mult32to64(ha, hb);
    uint64_t rm0 = smc_mult32to64(ha, lb);
    uint64_t rm1 = smc_mult32to64(hb, la);
    uint64_t rl = smc_mult32to64(la, lb);
    uint64_t t = rl + (rm0 << 32);
    uint64_t c = t < rl;
    uint64_t lo = t + (rm1 << 32);
    c += lo < t;
    uint64_t hi = rh + (rm0 >> 32) + (rm1 >> 32) + c;
    *A = lo ^ hi;
    *B = hi;
#endif
}

/* MIX: Multiply and XOR high/low - returns single value */
SMC_INLINE uint64_t smc_mix(uint64_t A, uint64_t B) {
#if defined(__SIZEOF_INT128__)
    __uint128_t r = (__uint128_t)A * B;
    return (uint64_t)(r) ^ (uint64_t)(r >> 64);
#elif defined(SMC_HAS_UMUL128)
    uint64_t hi;
    uint64_t lo = _umul128(A, B, &hi);
    return lo ^ hi;
#else
    uint64_t ha = A >> 32, la = (uint32_t)A;
    uint64_t hb = B >> 32, lb = (uint32_t)B;
    uint64_t rh = smc_mult32to64(ha, hb);
    uint64_t rm0 = smc_mult32to64(ha, lb);
    uint64_t rm1 = smc_mult32to64(hb, la);
    uint64_t rl = smc_mult32to64(la, lb);
    uint64_t t = rl + (rm0 << 32);
    uint64_t c = t < rl;
    uint64_t lo = t + (rm1 << 32);
    c += lo < t;
    uint64_t hi = rh + (rm0 >> 32) + (rm1 >> 32) + c;
    return hi ^ lo;
#endif
}

/* ---------------------------------------------------------------------------
 * smc_rand - PRNG (passes BigCrush/PractRand)
 * --------------------------------------------------------------------------- */
SMC_INLINE uint64_t smc_rand(uint64_t *seed) {
    *seed += SMC_SECRET[0];
    return smc_mix(*seed, *seed ^ SMC_SECRET[1]);
}

/* ---------------------------------------------------------------------------
 * Memory Read Helpers
 * --------------------------------------------------------------------------- */
SMC_INLINE uint64_t smc_read64(const uint8_t *p) {
    uint64_t v;
    memcpy(&v, p, 8);
#if SMC_BIG_ENDIAN
    v = smc_bswap64(v);
#endif
    return v;
}

SMC_INLINE uint32_t smc_read32(const uint8_t *p) {
    uint32_t v;
    memcpy(&v, p, 4);
#if SMC_BIG_ENDIAN
    v = smc_bswap32(v);
#endif
    return v;
}

/* ---------------------------------------------------------------------------
 * smchash - Main hash function
 * --------------------------------------------------------------------------- */
SMC_INLINE uint64_t smchash(const void *key, size_t len) {
    const uint8_t *p = (const uint8_t *)key;
    uint64_t seed = SMC_SECRET[0];
    uint64_t a, b;

    if (SMC_LIKELY(len <= 16)) {
        seed ^= smc_mix(seed ^ SMC_SECRET[0], SMC_SECRET[1] ^ len);
        
        if (len >= 4) {
            if (len >= 8) {
                a = smc_read64(p);
                b = smc_read64(p + len - 8);
            } else {
                a = smc_read32(p);
                b = smc_read32(p + len - 4);
            }
        } else if (SMC_LIKELY(len > 0)) {
            a = (((uint64_t)p[0]) << 56) | (((uint64_t)p[len >> 1]) << 32) | p[len - 1];
            b = 0;
        } else {
            a = b = 0;
        }
        a ^= SMC_SECRET[1];
        b ^= seed;
        smc_mum(&a, &b);
        return smc_mix(a ^ SMC_SECRET[8], b ^ SMC_SECRET[1] ^ len);
    }
    
    seed ^= smc_mix(seed ^ SMC_SECRET[2], SMC_SECRET[1]);
    size_t i = len;
    
    /* Bulk: 8 lanes = 128 bytes = 2 cache lines */
    if (len > 128) {
        uint64_t see1 = seed, see2 = seed, see3 = seed, see4 = seed;
        uint64_t see5 = seed, see6 = seed, see7 = seed;
        
        do {
            seed = smc_mix(smc_read64(p)       ^ SMC_SECRET[0], smc_read64(p + 8)   ^ seed);
            see1 = smc_mix(smc_read64(p + 16)  ^ SMC_SECRET[1], smc_read64(p + 24)  ^ see1);
            see2 = smc_mix(smc_read64(p + 32)  ^ SMC_SECRET[2], smc_read64(p + 40)  ^ see2);
            see3 = smc_mix(smc_read64(p + 48)  ^ SMC_SECRET[3], smc_read64(p + 56)  ^ see3);
            see4 = smc_mix(smc_read64(p + 64)  ^ SMC_SECRET[4], smc_read64(p + 72)  ^ see4);
            see5 = smc_mix(smc_read64(p + 80)  ^ SMC_SECRET[5], smc_read64(p + 88)  ^ see5);
            see6 = smc_mix(smc_read64(p + 96)  ^ SMC_SECRET[6], smc_read64(p + 104) ^ see6);
            see7 = smc_mix(smc_read64(p + 112) ^ SMC_SECRET[7], smc_read64(p + 120) ^ see7);
            p += 128;
            i -= 128;
        } while (i > 128);
        
        seed ^= see1 ^ see4 ^ see5;
        see2 ^= see3 ^ see6 ^ see7;
        seed ^= see2;
    }
    
    if (i > 64) {
        seed = smc_mix(smc_read64(p) ^ SMC_SECRET[0], smc_read64(p + 8) ^ seed);
        seed = smc_mix(smc_read64(p + 16) ^ SMC_SECRET[1], smc_read64(p + 24) ^ seed);
        seed = smc_mix(smc_read64(p + 32) ^ SMC_SECRET[2], smc_read64(p + 40) ^ seed);
        seed = smc_mix(smc_read64(p + 48) ^ SMC_SECRET[3], smc_read64(p + 56) ^ seed);
        p += 64;
        i -= 64;
    }
    if (i > 32) {
        seed = smc_mix(smc_read64(p) ^ SMC_SECRET[0], smc_read64(p + 8) ^ seed);
        seed = smc_mix(smc_read64(p + 16) ^ SMC_SECRET[1], smc_read64(p + 24) ^ seed);
        p += 32;
        i -= 32;
    }
    if (i > 16) {
        seed = smc_mix(smc_read64(p) ^ SMC_SECRET[0], smc_read64(p + 8) ^ seed);
    }
    
    a = smc_read64((const uint8_t*)key + len - 16) ^ len;
    b = smc_read64((const uint8_t*)key + len - 8);
    
    a ^= SMC_SECRET[1];
    b ^= seed;
    smc_mum(&a, &b);
    return smc_mix(a ^ SMC_SECRET[8], b ^ SMC_SECRET[1] ^ len);
}

/* ---------------------------------------------------------------------------
 * smchash_seeded - Hash with custom seed
 * --------------------------------------------------------------------------- */
SMC_INLINE uint64_t smchash_seeded(const void *key, size_t len, uint64_t seed) {
    const uint8_t *p = (const uint8_t *)key;
    uint64_t a, b;

    if (SMC_LIKELY(len <= 16)) {
        seed ^= smc_mix(seed ^ SMC_SECRET[0], SMC_SECRET[1] ^ len);
        
        if (len >= 4) {
            if (len >= 8) {
                a = smc_read64(p);
                b = smc_read64(p + len - 8);
            } else {
                a = smc_read32(p);
                b = smc_read32(p + len - 4);
            }
        } else if (SMC_LIKELY(len > 0)) {
            a = (((uint64_t)p[0]) << 56) | (((uint64_t)p[len >> 1]) << 32) | p[len - 1];
            b = 0;
        } else {
            a = b = 0;
        }
        a ^= SMC_SECRET[1];
        b ^= seed;
        smc_mum(&a, &b);
        return smc_mix(a ^ SMC_SECRET[8], b ^ SMC_SECRET[1] ^ len);
    }
    
    seed ^= smc_mix(seed ^ SMC_SECRET[0], SMC_SECRET[1]);
    size_t i = len;
    
    if (len > 128) {
        uint64_t see1 = seed, see2 = seed, see3 = seed, see4 = seed;
        uint64_t see5 = seed, see6 = seed, see7 = seed;
        
        do {
            seed = smc_mix(smc_read64(p)       ^ SMC_SECRET[0], smc_read64(p + 8)   ^ seed);
            see1 = smc_mix(smc_read64(p + 16)  ^ SMC_SECRET[1], smc_read64(p + 24)  ^ see1);
            see2 = smc_mix(smc_read64(p + 32)  ^ SMC_SECRET[2], smc_read64(p + 40)  ^ see2);
            see3 = smc_mix(smc_read64(p + 48)  ^ SMC_SECRET[3], smc_read64(p + 56)  ^ see3);
            see4 = smc_mix(smc_read64(p + 64)  ^ SMC_SECRET[4], smc_read64(p + 72)  ^ see4);
            see5 = smc_mix(smc_read64(p + 80)  ^ SMC_SECRET[5], smc_read64(p + 88)  ^ see5);
            see6 = smc_mix(smc_read64(p + 96)  ^ SMC_SECRET[6], smc_read64(p + 104) ^ see6);
            see7 = smc_mix(smc_read64(p + 112) ^ SMC_SECRET[7], smc_read64(p + 120) ^ see7);
            p += 128;
            i -= 128;
        } while (i > 128);
        
        seed ^= see1 ^ see4 ^ see5;
        see2 ^= see3 ^ see6 ^ see7;
        seed ^= see2;
    }
    
    if (i > 64) {
        seed = smc_mix(smc_read64(p) ^ SMC_SECRET[0], smc_read64(p + 8) ^ seed);
        seed = smc_mix(smc_read64(p + 16) ^ SMC_SECRET[1], smc_read64(p + 24) ^ seed);
        seed = smc_mix(smc_read64(p + 32) ^ SMC_SECRET[2], smc_read64(p + 40) ^ seed);
        seed = smc_mix(smc_read64(p + 48) ^ SMC_SECRET[3], smc_read64(p + 56) ^ seed);
        p += 64;
        i -= 64;
    }
    if (i > 32) {
        seed = smc_mix(smc_read64(p) ^ SMC_SECRET[0], smc_read64(p + 8) ^ seed);
        seed = smc_mix(smc_read64(p + 16) ^ SMC_SECRET[1], smc_read64(p + 24) ^ seed);
        p += 32;
        i -= 32;
    }
    if (i > 16) {
        seed = smc_mix(smc_read64(p) ^ SMC_SECRET[0], smc_read64(p + 8) ^ seed);
    }
    
    a = smc_read64((const uint8_t*)key + len - 16) ^ len;
    b = smc_read64((const uint8_t*)key + len - 8);
    
    a ^= SMC_SECRET[1];
    b ^= seed;
    smc_mum(&a, &b);
    return smc_mix(a ^ SMC_SECRET[8], b ^ SMC_SECRET[1] ^ len);
}

/* ---------------------------------------------------------------------------
 * smchash_secret - Hash with custom secrets
 * 
 * Use smc_make_secret() to generate custom secrets from a seed.
 * --------------------------------------------------------------------------- */
SMC_INLINE uint64_t smchash_secret(const void *key, size_t len, uint64_t seed, const uint64_t *secret) {
    const uint8_t *p = (const uint8_t *)key;
    uint64_t a, b;

    if (SMC_LIKELY(len <= 16)) {
        seed ^= smc_mix(seed ^ secret[0], secret[1] ^ len);
        
        if (len >= 4) {
            if (len >= 8) {
                a = smc_read64(p);
                b = smc_read64(p + len - 8);
            } else {
                a = smc_read32(p);
                b = smc_read32(p + len - 4);
            }
        } else if (SMC_LIKELY(len > 0)) {
            a = (((uint64_t)p[0]) << 56) | (((uint64_t)p[len >> 1]) << 32) | p[len - 1];
            b = 0;
        } else {
            a = b = 0;
        }
        a ^= secret[1];
        b ^= seed;
        smc_mum(&a, &b);
        return smc_mix(a ^ secret[8], b ^ secret[1] ^ len);
    }
    
    seed ^= smc_mix(seed ^ secret[0], secret[1]);
    size_t i = len;
    
    if (len > 128) {
        uint64_t see1 = seed, see2 = seed, see3 = seed, see4 = seed;
        uint64_t see5 = seed, see6 = seed, see7 = seed;
        
        do {
            seed = smc_mix(smc_read64(p)       ^ secret[0], smc_read64(p + 8)   ^ seed);
            see1 = smc_mix(smc_read64(p + 16)  ^ secret[1], smc_read64(p + 24)  ^ see1);
            see2 = smc_mix(smc_read64(p + 32)  ^ secret[2], smc_read64(p + 40)  ^ see2);
            see3 = smc_mix(smc_read64(p + 48)  ^ secret[3], smc_read64(p + 56)  ^ see3);
            see4 = smc_mix(smc_read64(p + 64)  ^ secret[4], smc_read64(p + 72)  ^ see4);
            see5 = smc_mix(smc_read64(p + 80)  ^ secret[5], smc_read64(p + 88)  ^ see5);
            see6 = smc_mix(smc_read64(p + 96)  ^ secret[6], smc_read64(p + 104) ^ see6);
            see7 = smc_mix(smc_read64(p + 112) ^ secret[7], smc_read64(p + 120) ^ see7);
            p += 128;
            i -= 128;
        } while (i > 128);
        
        seed ^= see1 ^ see4 ^ see5;
        see2 ^= see3 ^ see6 ^ see7;
        seed ^= see2;
    }
    
    if (i > 64) {
        seed = smc_mix(smc_read64(p) ^ secret[0], smc_read64(p + 8) ^ seed);
        seed = smc_mix(smc_read64(p + 16) ^ secret[1], smc_read64(p + 24) ^ seed);
        seed = smc_mix(smc_read64(p + 32) ^ secret[2], smc_read64(p + 40) ^ seed);
        seed = smc_mix(smc_read64(p + 48) ^ secret[3], smc_read64(p + 56) ^ seed);
        p += 64;
        i -= 64;
    }
    if (i > 32) {
        seed = smc_mix(smc_read64(p) ^ secret[0], smc_read64(p + 8) ^ seed);
        seed = smc_mix(smc_read64(p + 16) ^ secret[1], smc_read64(p + 24) ^ seed);
        p += 32;
        i -= 32;
    }
    if (i > 16) {
        seed = smc_mix(smc_read64(p) ^ secret[0], smc_read64(p + 8) ^ seed);
    }
    
    a = smc_read64((const uint8_t*)key + len - 16) ^ len;
    b = smc_read64((const uint8_t*)key + len - 8);
    
    a ^= secret[1];
    b ^= seed;
    smc_mum(&a, &b);
    return smc_mix(a ^ secret[8], b ^ secret[1] ^ len);
}

/* ---------------------------------------------------------------------------
 * Primality Testing (for smc_make_secret)
 * Uses Montgomery arithmetic for fast Miller-Rabin.
 * --------------------------------------------------------------------------- */
SMC_INLINE uint64_t smc_mont_inv(uint64_t n) {
    uint64_t est = (3 * n) ^ 2;
    est = (2 - est * n) * est;
    est = (2 - est * n) * est;
    est = (2 - est * n) * est;
    est = (2 - est * n) * est;
    return est;
}

SMC_INLINE uint64_t smc_mont_reduce(uint64_t x_lo, uint64_t x_hi, uint64_t n, uint64_t n_inv) {
    uint64_t m = x_lo * n_inv;
#if defined(__SIZEOF_INT128__)
    uint64_t t = (uint64_t)(((__uint128_t)m * n) >> 64);
#else
    uint64_t a_lo = (uint32_t)m, a_hi = m >> 32;
    uint64_t b_lo = (uint32_t)n, b_hi = n >> 32;
    uint64_t p0 = a_lo * b_lo, p1 = a_lo * b_hi, p2 = a_hi * b_lo, p3 = a_hi * b_hi;
    uint64_t cy = ((p0 >> 32) + (uint32_t)p1 + (uint32_t)p2) >> 32;
    uint64_t t = p3 + (p1 >> 32) + (p2 >> 32) + cy;
#endif
    return (x_hi < t) ? x_hi - t + n : x_hi - t;
}

SMC_INLINE uint64_t smc_mont_mul(uint64_t a, uint64_t b, uint64_t n, uint64_t n_inv) {
#if defined(__SIZEOF_INT128__)
    __uint128_t prod = (__uint128_t)a * b;
    return smc_mont_reduce((uint64_t)prod, (uint64_t)(prod >> 64), n, n_inv);
#else
    uint64_t a_lo = (uint32_t)a, a_hi = a >> 32;
    uint64_t b_lo = (uint32_t)b, b_hi = b >> 32;
    uint64_t p0 = a_lo * b_lo, p1 = a_lo * b_hi, p2 = a_hi * b_lo, p3 = a_hi * b_hi;
    uint64_t lo = p0 + (p1 << 32) + (p2 << 32);
    uint64_t cy = (lo < p0) + ((p0 >> 32) + (uint32_t)p1 + (uint32_t)p2 >= 0x100000000ULL);
    uint64_t hi = p3 + (p1 >> 32) + (p2 >> 32) + cy;
    return smc_mont_reduce(lo, hi, n, n_inv);
#endif
}

SMC_INLINE uint64_t smc_to_mont(uint64_t x, uint64_t n) {
#if defined(__SIZEOF_INT128__)
    return (uint64_t)(((__uint128_t)x << 64) % n);
#else
    uint64_t r = x % n;
    for (int i = 0; i < 64; i++) { r <<= 1; if (r >= n) r -= n; }
    return r;
#endif
}

SMC_INLINE uint64_t smc_mont_one(uint64_t n) {
    return (UINT64_MAX % n) + 1;
}

SMC_INLINE uint64_t smc_mont_pow(uint64_t base, uint64_t exp, uint64_t n, uint64_t n_inv, uint64_t one) {
    uint64_t result = one;
    while (exp > 0) {
        if (exp & 1) result = smc_mont_mul(result, base, n, n_inv);
        base = smc_mont_mul(base, base, n, n_inv);
        exp >>= 1;
    }
    return result;
}

SMC_INLINE int smc_mont_sprp(uint64_t n, uint64_t a, uint64_t n_inv, uint64_t one) {
    uint64_t d = n - 1;
    uint32_t s = 0;
    while ((d & 1) == 0) { d >>= 1; s++; }
    
    uint64_t a_mont = smc_to_mont(a % n, n);
    if (a_mont == 0) return 1;
    
    uint64_t x = smc_mont_pow(a_mont, d, n, n_inv, one);
    uint64_t neg_one = n - one;
    if (neg_one >= n) neg_one -= n;
    
    if (x == one || x == neg_one) return 1;
    
    for (uint32_t r = 1; r < s; r++) {
        x = smc_mont_mul(x, x, n, n_inv);
        if (x == neg_one) return 1;
        if (x == one) return 0;
    }
    return 0;
}

SMC_INLINE int smc_is_prime(uint64_t n) {
    if (n < 2) return 0;
    if (n == 2) return 1;
    if ((n & 1) == 0) return 0;
    if (n < 9) return 1;
    if (n % 3 == 0 || n % 5 == 0 || n % 7 == 0) return 0;
    if (n == 3215031751ULL) return 0;
    
    uint64_t n_inv = smc_mont_inv(n);
    uint64_t one = smc_mont_one(n);
    
    if (!smc_mont_sprp(n, 2, n_inv, one)) return 0;
    if (n < 2047) return 1;
    if (!smc_mont_sprp(n, 3, n_inv, one)) return 0;
    if (!smc_mont_sprp(n, 5, n_inv, one)) return 0;
    if (!smc_mont_sprp(n, 7, n_inv, one)) return 0;
    if (!smc_mont_sprp(n, 11, n_inv, one)) return 0;
    if (!smc_mont_sprp(n, 13, n_inv, one)) return 0;
    if (!smc_mont_sprp(n, 17, n_inv, one)) return 0;
    if (!smc_mont_sprp(n, 19, n_inv, one)) return 0;
    if (!smc_mont_sprp(n, 23, n_inv, one)) return 0;
    if (!smc_mont_sprp(n, 29, n_inv, one)) return 0;
    if (!smc_mont_sprp(n, 31, n_inv, one)) return 0;
    if (!smc_mont_sprp(n, 37, n_inv, one)) return 0;
    return 1;
}

/* ---------------------------------------------------------------------------
 * smc_popcount - Count bits set
 * --------------------------------------------------------------------------- */
SMC_INLINE int smc_popcount(uint64_t x) {
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_popcountll(x);
#elif defined(_MSC_VER) && defined(_WIN64)
    return (int)__popcnt64(x);
#else
    x -= (x >> 1) & UINT64_C(0x5555555555555555);
    x = (x & UINT64_C(0x3333333333333333)) + ((x >> 2) & UINT64_C(0x3333333333333333));
    x = (x + (x >> 4)) & UINT64_C(0x0f0f0f0f0f0f0f0f);
    return (int)((x * UINT64_C(0x0101010101010101)) >> 56);
#endif
}

/* ---------------------------------------------------------------------------
 * smc_make_secret - Generate custom secrets
 * 
 * Properties: odd, 32 bits set, pairwise hamming = 32, prime
 * --------------------------------------------------------------------------- */
SMC_INLINE void smc_make_secret(uint64_t seed, uint64_t *secret) {
    static const uint8_t c[] = {
        15, 23, 27, 29, 30, 39, 43, 45, 46, 51, 53, 54, 57, 58, 60,
        71, 75, 77, 78, 83, 85, 86, 89, 90, 92, 99, 101, 102, 105, 106, 108,
        113, 114, 116, 120, 135, 139, 141, 142, 147, 149, 150, 153, 154, 156,
        163, 165, 166, 169, 170, 172, 177, 178, 180, 184, 195, 197, 198,
        201, 202, 204, 209, 210, 212, 216, 225, 226, 228, 232, 240
    };
    const size_t c_len = sizeof(c) / sizeof(c[0]);
    
    for (size_t i = 0; i < 9; i++) {
        int ok;
        do {
            ok = 1;
            secret[i] = 0;
            
            for (size_t j = 0; j < 64; j += 8) {
                secret[i] |= ((uint64_t)c[smc_rand(&seed) % c_len]) << j;
            }
            
            if ((secret[i] & 1) == 0) { ok = 0; continue; }
            
            for (size_t j = 0; j < i; j++) {
                if (smc_popcount(secret[j] ^ secret[i]) != 32) { ok = 0; break; }
            }
            
            if (ok && !smc_is_prime(secret[i])) ok = 0;
        } while (!ok);
    }
}

#ifdef __cplusplus
}
#endif

#endif /* SMCHASH_H */
