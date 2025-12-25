# smcHash

High-performance hash function optimized for modern CPUs.

## Features

- **Fast**: Passes all 188 SMHasher3 quality tests
- **Cache-friendly**: Processes 128 bytes (2 cache lines) per iteration
- **Parallel**: 8 lanes for maximum ILP on ARM64
- **Portable**: x86, x64, ARM, ARM64, RISC-V
- **Header-only**: Single `smchash.h` file, no dependencies
- **Built-in PRNG**: `smc_rand()` passes BigCrush/PractRand

## Usage

```c
#include "smchash.h"

// Basic hashing
uint64_t hash = smchash("Hello, World!", 13);

// Seeded hashing
uint64_t hash = smchash_seeded("Hello", 5, my_seed);

// Custom secrets (for unique per-application hashing)
uint64_t secret[9];
smc_make_secret(my_seed, secret);
uint64_t hash = smchash_secret("Hello", 5, 0, secret);

// PRNG
uint64_t seed = 12345;
uint64_t random = smc_rand(&seed);
```

## API

### Hash Functions
- `smchash(key, len)` - Hash with default seed
- `smchash_seeded(key, len, seed)` - Hash with custom seed
- `smchash_secret(key, len, seed, secret)` - Hash with custom secrets

### Utilities
- `smc_rand(seed)` - PRNG (passes BigCrush/PractRand)
- `smc_make_secret(seed, secret)` - Generate custom secrets
- `smc_is_prime(n)` - Primality test (64-bit)

## Performance

Benchmarks (M4 Max):
- Small keys (≤16 bytes): ~2 GB/s
- Large keys: ~15 GB/s

## Design

- 128-bit MUM (Multiply-XOR-Mix) construction
- 8 parallel lanes (vs rapidhash's 7) for ARM64 optimization
- Secrets are odd, prime, 32 bits set, pairwise hamming distance = 32

## License

MIT License - Copyright 2025 ScaleCode Solutions

MV❤️
