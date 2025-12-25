# smchash

High-performance hash function passing all 188 SMHasher3 quality tests.

[![Crates.io](https://img.shields.io/crates/v/smchash.svg)](https://crates.io/crates/smchash)
[![Documentation](https://docs.rs/smchash/badge.svg)](https://docs.rs/smchash)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- **Fast**: Passes all 188 SMHasher3 quality tests
- **`no_std` compatible**: Works in embedded environments
- **Built-in PRNG**: `smc_rand()` passes BigCrush and PractRand
- **Cache-friendly**: Processes 128 bytes (2 cache lines) per iteration

## Usage

```rust
use smchash::{smchash, smchash_seeded, smc_rand};

// Basic hashing
let hash = smchash(b"Hello, World!");

// Seeded hashing
let hash = smchash_seeded(b"Hello", 12345);

// PRNG (passes BigCrush/PractRand)
let mut seed = 42u64;
let random = smc_rand(&mut seed);
```

## API

- `smchash(data: &[u8]) -> u64` - Hash with default seed
- `smchash_seeded(data: &[u8], seed: u64) -> u64` - Hash with custom seed
- `smchash_secret(data: &[u8], seed: u64, secret: &[u64; 9]) -> u64` - Hash with custom secrets
- `smc_rand(seed: &mut u64) -> u64` - PRNG

## Performance

- 128-bit MUM (Multiply-XOR-Mix) construction
- 8 parallel lanes for maximum ILP on ARM64
- Secrets are odd, prime, 32 bits set, pairwise hamming distance = 32

## License

MIT License - Copyright 2025 ScaleCode Solutions
