# smcHash

High-performance hash function optimized for modern CPUs.

## Features

- **Fast**: Passes all 188 SMHasher3 quality tests
- **Cache-friendly**: Processes 128 bytes (2 cache lines) per iteration
- **Parallel**: 8 lanes for maximum ILP on ARM64
- **Portable**: x86, x64, ARM, ARM64, RISC-V
- **Header-only**: Single `smchash.h` file, no dependencies
- **Built-in PRNG**: `smc_rand()` passes BigCrush/PractRand
- **Multi-language**: Official ports for 6 languages

## Official Language Ports

| Language | Location | Notes |
|----------|----------|-------|
| **C** | `smchash.h` | Reference implementation |
| **Go** | `go/` | Uses `math/bits.Mul64` |
| **Rust** | `rust/` | `no_std` compatible |
| **Python** | `python/` | Pure Python |
| **TypeScript** | `typescript/` | Uses BigInt (ES2020+) |
| **C#** | `csharp/` | Uses `Math.BigMul` |
| **Java** | `java/` | Uses `Math.multiplyHigh` (Java 9+) |

All ports produce identical hashes and are tested against the C reference.

## Usage

### C
```c
#include "smchash.h"

uint64_t hash = smchash("Hello, World!", 13);
uint64_t hash = smchash_seeded("Hello", 5, my_seed);

uint64_t seed = 12345;
uint64_t random = smc_rand(&seed);
```

### Go
```go
import "github.com/scalecode-solutions/smchash"

hash := smchash.Hash([]byte("Hello, World!"))
hash := smchash.HashSeeded([]byte("Hello"), 12345)

seed := uint64(12345)
random := smchash.Rand(&seed)
```

### Rust
```rust
use smchash::{smchash, smchash_seeded, smc_rand};

let hash = smchash(b"Hello, World!");
let hash = smchash_seeded(b"Hello", 12345);

let mut seed = 12345u64;
let random = smc_rand(&mut seed);
```

### Python
```python
from smchash import smchash, smchash_seeded, smc_rand

hash = smchash(b"Hello, World!")
hash = smchash_seeded(b"Hello", 12345)

seed = [12345]  # List for mutability
random = smc_rand(seed)
```

### TypeScript
```typescript
import { smchash, smchashSeeded, smcRand, stringToBytes } from './smchash';

const hash = smchash(stringToBytes("Hello, World!"));
const hash = smchashSeeded(stringToBytes("Hello"), 12345n);

const seed = { value: 12345n };
const random = smcRand(seed);
```

### C#
```csharp
using SmcHash;

var hash = SmcHash.Hash("Hello, World!"u8);
var hash = SmcHash.HashSeeded("Hello"u8, 12345);

ulong seed = 12345;
var random = SmcHash.Rand(ref seed);
```

### Java
```java
import SmcHash;

long hash = SmcHash.hash("Hello, World!".getBytes());
long hash = SmcHash.hashSeeded("Hello".getBytes(), 12345L);

long[] seed = {12345L};
long random = SmcHash.rand(seed);
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
