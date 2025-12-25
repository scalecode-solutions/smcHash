# smchash

High-performance hash function passing all 188 SMHasher3 quality tests.

[![npm version](https://badge.fury.io/js/smchash.svg)](https://www.npmjs.com/package/smchash)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- **Fast**: Passes all 188 SMHasher3 quality tests
- **Built-in PRNG**: `smcRand()` passes BigCrush and PractRand
- **TypeScript**: Full type definitions included
- **Zero dependencies**

## Installation

```bash
npm install smchash
```

## Usage

```typescript
import { smchash, smchashSeeded, smcRand, stringToBytes } from 'smchash';

// Basic hashing
const hash = smchash(stringToBytes("Hello, World!"));

// Seeded hashing
const hash = smchashSeeded(stringToBytes("Hello"), 12345n);

// PRNG (passes BigCrush/PractRand)
const seed = { value: 42n };
const random = smcRand(seed);
```

## API

- `smchash(data: Uint8Array): bigint` - Hash with default seed
- `smchashSeeded(data: Uint8Array, seed: bigint): bigint` - Hash with custom seed
- `smcRand(seed: { value: bigint }): bigint` - PRNG
- `stringToBytes(str: string): Uint8Array` - Helper to convert strings

## Requirements

- ES2020+ (for BigInt support)
- Node.js 12+ or modern browsers

## License

MIT License - Copyright 2025 ScaleCode Solutions
