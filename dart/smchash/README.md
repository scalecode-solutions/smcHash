# smchash

High-performance hash function passing all 188 SMHasher3 quality tests.

[![pub package](https://img.shields.io/pub/v/smchash.svg)](https://pub.dev/packages/smchash)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- **Fast**: Passes all 188 SMHasher3 quality tests
- **Built-in PRNG**: `smcRand()` passes BigCrush and PractRand
- **Pure Dart**: No native dependencies
- **Cross-platform**: Works on all Dart/Flutter platforms

## Installation

```yaml
dependencies:
  smchash: ^0.1.0
```

## Usage

```dart
import 'dart:convert';
import 'package:smchash/smchash.dart';

void main() {
  // Basic hashing
  final data = utf8.encode('Hello, World!');
  final hash = smchash(data);
  print('Hash: 0x${hash.toRadixString(16)}');

  // Seeded hashing
  final seeded = smchashSeeded(data, 12345);
  print('Seeded: 0x${seeded.toRadixString(16)}');

  // PRNG
  final rng = SmcRandState(42);
  print('Random: ${rng.next()}, ${rng.next()}, ${rng.next()}');
}
```

## API

### Hash Functions
- `smchash(List<int> data)` - Hash with default seed
- `smchashSeeded(List<int> data, int seed)` - Hash with custom seed

### PRNG
- `smcRand(int seed)` - Returns `(value, newSeed)` tuple
- `SmcRandState` - Mutable wrapper for easier PRNG usage

## License

MIT License - Copyright 2025 ScaleCode Solutions
