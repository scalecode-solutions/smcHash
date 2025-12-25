// smcHash - High-performance hash function
//
// Passes all 188 SMHasher3 quality tests. Includes a PRNG that passes BigCrush/PractRand.

/// Secret constants: odd, 32 bits set, pairwise hamming distance = 32, prime
const List<int> _smcSecret = [
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

const int _mask64 = 0xFFFFFFFFFFFFFFFF;

final BigInt _mask64Big = BigInt.from(_mask64).toUnsigned(64);

/// Convert int to unsigned BigInt
BigInt _toU64(int v) {
  if (v >= 0) return BigInt.from(v);
  // Handle negative (signed) int as unsigned
  return BigInt.from(v).toUnsigned(64);
}

/// 128-bit multiply, XOR high and low halves
int _mix(int a, int b) {
  final BigInt ba = _toU64(a);
  final BigInt bb = _toU64(b);
  final BigInt r = ba * bb;
  final BigInt lo = r & _mask64Big;
  final BigInt hi = (r >> 64) & _mask64Big;
  return (lo ^ hi).toSigned(64).toInt();
}

/// Multiply-update-mix
(int, int) _mum(int a, int b) {
  final BigInt ba = _toU64(a);
  final BigInt bb = _toU64(b);
  final BigInt r = ba * bb;
  final BigInt lo = r & _mask64Big;
  final BigInt hi = (r >> 64) & _mask64Big;
  return ((lo ^ hi).toSigned(64).toInt(), hi.toSigned(64).toInt());
}

/// Read little-endian uint64 from bytes
int _read64(List<int> data, int offset) {
  int v = 0;
  for (int i = 0; i < 8; i++) {
    v |= (data[offset + i] & 0xFF) << (i * 8);
  }
  return v;
}

/// Read little-endian uint32 from bytes
int _read32(List<int> data, int offset) {
  int v = 0;
  for (int i = 0; i < 4; i++) {
    v |= (data[offset + i] & 0xFF) << (i * 8);
  }
  return v;
}

/// Compute smcHash of the given data.
///
/// Example:
/// ```dart
/// final hash = smchash([72, 101, 108, 108, 111]); // "Hello"
/// ```
int smchash(List<int> data) {
  return smchashSeeded(data, _smcSecret[0]);
}

/// Compute smcHash with a custom seed.
int smchashSeeded(List<int> data, int seed) {
  final int length = data.length;
  int a, b;

  if (length <= 16) {
    seed ^= _mix(seed ^ _smcSecret[0], _smcSecret[1] ^ length);

    if (length >= 4) {
      if (length >= 8) {
        a = _read64(data, 0);
        b = _read64(data, length - 8);
      } else {
        a = _read32(data, 0);
        b = _read32(data, length - 4);
      }
    } else if (length > 0) {
      a = (data[0] << 56) | (data[length >> 1] << 32) | data[length - 1];
      b = 0;
    } else {
      a = 0;
      b = 0;
    }

    a ^= _smcSecret[1];
    b ^= seed;
    final mum = _mum(a, b);
    a = mum.$1;
    b = mum.$2;
    return _mix(a ^ _smcSecret[8], b ^ _smcSecret[1] ^ length);
  }

  seed ^= _mix(seed ^ _smcSecret[2], _smcSecret[1]);
  int i = length;
  int offset = 0;

  // Bulk: 8 lanes = 128 bytes = 2 cache lines
  if (length > 128) {
    int see1 = seed, see2 = seed, see3 = seed, see4 = seed;
    int see5 = seed, see6 = seed, see7 = seed;

    while (i > 128) {
      seed = _mix(_read64(data, offset) ^ _smcSecret[0],
          _read64(data, offset + 8) ^ seed);
      see1 = _mix(_read64(data, offset + 16) ^ _smcSecret[1],
          _read64(data, offset + 24) ^ see1);
      see2 = _mix(_read64(data, offset + 32) ^ _smcSecret[2],
          _read64(data, offset + 40) ^ see2);
      see3 = _mix(_read64(data, offset + 48) ^ _smcSecret[3],
          _read64(data, offset + 56) ^ see3);
      see4 = _mix(_read64(data, offset + 64) ^ _smcSecret[4],
          _read64(data, offset + 72) ^ see4);
      see5 = _mix(_read64(data, offset + 80) ^ _smcSecret[5],
          _read64(data, offset + 88) ^ see5);
      see6 = _mix(_read64(data, offset + 96) ^ _smcSecret[6],
          _read64(data, offset + 104) ^ see6);
      see7 = _mix(_read64(data, offset + 112) ^ _smcSecret[7],
          _read64(data, offset + 120) ^ see7);
      offset += 128;
      i -= 128;
    }

    seed ^= see1 ^ see4 ^ see5;
    see2 ^= see3 ^ see6 ^ see7;
    seed ^= see2;
  }

  if (i > 64) {
    seed = _mix(_read64(data, offset) ^ _smcSecret[0],
        _read64(data, offset + 8) ^ seed);
    seed = _mix(_read64(data, offset + 16) ^ _smcSecret[1],
        _read64(data, offset + 24) ^ seed);
    seed = _mix(_read64(data, offset + 32) ^ _smcSecret[2],
        _read64(data, offset + 40) ^ seed);
    seed = _mix(_read64(data, offset + 48) ^ _smcSecret[3],
        _read64(data, offset + 56) ^ seed);
    offset += 64;
    i -= 64;
  }
  if (i > 32) {
    seed = _mix(_read64(data, offset) ^ _smcSecret[0],
        _read64(data, offset + 8) ^ seed);
    seed = _mix(_read64(data, offset + 16) ^ _smcSecret[1],
        _read64(data, offset + 24) ^ seed);
    offset += 32;
    i -= 32;
  }
  if (i > 16) {
    seed = _mix(_read64(data, offset) ^ _smcSecret[0],
        _read64(data, offset + 8) ^ seed);
  }

  a = _read64(data, length - 16) ^ length;
  b = _read64(data, length - 8);

  a ^= _smcSecret[1];
  b ^= seed;
  final mum = _mum(a, b);
  a = mum.$1;
  b = mum.$2;
  return _mix(a ^ _smcSecret[8], b ^ _smcSecret[1] ^ length);
}

/// PRNG - passes BigCrush and PractRand
///
/// Example:
/// ```dart
/// var seed = 12345;
/// final r1 = smcRand(seed);
/// seed = r1.$2; // Update seed for next call
/// ```
(int, int) smcRand(int seed) {
  seed = (seed + _smcSecret[0]) & _mask64;
  return (_mix(seed, seed ^ _smcSecret[1]), seed);
}

/// Mutable seed wrapper for PRNG
class SmcRandState {
  int _seed;

  SmcRandState(this._seed);

  /// Generate next random number
  int next() {
    final result = smcRand(_seed);
    _seed = result.$2;
    return result.$1;
  }

  /// Current seed value
  int get seed => _seed;
}
