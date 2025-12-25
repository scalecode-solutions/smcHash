import 'dart:convert';
import 'package:smchash/smchash.dart';

void main() {
  // Basic hashing
  final data = utf8.encode('Hello, World!');
  final hash = smchash(data);
  print('smchash("Hello, World!") = 0x${hash.toRadixString(16)}');

  // Seeded hashing
  final seeded = smchashSeeded(data, 12345);
  print(
      'smchashSeeded("Hello, World!", 12345) = 0x${seeded.toRadixString(16)}');

  // PRNG
  final rng = SmcRandState(42);
  print('Random: ${rng.next()}, ${rng.next()}, ${rng.next()}');
}
