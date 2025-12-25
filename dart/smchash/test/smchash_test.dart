import 'dart:convert';
import 'package:smchash/smchash.dart';
import 'package:test/test.dart';

void main() {
  group('smchash', () {
    test('hash Hello, World!', () {
      final data = utf8.encode('Hello, World!');
      final hash = smchash(data);
      expect(hash, equals(0x25bb0982c5c0de6e));
    });

    test('hash seeded', () {
      final data = utf8.encode('Hello, World!');
      final hash = smchashSeeded(data, 12345);
      // 0xd26cb494f911af5b as signed int64
      expect(hash, equals(-3284051476333088933));
    });

    test('empty hash is not zero', () {
      final hash = smchash([]);
      expect(hash, isNot(equals(0)));
    });

    test('different seeds produce different hashes', () {
      final data = utf8.encode('data');
      final hash1 = smchashSeeded(data, 1);
      final hash2 = smchashSeeded(data, 2);
      expect(hash1, isNot(equals(hash2)));
    });
  });

  group('smcRand', () {
    test('produces different values', () {
      final rng = SmcRandState(42);
      final r1 = rng.next();
      final r2 = rng.next();
      final r3 = rng.next();
      expect(r1, isNot(equals(r2)));
      expect(r2, isNot(equals(r3)));
    });
  });
}
