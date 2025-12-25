using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace SmcHash
{
    /// <summary>
    /// High-performance hash function passing all 188 SMHasher3 tests.
    /// Includes a PRNG that passes BigCrush and PractRand.
    /// </summary>
    public static class SmcHash
    {
        // Secret constants: odd, 32 bits set, pairwise hamming distance = 32, prime
        private static readonly ulong[] Secret = {
            0x9ad1e8e2aa5a5c4b,
            0xaaaad2335647d21b,
            0xb8ac35e269d1b495,
            0xa98d653cb2b4c959,
            0x71a5b853b43ca68b,
            0x2b55934dc35c9655,
            0x746ae48ed4d41e4d,
            0xa3d8c38e78aaa6a9,
            0x1bca69c565658bc3,
        };

        /// <summary>128-bit multiply, XOR high and low halves</summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong Mix(ulong a, ulong b)
        {
            var r = Math.BigMul(a, b);
            return (ulong)r ^ (ulong)(r >> 64);
        }

        /// <summary>Multiply-update-mix: modifies both values</summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Mum(ref ulong a, ref ulong b)
        {
            var r = Math.BigMul(a, b);
            a = (ulong)r ^ (ulong)(r >> 64);
            b = (ulong)(r >> 64);
        }

        /// <summary>Read little-endian uint64</summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong Read64(ReadOnlySpan<byte> p) => BinaryPrimitives.ReadUInt64LittleEndian(p);

        /// <summary>Read little-endian uint32</summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint Read32(ReadOnlySpan<byte> p) => BinaryPrimitives.ReadUInt32LittleEndian(p);

        /// <summary>Compute smcHash of the given data</summary>
        public static ulong Hash(ReadOnlySpan<byte> data) => HashSeeded(data, Secret[0]);

        /// <summary>Compute smcHash with a custom seed</summary>
        public static ulong HashSeeded(ReadOnlySpan<byte> data, ulong seed)
        {
            int length = data.Length;
            ulong a, b;

            if (length <= 16)
            {
                seed ^= Mix(seed ^ Secret[0], Secret[1] ^ (ulong)length);

                if (length >= 4)
                {
                    if (length >= 8)
                    {
                        a = Read64(data);
                        b = Read64(data.Slice(length - 8));
                    }
                    else
                    {
                        a = Read32(data);
                        b = Read32(data.Slice(length - 4));
                    }
                }
                else if (length > 0)
                {
                    a = ((ulong)data[0] << 56) | ((ulong)data[length >> 1] << 32) | data[length - 1];
                    b = 0;
                }
                else
                {
                    a = b = 0;
                }

                a ^= Secret[1];
                b ^= seed;
                Mum(ref a, ref b);
                return Mix(a ^ Secret[8], b ^ Secret[1] ^ (ulong)length);
            }

            seed ^= Mix(seed ^ Secret[2], Secret[1]);
            int i = length;
            int offset = 0;

            // Bulk: 8 lanes = 128 bytes = 2 cache lines
            if (length > 128)
            {
                ulong see1 = seed, see2 = seed, see3 = seed, see4 = seed;
                ulong see5 = seed, see6 = seed, see7 = seed;

                while (i > 128)
                {
                    seed = Mix(Read64(data.Slice(offset)) ^ Secret[0], Read64(data.Slice(offset + 8)) ^ seed);
                    see1 = Mix(Read64(data.Slice(offset + 16)) ^ Secret[1], Read64(data.Slice(offset + 24)) ^ see1);
                    see2 = Mix(Read64(data.Slice(offset + 32)) ^ Secret[2], Read64(data.Slice(offset + 40)) ^ see2);
                    see3 = Mix(Read64(data.Slice(offset + 48)) ^ Secret[3], Read64(data.Slice(offset + 56)) ^ see3);
                    see4 = Mix(Read64(data.Slice(offset + 64)) ^ Secret[4], Read64(data.Slice(offset + 72)) ^ see4);
                    see5 = Mix(Read64(data.Slice(offset + 80)) ^ Secret[5], Read64(data.Slice(offset + 88)) ^ see5);
                    see6 = Mix(Read64(data.Slice(offset + 96)) ^ Secret[6], Read64(data.Slice(offset + 104)) ^ see6);
                    see7 = Mix(Read64(data.Slice(offset + 112)) ^ Secret[7], Read64(data.Slice(offset + 120)) ^ see7);
                    offset += 128;
                    i -= 128;
                }

                seed ^= see1 ^ see4 ^ see5;
                see2 ^= see3 ^ see6 ^ see7;
                seed ^= see2;
            }

            if (i > 64)
            {
                seed = Mix(Read64(data.Slice(offset)) ^ Secret[0], Read64(data.Slice(offset + 8)) ^ seed);
                seed = Mix(Read64(data.Slice(offset + 16)) ^ Secret[1], Read64(data.Slice(offset + 24)) ^ seed);
                seed = Mix(Read64(data.Slice(offset + 32)) ^ Secret[2], Read64(data.Slice(offset + 40)) ^ seed);
                seed = Mix(Read64(data.Slice(offset + 48)) ^ Secret[3], Read64(data.Slice(offset + 56)) ^ seed);
                offset += 64;
                i -= 64;
            }
            if (i > 32)
            {
                seed = Mix(Read64(data.Slice(offset)) ^ Secret[0], Read64(data.Slice(offset + 8)) ^ seed);
                seed = Mix(Read64(data.Slice(offset + 16)) ^ Secret[1], Read64(data.Slice(offset + 24)) ^ seed);
                offset += 32;
                i -= 32;
            }
            if (i > 16)
            {
                seed = Mix(Read64(data.Slice(offset)) ^ Secret[0], Read64(data.Slice(offset + 8)) ^ seed);
            }

            a = Read64(data.Slice(length - 16)) ^ (ulong)length;
            b = Read64(data.Slice(length - 8));

            a ^= Secret[1];
            b ^= seed;
            Mum(ref a, ref b);
            return Mix(a ^ Secret[8], b ^ Secret[1] ^ (ulong)length);
        }

        /// <summary>PRNG - passes BigCrush and PractRand</summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong Rand(ref ulong seed)
        {
            seed += Secret[0];
            return Mix(seed, seed ^ Secret[1]);
        }
    }
}
