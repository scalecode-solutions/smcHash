/**
 * smcHash - High-performance hash function
 * 
 * Passes all 188 SMHasher3 quality tests. Includes a PRNG that passes BigCrush/PractRand.
 */

// Secret constants: odd, 32 bits set, pairwise hamming distance = 32, prime
const SMC_SECRET = [
    0x9ad1e8e2aa5a5c4bn,
    0xaaaad2335647d21bn,
    0xb8ac35e269d1b495n,
    0xa98d653cb2b4c959n,
    0x71a5b853b43ca68bn,
    0x2b55934dc35c9655n,
    0x746ae48ed4d41e4dn,
    0xa3d8c38e78aaa6a9n,
    0x1bca69c565658bc3n,
] as const;

const MASK64 = 0xFFFFFFFFFFFFFFFFn;

/** 128-bit multiply, XOR high and low halves */
function mix(a: bigint, b: bigint): bigint {
    const r = a * b;
    return ((r & MASK64) ^ (r >> 64n)) & MASK64;
}

/** Multiply-update-mix: returns [lo ^ hi, hi] */
function mum(a: bigint, b: bigint): [bigint, bigint] {
    const r = a * b;
    const lo = r & MASK64;
    const hi = (r >> 64n) & MASK64;
    return [(lo ^ hi), hi];
}

/** Read little-endian uint64 from DataView */
function read64(view: DataView, offset: number): bigint {
    const lo = BigInt(view.getUint32(offset, true));
    const hi = BigInt(view.getUint32(offset + 4, true));
    return lo | (hi << 32n);
}

/** Read little-endian uint32 from DataView */
function read32(view: DataView, offset: number): bigint {
    return BigInt(view.getUint32(offset, true));
}

/** Compute smcHash of the given data */
export function smchash(data: Uint8Array): bigint {
    return smchashSeeded(data, SMC_SECRET[0]);
}

/** Compute smcHash with a custom seed */
export function smchashSeeded(data: Uint8Array, seed: bigint): bigint {
    const length = data.length;
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    seed &= MASK64;

    if (length <= 16) {
        seed ^= mix(seed ^ SMC_SECRET[0], SMC_SECRET[1] ^ BigInt(length));

        let a: bigint, b: bigint;
        if (length >= 4) {
            if (length >= 8) {
                a = read64(view, 0);
                b = read64(view, length - 8);
            } else {
                a = read32(view, 0);
                b = read32(view, length - 4);
            }
        } else if (length > 0) {
            a = (BigInt(data[0]) << 56n) | (BigInt(data[length >> 1]) << 32n) | BigInt(data[length - 1]);
            b = 0n;
        } else {
            a = 0n;
            b = 0n;
        }

        a = (a ^ SMC_SECRET[1]) & MASK64;
        b = (b ^ seed) & MASK64;
        [a, b] = mum(a, b);
        return mix(a ^ SMC_SECRET[8], b ^ SMC_SECRET[1] ^ BigInt(length));
    }

    seed ^= mix(seed ^ SMC_SECRET[2], SMC_SECRET[1]);
    let i = length;
    let offset = 0;

    // Bulk: 8 lanes = 128 bytes = 2 cache lines
    if (length > 128) {
        let see1 = seed, see2 = seed, see3 = seed, see4 = seed;
        let see5 = seed, see6 = seed, see7 = seed;

        while (i > 128) {
            seed = mix(read64(view, offset) ^ SMC_SECRET[0], read64(view, offset + 8) ^ seed);
            see1 = mix(read64(view, offset + 16) ^ SMC_SECRET[1], read64(view, offset + 24) ^ see1);
            see2 = mix(read64(view, offset + 32) ^ SMC_SECRET[2], read64(view, offset + 40) ^ see2);
            see3 = mix(read64(view, offset + 48) ^ SMC_SECRET[3], read64(view, offset + 56) ^ see3);
            see4 = mix(read64(view, offset + 64) ^ SMC_SECRET[4], read64(view, offset + 72) ^ see4);
            see5 = mix(read64(view, offset + 80) ^ SMC_SECRET[5], read64(view, offset + 88) ^ see5);
            see6 = mix(read64(view, offset + 96) ^ SMC_SECRET[6], read64(view, offset + 104) ^ see6);
            see7 = mix(read64(view, offset + 112) ^ SMC_SECRET[7], read64(view, offset + 120) ^ see7);
            offset += 128;
            i -= 128;
        }

        seed ^= see1 ^ see4 ^ see5;
        see2 ^= see3 ^ see6 ^ see7;
        seed ^= see2;
    }

    if (i > 64) {
        seed = mix(read64(view, offset) ^ SMC_SECRET[0], read64(view, offset + 8) ^ seed);
        seed = mix(read64(view, offset + 16) ^ SMC_SECRET[1], read64(view, offset + 24) ^ seed);
        seed = mix(read64(view, offset + 32) ^ SMC_SECRET[2], read64(view, offset + 40) ^ seed);
        seed = mix(read64(view, offset + 48) ^ SMC_SECRET[3], read64(view, offset + 56) ^ seed);
        offset += 64;
        i -= 64;
    }
    if (i > 32) {
        seed = mix(read64(view, offset) ^ SMC_SECRET[0], read64(view, offset + 8) ^ seed);
        seed = mix(read64(view, offset + 16) ^ SMC_SECRET[1], read64(view, offset + 24) ^ seed);
        offset += 32;
        i -= 32;
    }
    if (i > 16) {
        seed = mix(read64(view, offset) ^ SMC_SECRET[0], read64(view, offset + 8) ^ seed);
    }

    let a = read64(view, length - 16) ^ BigInt(length);
    let b = read64(view, length - 8);

    a = (a ^ SMC_SECRET[1]) & MASK64;
    b = (b ^ seed) & MASK64;
    [a, b] = mum(a, b);
    return mix(a ^ SMC_SECRET[8], b ^ SMC_SECRET[1] ^ BigInt(length));
}

/** PRNG - passes BigCrush and PractRand */
export function smcRand(seed: { value: bigint }): bigint {
    seed.value = (seed.value + SMC_SECRET[0]) & MASK64;
    return mix(seed.value, seed.value ^ SMC_SECRET[1]);
}

/** Helper to convert string to Uint8Array */
export function stringToBytes(str: string): Uint8Array {
    return new TextEncoder().encode(str);
}

// Test when run directly
if (typeof require !== 'undefined' && require.main === module) {
    const data = stringToBytes("Hello, World!");
    const h = smchash(data);
    console.log(`smchash('Hello, World!') = 0x${h.toString(16)}`);
    
    const expected = 0x25bb0982c5c0de6en;
    if (h !== expected) {
        console.error(`FAIL: Expected 0x${expected.toString(16)}, got 0x${h.toString(16)}`);
        process.exit(1);
    }
    
    const h2 = smchashSeeded(data, 12345n);
    console.log(`smchashSeeded('Hello, World!', 12345) = 0x${h2.toString(16)}`);
    
    const expected2 = 0xd26cb494f911af5bn;
    if (h2 !== expected2) {
        console.error(`FAIL: Expected 0x${expected2.toString(16)}, got 0x${h2.toString(16)}`);
        process.exit(1);
    }
    
    console.log("All tests passed!");
}
