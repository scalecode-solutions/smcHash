import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * smcHash - High-performance hash function
 * 
 * Passes all 188 SMHasher3 quality tests. Includes a PRNG that passes BigCrush/PractRand.
 */
public final class SmcHash {
    
    // Secret constants: odd, 32 bits set, pairwise hamming distance = 32, prime
    private static final long[] SECRET = {
        0x9ad1e8e2aa5a5c4bL,
        0xaaaad2335647d21bL,
        0xb8ac35e269d1b495L,
        0xa98d653cb2b4c959L,
        0x71a5b853b43ca68bL,
        0x2b55934dc35c9655L,
        0x746ae48ed4d41e4dL,
        0xa3d8c38e78aaa6a9L,
        0x1bca69c565658bc3L,
    };
    
    private SmcHash() {} // Prevent instantiation
    
    /** 128-bit multiply, XOR high and low halves */
    private static long mix(long a, long b) {
        // Use Math.multiplyHigh (Java 9+) for upper 64 bits
        long lo = a * b;
        long hi = Math.multiplyHigh(a, b);
        // Adjust for unsigned multiplication
        if (a < 0) hi += b;
        if (b < 0) hi += a;
        return lo ^ hi;
    }
    
    /** Read little-endian uint64 */
    private static long read64(byte[] data, int offset) {
        return ByteBuffer.wrap(data, offset, 8).order(ByteOrder.LITTLE_ENDIAN).getLong();
    }
    
    /** Read little-endian uint32 as unsigned long */
    private static long read32(byte[] data, int offset) {
        return Integer.toUnsignedLong(
            ByteBuffer.wrap(data, offset, 4).order(ByteOrder.LITTLE_ENDIAN).getInt()
        );
    }
    
    /** Compute smcHash of the given data */
    public static long hash(byte[] data) {
        return hashSeeded(data, SECRET[0]);
    }
    
    /** Compute smcHash with a custom seed */
    public static long hashSeeded(byte[] data, long seed) {
        int length = data.length;
        long a, b;
        
        if (length <= 16) {
            seed ^= mix(seed ^ SECRET[0], SECRET[1] ^ length);
            
            if (length >= 4) {
                if (length >= 8) {
                    a = read64(data, 0);
                    b = read64(data, length - 8);
                } else {
                    a = read32(data, 0);
                    b = read32(data, length - 4);
                }
            } else if (length > 0) {
                a = ((long)(data[0] & 0xFF) << 56) | 
                    ((long)(data[length >> 1] & 0xFF) << 32) | 
                    (data[length - 1] & 0xFF);
                b = 0;
            } else {
                a = b = 0;
            }
            
            a ^= SECRET[1];
            b ^= seed;
            // mum inline
            long r_lo = a * b;
            long r_hi = Math.multiplyHigh(a, b);
            if (a < 0) r_hi += b;
            if (b < 0) r_hi += a;
            a = r_lo ^ r_hi;
            b = r_hi;
            
            return mix(a ^ SECRET[8], b ^ SECRET[1] ^ length);
        }
        
        seed ^= mix(seed ^ SECRET[2], SECRET[1]);
        int i = length;
        int offset = 0;
        
        // Bulk: 8 lanes = 128 bytes = 2 cache lines
        if (length > 128) {
            long see1 = seed, see2 = seed, see3 = seed, see4 = seed;
            long see5 = seed, see6 = seed, see7 = seed;
            
            while (i > 128) {
                seed = mix(read64(data, offset) ^ SECRET[0], read64(data, offset + 8) ^ seed);
                see1 = mix(read64(data, offset + 16) ^ SECRET[1], read64(data, offset + 24) ^ see1);
                see2 = mix(read64(data, offset + 32) ^ SECRET[2], read64(data, offset + 40) ^ see2);
                see3 = mix(read64(data, offset + 48) ^ SECRET[3], read64(data, offset + 56) ^ see3);
                see4 = mix(read64(data, offset + 64) ^ SECRET[4], read64(data, offset + 72) ^ see4);
                see5 = mix(read64(data, offset + 80) ^ SECRET[5], read64(data, offset + 88) ^ see5);
                see6 = mix(read64(data, offset + 96) ^ SECRET[6], read64(data, offset + 104) ^ see6);
                see7 = mix(read64(data, offset + 112) ^ SECRET[7], read64(data, offset + 120) ^ see7);
                offset += 128;
                i -= 128;
            }
            
            seed ^= see1 ^ see4 ^ see5;
            see2 ^= see3 ^ see6 ^ see7;
            seed ^= see2;
        }
        
        if (i > 64) {
            seed = mix(read64(data, offset) ^ SECRET[0], read64(data, offset + 8) ^ seed);
            seed = mix(read64(data, offset + 16) ^ SECRET[1], read64(data, offset + 24) ^ seed);
            seed = mix(read64(data, offset + 32) ^ SECRET[2], read64(data, offset + 40) ^ seed);
            seed = mix(read64(data, offset + 48) ^ SECRET[3], read64(data, offset + 56) ^ seed);
            offset += 64;
            i -= 64;
        }
        if (i > 32) {
            seed = mix(read64(data, offset) ^ SECRET[0], read64(data, offset + 8) ^ seed);
            seed = mix(read64(data, offset + 16) ^ SECRET[1], read64(data, offset + 24) ^ seed);
            offset += 32;
            i -= 32;
        }
        if (i > 16) {
            seed = mix(read64(data, offset) ^ SECRET[0], read64(data, offset + 8) ^ seed);
        }
        
        a = read64(data, length - 16) ^ length;
        b = read64(data, length - 8);
        
        a ^= SECRET[1];
        b ^= seed;
        // mum inline
        long r_lo = a * b;
        long r_hi = Math.multiplyHigh(a, b);
        if (a < 0) r_hi += b;
        if (b < 0) r_hi += a;
        a = r_lo ^ r_hi;
        b = r_hi;
        
        return mix(a ^ SECRET[8], b ^ SECRET[1] ^ length);
    }
    
    /** 
     * PRNG - passes BigCrush and PractRand
     * @param seed Array of length 1 containing the seed (modified in place)
     * @return Random 64-bit value
     */
    public static long rand(long[] seed) {
        seed[0] += SECRET[0];
        return mix(seed[0], seed[0] ^ SECRET[1]);
    }
    
    // Test
    public static void main(String[] args) {
        byte[] data = "Hello, World!".getBytes();
        long h = hash(data);
        System.out.printf("smchash('Hello, World!') = 0x%016x%n", h);
        
        long expected = 0x25bb0982c5c0de6eL;
        if (h != expected) {
            System.err.printf("FAIL: Expected 0x%016x, got 0x%016x%n", expected, h);
            System.exit(1);
        }
        
        long h2 = hashSeeded(data, 12345L);
        System.out.printf("smchashSeeded('Hello, World!', 12345) = 0x%016x%n", h2);
        
        long expected2 = 0xd26cb494f911af5bL;
        if (h2 != expected2) {
            System.err.printf("FAIL: Expected 0x%016x, got 0x%016x%n", expected2, h2);
            System.exit(1);
        }
        
        System.out.println("All tests passed!");
    }
}
