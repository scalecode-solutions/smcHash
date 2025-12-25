// Package smchash provides a high-performance hash function.
//
// smcHash passes all 188 SMHasher3 quality tests and includes
// a PRNG (SmcRand) that passes BigCrush and PractRand.
package smchash

import (
	"encoding/binary"
	"math/bits"
)

// Secret constants with properties: odd, 32 bits set, pairwise hamming distance = 32, prime
var smcSecret = [9]uint64{
	0x9ad1e8e2aa5a5c4b,
	0xaaaad2335647d21b,
	0xb8ac35e269d1b495,
	0xa98d653cb2b4c959,
	0x71a5b853b43ca68b,
	0x2b55934dc35c9655,
	0x746ae48ed4d41e4d,
	0xa3d8c38e78aaa6a9,
	0x1bca69c565658bc3,
}

// mix performs 128-bit multiply and XORs high/low halves
func mix(a, b uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	return hi ^ lo
}

// mum performs multiply-update-mix, modifying both inputs
func mum(a, b *uint64) {
	hi, lo := bits.Mul64(*a, *b)
	*a = lo ^ hi
	*b = hi
}

// read64 reads a little-endian uint64 from a byte slice
func read64(p []byte) uint64 {
	return binary.LittleEndian.Uint64(p)
}

// read32 reads a little-endian uint32 from a byte slice
func read32(p []byte) uint32 {
	return binary.LittleEndian.Uint32(p)
}

// Hash computes the smcHash of the given data
func Hash(data []byte) uint64 {
	return HashSeeded(data, smcSecret[0])
}

// HashSeeded computes the smcHash with a custom seed
func HashSeeded(data []byte, seed uint64) uint64 {
	p := data
	length := len(data)
	var a, b uint64

	if length <= 16 {
		seed ^= mix(seed^smcSecret[0], smcSecret[1]^uint64(length))

		if length >= 4 {
			if length >= 8 {
				a = read64(p)
				b = read64(p[length-8:])
			} else {
				a = uint64(read32(p))
				b = uint64(read32(p[length-4:]))
			}
		} else if length > 0 {
			a = (uint64(p[0]) << 56) | (uint64(p[length>>1]) << 32) | uint64(p[length-1])
			b = 0
		} else {
			a, b = 0, 0
		}

		a ^= smcSecret[1]
		b ^= seed
		mum(&a, &b)
		return mix(a^smcSecret[8], b^smcSecret[1]^uint64(length))
	}

	seed ^= mix(seed^smcSecret[2], smcSecret[1])
	i := length

	// Bulk: 8 lanes = 128 bytes = 2 cache lines
	if length > 128 {
		see1, see2, see3, see4 := seed, seed, seed, seed
		see5, see6, see7 := seed, seed, seed

		for i > 128 {
			seed = mix(read64(p)^smcSecret[0], read64(p[8:])^seed)
			see1 = mix(read64(p[16:])^smcSecret[1], read64(p[24:])^see1)
			see2 = mix(read64(p[32:])^smcSecret[2], read64(p[40:])^see2)
			see3 = mix(read64(p[48:])^smcSecret[3], read64(p[56:])^see3)
			see4 = mix(read64(p[64:])^smcSecret[4], read64(p[72:])^see4)
			see5 = mix(read64(p[80:])^smcSecret[5], read64(p[88:])^see5)
			see6 = mix(read64(p[96:])^smcSecret[6], read64(p[104:])^see6)
			see7 = mix(read64(p[112:])^smcSecret[7], read64(p[120:])^see7)
			p = p[128:]
			i -= 128
		}

		seed ^= see1 ^ see4 ^ see5
		see2 ^= see3 ^ see6 ^ see7
		seed ^= see2
	}

	if i > 64 {
		seed = mix(read64(p)^smcSecret[0], read64(p[8:])^seed)
		seed = mix(read64(p[16:])^smcSecret[1], read64(p[24:])^seed)
		seed = mix(read64(p[32:])^smcSecret[2], read64(p[40:])^seed)
		seed = mix(read64(p[48:])^smcSecret[3], read64(p[56:])^seed)
		p = p[64:]
		i -= 64
	}
	if i > 32 {
		seed = mix(read64(p)^smcSecret[0], read64(p[8:])^seed)
		seed = mix(read64(p[16:])^smcSecret[1], read64(p[24:])^seed)
		p = p[32:]
		i -= 32
	}
	if i > 16 {
		seed = mix(read64(p)^smcSecret[0], read64(p[8:])^seed)
	}

	a = read64(data[length-16:]) ^ uint64(length)
	b = read64(data[length-8:])

	a ^= smcSecret[1]
	b ^= seed
	mum(&a, &b)
	return mix(a^smcSecret[8], b^smcSecret[1]^uint64(length))
}

// HashSecret computes smcHash with custom secrets
func HashSecret(data []byte, seed uint64, secret *[9]uint64) uint64 {
	p := data
	length := len(data)
	var a, b uint64

	if length <= 16 {
		seed ^= mix(seed^secret[0], secret[1]^uint64(length))

		if length >= 4 {
			if length >= 8 {
				a = read64(p)
				b = read64(p[length-8:])
			} else {
				a = uint64(read32(p))
				b = uint64(read32(p[length-4:]))
			}
		} else if length > 0 {
			a = (uint64(p[0]) << 56) | (uint64(p[length>>1]) << 32) | uint64(p[length-1])
			b = 0
		} else {
			a, b = 0, 0
		}

		a ^= secret[1]
		b ^= seed
		mum(&a, &b)
		return mix(a^secret[8], b^secret[1]^uint64(length))
	}

	seed ^= mix(seed^secret[0], secret[1])
	i := length

	if length > 128 {
		see1, see2, see3, see4 := seed, seed, seed, seed
		see5, see6, see7 := seed, seed, seed

		for i > 128 {
			seed = mix(read64(p)^secret[0], read64(p[8:])^seed)
			see1 = mix(read64(p[16:])^secret[1], read64(p[24:])^see1)
			see2 = mix(read64(p[32:])^secret[2], read64(p[40:])^see2)
			see3 = mix(read64(p[48:])^secret[3], read64(p[56:])^see3)
			see4 = mix(read64(p[64:])^secret[4], read64(p[72:])^see4)
			see5 = mix(read64(p[80:])^secret[5], read64(p[88:])^see5)
			see6 = mix(read64(p[96:])^secret[6], read64(p[104:])^see6)
			see7 = mix(read64(p[112:])^secret[7], read64(p[120:])^see7)
			p = p[128:]
			i -= 128
		}

		seed ^= see1 ^ see4 ^ see5
		see2 ^= see3 ^ see6 ^ see7
		seed ^= see2
	}

	if i > 64 {
		seed = mix(read64(p)^secret[0], read64(p[8:])^seed)
		seed = mix(read64(p[16:])^secret[1], read64(p[24:])^seed)
		seed = mix(read64(p[32:])^secret[2], read64(p[40:])^seed)
		seed = mix(read64(p[48:])^secret[3], read64(p[56:])^seed)
		p = p[64:]
		i -= 64
	}
	if i > 32 {
		seed = mix(read64(p)^secret[0], read64(p[8:])^seed)
		seed = mix(read64(p[16:])^secret[1], read64(p[24:])^seed)
		p = p[32:]
		i -= 32
	}
	if i > 16 {
		seed = mix(read64(p)^secret[0], read64(p[8:])^seed)
	}

	a = read64(data[length-16:]) ^ uint64(length)
	b = read64(data[length-8:])

	a ^= secret[1]
	b ^= seed
	mum(&a, &b)
	return mix(a^secret[8], b^secret[1]^uint64(length))
}

// Rand generates a pseudo-random number (passes BigCrush/PractRand)
func Rand(seed *uint64) uint64 {
	*seed += smcSecret[0]
	return mix(*seed, *seed^smcSecret[1])
}
