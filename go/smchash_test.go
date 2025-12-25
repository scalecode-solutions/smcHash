package smchash

import (
	"testing"
)

func TestHash(t *testing.T) {
	// Test against known C implementation output
	data := []byte("Hello, World!")
	expected := uint64(0x25bb0982c5c0de6e)

	result := Hash(data)
	if result != expected {
		t.Errorf("Hash mismatch: got 0x%x, expected 0x%x", result, expected)
	}
}

func TestHashEmpty(t *testing.T) {
	result := Hash([]byte{})
	if result == 0 {
		t.Error("Empty hash should not be zero")
	}
}

func TestHashSeeded(t *testing.T) {
	data := []byte("Hello, World!")
	seed := uint64(12345)
	expected := uint64(0xd26cb494f911af5b)

	result := HashSeeded(data, seed)
	if result != expected {
		t.Errorf("HashSeeded mismatch: got 0x%x, expected 0x%x", result, expected)
	}
}

func TestRand(t *testing.T) {
	seed := uint64(42)

	// Generate some random numbers and check they're different
	r1 := Rand(&seed)
	r2 := Rand(&seed)
	r3 := Rand(&seed)

	if r1 == r2 || r2 == r3 || r1 == r3 {
		t.Error("PRNG produced duplicate values")
	}
}

func TestHashDifferentLengths(t *testing.T) {
	// Test various input lengths to exercise different code paths
	lengths := []int{1, 2, 3, 4, 5, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 256, 512}

	hashes := make(map[uint64]bool)
	for _, length := range lengths {
		data := make([]byte, length)
		for i := range data {
			data[i] = byte(i)
		}
		h := Hash(data)
		if hashes[h] {
			t.Errorf("Collision at length %d", length)
		}
		hashes[h] = true
	}
}

func BenchmarkHash16(b *testing.B) {
	data := []byte("0123456789abcdef")
	for i := 0; i < b.N; i++ {
		Hash(data)
	}
}

func BenchmarkHash64(b *testing.B) {
	data := make([]byte, 64)
	for i := range data {
		data[i] = byte(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Hash(data)
	}
}

func BenchmarkHash256(b *testing.B) {
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Hash(data)
	}
}

func BenchmarkHash1024(b *testing.B) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Hash(data)
	}
}

func BenchmarkRand(b *testing.B) {
	seed := uint64(12345)
	for i := 0; i < b.N; i++ {
		Rand(&seed)
	}
}
