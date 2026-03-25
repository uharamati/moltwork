package crypto

import "github.com/zeebo/blake3"

// Hash computes the BLAKE3 hash of data, returning 32 bytes.
func Hash(data []byte) [32]byte {
	return blake3.Sum256(data)
}

// HashMulti computes the BLAKE3 hash of multiple data slices concatenated.
func HashMulti(parts ...[]byte) [32]byte {
	h := blake3.New()
	for _, p := range parts {
		h.Write(p)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
