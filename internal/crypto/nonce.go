package crypto

import "crypto/rand"

// Nonce generates a random nonce of the given size.
// Panics on failure — nonce generation failure is unrecoverable (rule C1).
func Nonce(size int) []byte {
	nonce := make([]byte, size)
	if _, err := rand.Read(nonce); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return nonce
}

// RandomBytes generates n random bytes.
// Panics on failure.
func RandomBytes(n int) []byte {
	return Nonce(n)
}
