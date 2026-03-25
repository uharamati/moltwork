package crypto

// GenerateGroupKey creates a random 32-byte group key for private channels or group DMs.
func GenerateGroupKey() [32]byte {
	var key [32]byte
	copy(key[:], RandomBytes(32))
	return key
}

// EncryptGroupKeyForMember encrypts a group key using the pairwise secret
// shared with a specific member. Uses SealForPeer which pads before encrypting
// to prevent traffic analysis from revealing exact key size (rule C7, C10).
func EncryptGroupKeyForMember(pairwiseSecret [32]byte, groupKey [32]byte) ([]byte, error) {
	return SealForPeer(pairwiseSecret, groupKey[:])
}

// DecryptGroupKey decrypts a group key received via pairwise secret.
func DecryptGroupKey(pairwiseSecret [32]byte, encrypted []byte) ([32]byte, error) {
	plaintext, err := OpenFromPeer(pairwiseSecret, encrypted)
	if err != nil {
		return [32]byte{}, err
	}
	if len(plaintext) != 32 {
		return [32]byte{}, ErrDecryptionFailed
	}
	var key [32]byte
	copy(key[:], plaintext)
	return key, nil
}
