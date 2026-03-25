package crypto

import "fmt"

// Size buckets for entry padding (rule C10).
// All encrypted entries are padded to the nearest bucket to prevent
// traffic analysis based on entry sizes.
var sizeBuckets = []int{256, 1024, 4096, 16384, 65536}

// Pad pads data to the nearest size bucket with random bytes.
// The padding is appended inside the encrypted envelope (before encryption).
// Format: [original_length (4 bytes big-endian)] [data] [random padding]
func Pad(data []byte) ([]byte, error) {
	targetSize := bucketFor(len(data) + 4) // +4 for length prefix
	if targetSize < 0 {
		return nil, fmt.Errorf("data too large to pad: %d bytes", len(data))
	}

	padded := make([]byte, targetSize)

	// Store original length as 4 bytes big-endian
	dataLen := len(data)
	padded[0] = byte(dataLen >> 24)
	padded[1] = byte(dataLen >> 16)
	padded[2] = byte(dataLen >> 8)
	padded[3] = byte(dataLen)

	// Copy data
	copy(padded[4:], data)

	// Fill remainder with random bytes
	remaining := padded[4+dataLen:]
	if len(remaining) > 0 {
		copy(remaining, RandomBytes(len(remaining)))
	}

	return padded, nil
}

// Unpad extracts original data from a padded buffer.
func Unpad(padded []byte) ([]byte, error) {
	if len(padded) < 4 {
		return nil, fmt.Errorf("padded data too short")
	}

	dataLen := int(padded[0])<<24 | int(padded[1])<<16 | int(padded[2])<<8 | int(padded[3])
	if dataLen < 0 || dataLen > len(padded)-4 {
		return nil, fmt.Errorf("invalid padded data length: %d", dataLen)
	}

	result := make([]byte, dataLen)
	copy(result, padded[4:4+dataLen])
	return result, nil
}

// bucketFor returns the smallest bucket size that fits the given size.
// Returns -1 if too large.
func bucketFor(size int) int {
	for _, bucket := range sizeBuckets {
		if size <= bucket {
			return bucket
		}
	}
	return -1
}

// BucketSize returns the padded size for a given data length.
func BucketSize(dataLen int) int {
	return bucketFor(dataLen + 4)
}
