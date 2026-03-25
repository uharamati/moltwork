package cbor

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

const (
	// MaxEntrySize is the maximum allowed size for a serialized entry (rule B2).
	MaxEntrySize = 65536 // 64KB

	// MaxNestingDepth is the maximum allowed nesting depth (rule B2).
	MaxNestingDepth = 16
)

// Strict encoding/decoding modes per rules B1-B4.
var (
	encMode cbor.EncMode
	decMode cbor.DecMode
)

func init() {
	var err error

	// Encoding: deterministic, canonical CBOR
	encOpts := cbor.CanonicalEncOptions()
	encMode, err = encOpts.EncMode()
	if err != nil {
		panic("cbor enc mode: " + err.Error())
	}

	// Decoding: strict mode
	// - Reject duplicate map keys (rule B1)
	// - Reject unknown fields handled by Go struct tags
	// - Max nesting depth (rule B2)
	decOpts := cbor.DecOptions{
		DupMapKey:   cbor.DupMapKeyEnforcedAPF, // reject duplicate keys
		MaxNestedLevels: MaxNestingDepth,
		MaxArrayElements: 10000,
		MaxMapPairs:      10000,
		IndefLength:      cbor.IndefLengthForbidden, // reject indefinite-length (rule B1)
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField, // reject unknown fields
	}
	decMode, err = decOpts.DecMode()
	if err != nil {
		panic("cbor dec mode: " + err.Error())
	}
}

// Marshal encodes a value to canonical CBOR.
func Marshal(v any) ([]byte, error) {
	data, err := encMode.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("cbor marshal: %w", err)
	}
	return data, nil
}

// Unmarshal decodes CBOR data into a value with strict validation.
// Enforces size limit before decoding (rule B2).
func Unmarshal(data []byte, v any) error {
	if len(data) > MaxEntrySize {
		return fmt.Errorf("cbor data exceeds max size: %d > %d", len(data), MaxEntrySize)
	}
	if err := decMode.Unmarshal(data, v); err != nil {
		return fmt.Errorf("cbor unmarshal: %w", err)
	}
	return nil
}
