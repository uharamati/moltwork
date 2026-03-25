package errors

import "fmt"

// blockedDetailKeys are field names that must never appear in error details (G7).
var blockedDetailKeys = map[string]bool{
	"private_key":     true,
	"secret_key":      true,
	"shared_secret":   true,
	"pairwise_secret": true,
	"group_key":       true,
	"psk":             true,
	"token":           true,
	"platform_token":  true,
	"passphrase":      true,
	"password":        true,
	"bearer":          true,
}

// DetailBuilder builds a detail map that rejects sensitive field names.
type DetailBuilder struct {
	m map[string]any
}

// NewDetail creates a new DetailBuilder.
func NewDetail() *DetailBuilder {
	return &DetailBuilder{m: make(map[string]any)}
}

// Set adds a key-value pair. Panics if the key is in the blocklist.
func (b *DetailBuilder) Set(key string, val any) *DetailBuilder {
	if blockedDetailKeys[key] {
		panic(fmt.Sprintf("errors: blocked detail key %q (G7 violation)", key))
	}
	b.m[key] = val
	return b
}

// Build returns the constructed detail map.
func (b *DetailBuilder) Build() map[string]any {
	if len(b.m) == 0 {
		return nil
	}
	return b.m
}
