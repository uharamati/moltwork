package logging

import "strings"

// sensitiveKeys are field names that should never appear in logs.
// Per security rules C8 (never log key material) and P5 (never log platform tokens).
var sensitiveKeys = map[string]bool{
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

const redactedValue = "[REDACTED]"

// RedactFields returns a copy of fields with sensitive values replaced.
func RedactFields(fields map[string]any) map[string]any {
	if fields == nil {
		return nil
	}

	safe := make(map[string]any, len(fields))
	for k, v := range fields {
		if isSensitive(k) {
			safe[k] = redactedValue
		} else {
			safe[k] = v
		}
	}
	return safe
}

func isSensitive(key string) bool {
	lower := strings.ToLower(key)
	return sensitiveKeys[lower]
}
