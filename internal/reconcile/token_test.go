package reconcile

import (
	"encoding/hex"
	"testing"
)

func TestSecureTokenProducesUnique128BitHexValues(t *testing.T) {
	seen := make(map[string]struct{}, 32)
	for range 32 {
		token, err := secureToken()
		if err != nil {
			t.Fatal("secure token generation failed")
		}
		decoded, err := hex.DecodeString(token)
		if err != nil || len(decoded) != 16 {
			t.Fatal("secure token has invalid shape")
		}
		if _, duplicate := seen[token]; duplicate {
			t.Fatal("secure token generator repeated a value")
		}
		seen[token] = struct{}{}
	}
}
