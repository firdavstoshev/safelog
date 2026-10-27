// Example: masking a URL / query string. Key-based rules catch test
// cards whose Luhn is intentionally invalid; value-regex rules catch
// PII in parameters whose names are unknown.
//
//	go run ./example/query
package main

import (
	"os"

	"github.com/firdavstoshev/safelog"
	"github.com/firdavstoshev/safelog/masker"
)

func main() {
	m := masker.New(masker.DefaultRules())
	log := safelog.New(os.Stdout, m)

	reqID := "req-7c8f-42"

	// 1. Known keys — masked by rule regardless of Luhn.
	req := []byte("/charge?pan=5058600012346210&cvv=123&phone=%2B79161234567&amount=100")
	log.Info().WithRequestID(reqID).
		Str("method", "GET").
		MaskedQuery("url", req).
		Msg("inbound request")

	// 2. Unknown parameter — value regex still catches PAN+phone+email.
	req2 := []byte("/webhook?payload=card+4111+1111+1111+1111+from+ivanov%40example.com")
	log.Info().WithRequestID(reqID).
		MaskedQuery("url", req2).
		Msg("webhook payload")
}
