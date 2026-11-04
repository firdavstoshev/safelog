// Example: masking a URL / query string. Key-based rules catch test
// cards whose Luhn is intentionally invalid; value-regex rules catch
// PII in parameters whose names are unknown. The examples also cover raw
// queries, repeated keys and malformed input.
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

	// 3. Raw query without '?' — unrelated keys do not prevent key masking.
	// Output: amount=100&currency=TJS&cvv=%2A%2A%2A&pin=%2A%2A%2A
	log.Info().WithRequestID(reqID).
		MaskedQuery("query", []byte("amount=100&cvv=123&currency=TJS&pin=4321")).
		Msg("raw query with unrelated parameters")

	// 4. Repeated and percent-encoded keys — every CVV value is masked.
	// Output: amount=100&cvv=%2A%2A%2A&cvv=%2A%2A%2A
	log.Info().WithRequestID(reqID).
		MaskedQuery("query", []byte("c%76v=123&cvv=456&amount=100")).
		Msg("repeated and encoded query keys")

	// 5. Invalid percent escapes and unescaped semicolons cause parsing errors.
	// Query text is preserved unchanged when parsing fails.
	// Outputs:
	// /charge?cvv=123&amount=%ZZ&currency=TJS
	// /charge?cvv=123&amount=100;currency=TJS
	for _, malformed := range []string{
		"/charge?cvv=123&amount=%ZZ&currency=TJS",
		"/charge?cvv=123&amount=100;currency=TJS",
	} {
		log.Info().WithRequestID(reqID).
			MaskedQuery("url", []byte(malformed)).
			Msg("malformed query preserved")
	}

}
