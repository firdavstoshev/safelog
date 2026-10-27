// Example: masking a partner JSON response.
//
//	go run ./example/json
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
	body := []byte(`{
		"status": "ok",
		"card": {"pan": "5058600012346210", "cvv": "123"},
		"client": {
			"firstName": "Ivan",
			"lastName":  "Ivanov",
			"email":     "ivanov@example.com",
			"phone":     "+79161234567",
			"inn":       "773401234567"
		},
		"note": "backup card 4111 1111 1111 1111"
	}`)

	log.Info().WithRequestID(reqID).
		Str("partner", "visa").
		Str("endpoint", "/cards/get").
		MaskedJSON("response", body).
		Msg("partner response received")
}
