// Example: masking a plain-text payload (SMS body, URL query, logs
// forwarded from a legacy system — anything that is not JSON or XML).
//
// Only value-regex rules fire for plain text (there are no keys to match
// against). The default set covers PAN, Russian phone and email.
//
//	go run ./example/string
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
	sms := "Payment of 1500 RUB approved for card 4111 1111 1111 1111, " +
		"receipt sent to ivanov@example.com, call +79161234567 for support."

	log.Info().WithRequestID(reqID).
		Str("channel", "sms").
		MaskedString("body", sms).
		Msg("outgoing sms masked")
}
