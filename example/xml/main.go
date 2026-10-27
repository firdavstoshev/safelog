// Example: masking a SOAP response from a legacy partner.
//
//	go run ./example/xml
package main

import (
	"os"

	"github.com/firdavstoshev/safelog"
	"github.com/firdavstoshev/safelog/masker"
)

func main() {
	// Default rules cover PAN, CVV, phone, email, FIO/holder, passport,
	// INN/SNILS. Extend via YAML or append custom rules in code.
	m := masker.New(masker.DefaultRules())
	log := safelog.New(os.Stdout, m)

	reqID := "req-7c8f-42"
	body := []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetCardResponse>
      <pan>5058600012346210</pan>
      <cvv>456</cvv>
      <holder>IVANOV IVAN</holder>
      <client>
        <firstName>Ivan</firstName>
        <lastName>Ivanov</lastName>
        <phone>+79161234567</phone>
        <email>ivanov@example.com</email>
      </client>
    </GetCardResponse>
  </soap:Body>
</soap:Envelope>`)

	log.Info().WithRequestID(reqID).
		Str("partner", "legacy-soap").
		Str("endpoint", "/cards/get").
		MaskedXML("response", body).
		Msg("partner response received")
}
