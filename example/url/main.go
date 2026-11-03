// Example: mask IP/domain hosts and query parameters together, both directly
// and inside JSON fields configured with mask_url_components.
//
// Run with: go run ./example/url
package main

import (
	_ "embed"
	"os"

	"github.com/firdavstoshev/safelog"
	"github.com/firdavstoshev/safelog/masker"
)

//go:embed masking.yaml
var config []byte

func main() {
	extra, err := masker.Load(config)
	if err != nil {
		panic(err)
	}
	// DefaultRules supplies password/PAN/etc.; the YAML adds IP and URL rules.
	m := masker.New(append(masker.DefaultRules(), extra...))
	log := safelog.New(os.Stdout, m)

	// The host is masked by the IP regex; password by its parameter name.
	log.Info().MaskedURL("url", []byte("http://192.168.1.4:8080/charge?password=secret&amount=100")).
		Msg("outbound request")

	// Domain hosts are automatically replaced with ***. The same processing
	// works inside JSON via the URL field strategy.
	log.Info().MaskedJSON("request", []byte(`{"requestUrl":"https://api.example.com:8443/charge?password=secret&amount=100"}`)).
		Msg("request payload")

	// Bare queries also use parameter-name rules, without a leading '?'.
	log.Info().MaskedQuery("query", []byte("password=secret&amount=100")).
		Msg("query parameters")
}
