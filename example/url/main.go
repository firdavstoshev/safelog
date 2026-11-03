// Example: mask IP/domain hosts and query parameters together, both directly
// inside JSON fields, and by pattern inside plain text. Also compares the
// mask_url and replace strategies.
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

	// The YAML URL pattern finds URLs inside text without a matching field key.
	text := "calling https://api.example.com/charge?password=secret&amount=100 and http://192.168.1.4:8080/charge?password=secret"
	log.Info().MaskedString("text", text).
		Msg("URL pattern with mask_url_components")

	// Alternative strategies use separate maskers so they do not stack.
	// mask_url preserves the host and removes the entire path/query/fragment.
	stripped := masker.New([]masker.Rule{{Pattern: masker.URLRegex, Mask: masker.MaskURL()}})
	safelog.New(os.Stdout, stripped).Info().MaskedString("text", text).
		Msg("URL pattern with mask_url")

	// replace hides each whole URL, preserving the surrounding text.
	replaced := masker.New([]masker.Rule{{Pattern: masker.URLRegex, Mask: masker.Replace("***")}})
	safelog.New(os.Stdout, replaced).Info().MaskedString("text", text).
		Msg("URL pattern with replace")

}
