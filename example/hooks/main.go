// Example: integrating a service-owned request-ID context key through a hook.
//
//	go run ./example/hooks
package main

import (
	"context"
	"os"

	"github.com/firdavstoshev/safelog"
	"github.com/firdavstoshev/safelog/masker"
)

type requestIDKey struct{}

// In a real service, use the accessor supplied by your HTTP middleware.
func requestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

func main() {
	log := safelog.New(os.Stdout, masker.New(masker.DefaultRules()),
		safelog.WithHook(safelog.RequestIDHook{Extract: requestID}),
	)

	ctx := context.WithValue(context.Background(), requestIDKey{}, "req-7c8f-42")
	log.Info().Ctx(ctx).
		MaskedJSON("response", []byte(`{"pan":"4111111111111111","cvv":"123"}`)).
		Msg("partner response received")
}
