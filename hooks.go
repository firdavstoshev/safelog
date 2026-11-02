package safelog

import (
	"context"

	"github.com/rs/zerolog"
)

// Option configures a Logger during construction.
type Option func(*Logger)

// WithHook registers a zerolog hook. Multiple options run hooks in registration
// order. Hooks must be safe for concurrent calls; fields they add are not masked.
func WithHook(hook zerolog.Hook) Option {
	return func(l *Logger) {
		l.z = l.z.Hook(hook)
	}
}

// RequestIDHook adds X-Request-ID from the event context when the ID is nonempty.
// Register it with WithHook. Do not combine it with WithRequestID or another
// writer of X-Request-ID on the same event: zerolog appends duplicate keys.
type RequestIDHook struct {
	// Extract reads the request ID from the service's context. If nil,
	// RequestIDFromContext is used. It must be safe for concurrent calls.
	// Events without a context supply context.Background().
	Extract func(context.Context) string
}

// Run implements zerolog.Hook. Request IDs are emitted verbatim.
func (h RequestIDHook) Run(e *zerolog.Event, _ zerolog.Level, _ string) {
	extract := h.Extract
	if extract == nil {
		extract = RequestIDFromContext
	}
	if id := extract(e.GetCtx()); id != "" {
		e.Str(requestIDKey, id)
	}
}
