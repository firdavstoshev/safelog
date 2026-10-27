// Package safelog is a thin zerolog wrapper that applies PII masking to
// JSON/XML/SOAP payloads before they reach the log sink.
//
// Typical usage:
//
//	log := safelog.New(os.Stdout, masker.New(masker.DefaultRules()))
//	log.Info().
//	    WithRequestID(reqID).
//	    MaskedJSON("partner_response", body).
//	    Msg("partner call finished")
//
// The active *masker.Masker is held via atomic.Pointer so services can
// hot-swap rules at runtime without rebuilding the Logger — see SetMasker.
package safelog

import (
	"context"
	"io"
	"os"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"

	"github.com/firdavstoshev/safelog/masker"
)

// Logger wraps a zerolog.Logger and holds a lock-free pointer to the
// current masker. Swap rules at runtime via SetMasker — the swap is
// atomic and safe to call concurrently with log emission.
type Logger struct {
	z zerolog.Logger
	m atomic.Pointer[masker.Masker]
}

// New builds a Logger that writes to w and masks with m. The underlying
// zerolog uses RFC3339Nano timestamps and includes the caller for Error
// level and above.
func New(w io.Writer, m *masker.Masker) *Logger {
	if w == nil {
		w = os.Stdout
	}
	zerolog.TimeFieldFormat = time.RFC3339Nano
	z := zerolog.New(w).With().Timestamp().Logger()
	l := &Logger{z: z}
	l.m.Store(m)
	return l
}

// SetMasker atomically replaces the active masker. Intended for hot-reload
// of masking rules at runtime (SIGHUP, fsnotify, ConfigMap watcher, HTTP
// admin endpoint — the trigger lives in the caller, Logger just owns the
// swap primitive).
//
// If the caller fails to build a new *Masker (e.g. invalid YAML), it MUST
// keep the previous instance active rather than passing nil here. Passing
// nil is a programming error and will panic on next log emission.
func (l *Logger) SetMasker(m *masker.Masker) {
	if m == nil {
		panic("safelog: SetMasker called with nil masker")
	}
	l.m.Store(m)
}

// Masker returns the currently active masker. Mostly useful for tests and
// for the reload code path that wants to compare before/after.
func (l *Logger) Masker() *masker.Masker { return l.m.Load() }

// With exposes zerolog's chained context — use for correlation fields
// that are safe to log verbatim. Returns zerolog's native type; call
// .Logger() to get a bare zerolog.Logger.
func (l *Logger) With() zerolog.Context { return l.z.With() }

// requestIDKey is the JSON field name used for correlation ids. Project
// convention — do not rename without aligning with log pipelines.
const requestIDKey = "X-Request-ID"

// Info/Error/Debug/Warn open a zerolog event wrapped with masking helpers.
// Each call reads the current *Masker atomically, so events in flight
// before a SetMasker swap keep their original rules and events started
// after use the new ones.
func (l *Logger) Info() *Event  { return &Event{e: l.z.Info(), m: l.m.Load()} }
func (l *Logger) Error() *Event { return &Event{e: l.z.Error().Caller(1), m: l.m.Load()} }
func (l *Logger) Warn() *Event  { return &Event{e: l.z.Warn(), m: l.m.Load()} }
func (l *Logger) Debug() *Event { return &Event{e: l.z.Debug(), m: l.m.Load()} }

// Event is a zerolog.Event decorated with masking helpers. The masker
// pointer is captured when the event opens, so a SetMasker swap mid-event
// does not cause rule mixing within the same log line.
type Event struct {
	e *zerolog.Event
	m *masker.Masker
}

// WithRequestID attaches X-Request-ID to this event. Project convention:
// every log line must carry a correlation id.
func (e *Event) WithRequestID(reqID string) *Event {
	e.e = e.e.Str(requestIDKey, reqID)
	return e
}

// Ctx extracts correlation fields from ctx (currently X-Request-ID) and
// attaches them to the event. No-op if ctx is nil or carries no reqID.
// Preferred form when a request context is already in scope:
//
//	log.Info().Ctx(ctx).Str("partner", "visa").Msg("...")
func (e *Event) Ctx(ctx context.Context) *Event {
	if reqID := RequestIDFromContext(ctx); reqID != "" {
		e.e = e.e.Str(requestIDKey, reqID)
	}
	return e
}

// Str/Int/Err passthrough to zerolog for safe (non-PII) fields.
func (e *Event) Str(k, v string) *Event     { e.e = e.e.Str(k, v); return e }
func (e *Event) Int(k string, v int) *Event { e.e = e.e.Int(k, v); return e }
func (e *Event) Err(err error) *Event       { e.e = e.e.Err(err); return e }

// MaskedJSON masks the given JSON payload by key and value before adding it
// to the event under `key`. The payload is emitted as a nested JSON object
// — the log line stays valid structured JSON.
func (e *Event) MaskedJSON(key string, payload []byte) *Event {
	e.e = e.e.RawJSON(key, e.m.MaskJSON(payload))
	return e
}

// MaskedXML masks the given XML/SOAP envelope and attaches it as a string
// field. Keeping XML as a string avoids escaping it into JSON twice.
func (e *Event) MaskedXML(key string, payload []byte) *Event {
	e.e = e.e.Str(key, string(e.m.MaskXML(payload)))
	return e
}

// MaskedString applies value-pattern rules to an arbitrary string — use for
// plain-text bodies, SMS, logs forwarded from legacy systems.
func (e *Event) MaskedString(key, v string) *Event {
	e.e = e.e.Str(key, e.m.MaskString(v))
	return e
}

// MaskedQuery masks a URL or raw query string. Parameters whose names
// match a configured rule are masked by key (test cards with invalid
// Luhn are still caught). Values of unknown parameters fall through to
// value-regex rules.
func (e *Event) MaskedQuery(key string, raw []byte) *Event {
	e.e = e.e.Str(key, string(e.m.MaskQuery(raw)))
	return e
}

// MaskedAny marshals an already-decoded structure, masks it, and attaches
// the result. Prefer MaskedJSON when the data is already serialized.
func (e *Event) MaskedAny(key string, v any) *Event {
	e.e = e.e.Interface(key, e.m.MaskAny(v))
	return e
}

// Msg flushes the event. Mirrors zerolog's terminal call.
func (e *Event) Msg(msg string) { e.e.Msg(msg) }

// Msgf formats and flushes.
func (e *Event) Msgf(format string, a ...any) { e.e.Msgf(format, a...) }
