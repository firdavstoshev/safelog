package safelog

import (
	"runtime"

	"github.com/rs/zerolog"
)

// WithCaller adds the caller's file:line to events at every level. Without
// it, only Error events carry a caller.
func WithCaller() Option {
	return func(l *Logger) {
		l.callerLevel = zerolog.TraceLevel
	}
}

// WithCallerSkip skips n extra stack frames when resolving the caller, for
// every event of this Logger. Use it when all logging goes through your own
// wrapper functions: with one wrapper layer, pass 1 so the caller points at
// the code that called the wrapper instead of the wrapper itself.
//
//	func logInfo(l *safelog.Logger, msg string) { l.Info().Msg(msg) }
//	log := safelog.New(w, m, safelog.WithCaller(), safelog.WithCallerSkip(1))
func WithCallerSkip(n int) Option {
	return func(l *Logger) {
		l.callerSkip = n
	}
}

// CallerSkipFrame skips n extra stack frames for this event only, on top of
// any WithCallerSkip. Use it in helpers that sit at a different depth than
// the rest of your wrappers. Negative values are allowed, but the total skip
// never goes below the code that called Msg or Msgf.
func (e *Event) CallerSkipFrame(n int) *Event {
	e.skip += n
	return e
}

// callerDepth is the number of frames between runtime.Caller in addCaller
// and the code that called Msg or Msgf: addCaller itself, then Msg or Msgf.
const callerDepth = 2

// addCaller resolves the caller at flush time, so skips set anywhere in the
// chain apply. It must be called directly from Msg or Msgf. It does not use
// zerolog's Caller, which depends on the global zerolog.CallerSkipFrameCount.
func (e *Event) addCaller() {
	if !e.caller || e.e == nil {
		return
	}
	skip := max(e.skip, 0)
	if pc, file, line, ok := runtime.Caller(callerDepth + skip); ok {
		e.e = e.e.Str(zerolog.CallerFieldName, zerolog.CallerMarshalFunc(pc, file, line))
	}
}
