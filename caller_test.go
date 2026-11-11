package safelog

import (
	"bytes"
	"encoding/json"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

// above returns file:line of the line just before the one that calls it, in
// zerolog's caller format. Call it right after the log statement under test.
func above(t *testing.T) string {
	t.Helper()
	_, file, line, ok := runtime.Caller(1)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return file + ":" + strconv.Itoa(line-1)
}

// callerOf parses one log line and returns its caller field. It fails if the
// line has more than one caller key.
func callerOf(t *testing.T, buf *bytes.Buffer) string {
	t.Helper()
	line := buf.String()
	buf.Reset()
	if n := strings.Count(line, `"`+zerolog.CallerFieldName+`":`); n > 1 {
		t.Fatalf("caller key written %d times: %s", n, line)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, line)
	}
	s, _ := got[zerolog.CallerFieldName].(string)
	return s
}

func TestCaller_DefaultOnlyError(t *testing.T) {
	log, buf := newTestLogger()

	log.Info().Msg("info")
	if got := callerOf(t, buf); got != "" {
		t.Fatalf("info got caller %q, want none", got)
	}

	log.Error().Msg("error")
	want := above(t)
	if got := callerOf(t, buf); got != want {
		t.Fatalf("error caller = %q, want %q", got, want)
	}
}

func TestCaller_WithCallerAllLevels(t *testing.T) {
	log, buf := newTestLogger(WithCaller())

	log.Debug().Msg("x")
	checkCaller(t, buf, "debug", above(t))
	log.Info().Msg("x")
	checkCaller(t, buf, "info", above(t))
	log.Warn().Msg("x")
	checkCaller(t, buf, "warn", above(t))
	log.Error().Msg("x")
	checkCaller(t, buf, "error", above(t))
	log.Info().Msgf("x %d", 1)
	checkCaller(t, buf, "msgf", above(t))
	log.Info().Str("k", "v").MaskedString("s", "x").Msg("x")
	checkCaller(t, buf, "chained", above(t))
}

func checkCaller(t *testing.T, buf *bytes.Buffer, name, want string) {
	t.Helper()
	if got := callerOf(t, buf); got != want {
		t.Errorf("%s: caller = %q, want %q", name, got, want)
	}
}

func wrapInfo(l *Logger, msg string)          { l.Info().Msg(msg) }
func wrapInfof(l *Logger, f string, a ...any) { l.Info().Msgf(f, a...) }
func wrapOuter(l *Logger, msg string)         { wrapInner(l, msg) }
func wrapInner(l *Logger, msg string)         { l.Info().CallerSkipFrame(1).Msg(msg) }

func TestCaller_WithCallerSkipForWrappers(t *testing.T) {
	log, buf := newTestLogger(WithCaller(), WithCallerSkip(1))

	wrapInfo(log, "x")
	want := above(t)
	if got := callerOf(t, buf); got != want {
		t.Fatalf("Msg wrapper: caller = %q, want %q", got, want)
	}

	wrapInfof(log, "x %d", 1)
	want = above(t)
	if got := callerOf(t, buf); got != want {
		t.Fatalf("Msgf wrapper: caller = %q, want %q", got, want)
	}
}

func TestCaller_EventSkipStacksOnLoggerSkip(t *testing.T) {
	log, buf := newTestLogger(WithCaller(), WithCallerSkip(1))

	// wrapOuter -> wrapInner adds one more frame than wrapInfo; wrapInner
	// compensates with CallerSkipFrame(1).
	wrapOuter(log, "x")
	want := above(t)
	if got := callerOf(t, buf); got != want {
		t.Fatalf("caller = %q, want %q", got, want)
	}

	// A direct call on a logger built for wrappers can step back down.
	log.Info().CallerSkipFrame(-1).Msg("x")
	want = above(t)
	if got := callerOf(t, buf); got != want {
		t.Fatalf("negative skip: caller = %q, want %q", got, want)
	}
}

func TestCaller_NegativeSkipStopsAtMsgCaller(t *testing.T) {
	log, buf := newTestLogger(WithCaller())

	log.Info().CallerSkipFrame(-5).Msg("x")
	want := above(t)
	if got := callerOf(t, buf); got != want {
		t.Fatalf("caller = %q, want %q", got, want)
	}
}

func TestCaller_IgnoresGlobalSkipFrameCount(t *testing.T) {
	prev := zerolog.CallerSkipFrameCount
	zerolog.CallerSkipFrameCount = 5
	t.Cleanup(func() { zerolog.CallerSkipFrameCount = prev })

	log, buf := newTestLogger()
	log.Error().Msg("x")
	want := above(t)
	if got := callerOf(t, buf); got != want {
		t.Fatalf("caller = %q, want %q", got, want)
	}
}
