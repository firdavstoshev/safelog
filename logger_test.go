package safelog

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/firdavstoshev/safelog/masker"
)

func newTestLogger(opts ...Option) (*Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	return New(buf, masker.New(masker.DefaultRules()), opts...), buf
}

func TestEvent_Ctx_AttachesRequestID(t *testing.T) {
	log, buf := newTestLogger(WithHook(RequestIDHook{}))
	ctx := ContextWithRequestID(context.Background(), "req-ctx-1")

	log.Info().Ctx(ctx).Str("partner", "visa").Msg("ok")

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, buf.String())
	}
	if got["X-Request-ID"] != "req-ctx-1" {
		t.Fatalf("missing reqID: %s", buf.String())
	}
	if got["partner"] != "visa" {
		t.Fatalf("missing partner: %s", buf.String())
	}
}

func TestEvent_Ctx_NilIsNoop(t *testing.T) {
	log, buf := newTestLogger(WithHook(RequestIDHook{}))
	log.Info().Ctx(nil).Str("k", "v").Msg("ok")
	if strings.Contains(buf.String(), "X-Request-ID") {
		t.Fatalf("unexpected reqID in: %s", buf.String())
	}
}

func TestEvent_Ctx_WithoutReqIDIsNoop(t *testing.T) {
	log, buf := newTestLogger(WithHook(RequestIDHook{}))
	log.Info().Ctx(context.Background()).Str("k", "v").Msg("ok")
	if strings.Contains(buf.String(), "X-Request-ID") {
		t.Fatalf("unexpected reqID in: %s", buf.String())
	}
}

func TestEvent_MaskedJSON_WithCtx(t *testing.T) {
	log, buf := newTestLogger(WithHook(RequestIDHook{}))
	ctx := ContextWithRequestID(context.Background(), "req-ctx-2")

	log.Info().Ctx(ctx).
		MaskedJSON("response", []byte(`{"pan":"5058600012346210"}`)).
		Msg("ok")

	s := buf.String()
	if !strings.Contains(s, `"X-Request-ID":"req-ctx-2"`) {
		t.Fatalf("missing reqID: %s", s)
	}
	if !strings.Contains(s, `"pan":"5058********6210"`) {
		t.Fatalf("pan not masked: %s", s)
	}
}

func TestSetMasker_SwapChangesRules(t *testing.T) {
	// Start with DefaultRules (CVV → ***).
	log, buf := newTestLogger()
	log.Info().MaskedJSON("r", []byte(`{"cvv":"123"}`)).Msg("v1")
	if !strings.Contains(buf.String(), `"cvv":"***"`) {
		t.Fatalf("v1 wrong: %s", buf.String())
	}

	// Hot-swap to a masker that leaves CVV alone.
	buf.Reset()
	log.SetMasker(masker.New(nil))
	log.Info().MaskedJSON("r", []byte(`{"cvv":"123"}`)).Msg("v2")
	if !strings.Contains(buf.String(), `"cvv":"123"`) {
		t.Fatalf("v2 should preserve cvv: %s", buf.String())
	}
}

func TestSetMasker_NilPanics(t *testing.T) {
	log, _ := newTestLogger()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on nil masker")
		}
	}()
	log.SetMasker(nil)
}

func TestSetMasker_ConcurrentSwap(t *testing.T) {
	// Readers log concurrently with writer swapping maskers. Race detector
	// (go test -race) must stay clean.
	log, _ := newTestLogger()
	m1 := masker.New(masker.DefaultRules())
	m2 := masker.New(nil)

	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			if i%2 == 0 {
				log.SetMasker(m1)
			} else {
				log.SetMasker(m2)
			}
		}
		close(done)
	}()
	for {
		select {
		case <-done:
			return
		default:
			log.Info().MaskedJSON("r", []byte(`{"pan":"5058600012346210"}`)).Msg("")
		}
	}
}

func TestRequestIDFromContext(t *testing.T) {
	if got := RequestIDFromContext(nil); got != "" {
		t.Fatalf("nil ctx: want empty, got %q", got)
	}
	if got := RequestIDFromContext(context.Background()); got != "" {
		t.Fatalf("empty ctx: want empty, got %q", got)
	}
	ctx := ContextWithRequestID(context.Background(), "abc")
	if got := RequestIDFromContext(ctx); got != "abc" {
		t.Fatalf("want abc, got %q", got)
	}
}

func TestEvent_MaskedURL_IPAndPassword(t *testing.T) {
	var buf bytes.Buffer
	rules := append(masker.DefaultRules(), masker.Rule{Pattern: masker.IPv4Regex, Mask: masker.MaskIPv4(2)})
	log := New(&buf, masker.New(rules))
	log.Info().MaskedURL("url", []byte("http://192.168.1.4:8080/charge?password=secret&amount=100")).Msg("request")
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if want := "http://192.168.x.x:8080/charge?amount=100&password=%2A%2A%2A"; got["url"] != want {
		t.Fatalf("got %q, want %q", got["url"], want)
	}
}

func TestEvent_MaskedQuery_PreservesHost(t *testing.T) {
	var buf bytes.Buffer
	rules := append(masker.DefaultRules(), masker.Rule{Pattern: masker.IPv4Regex, Mask: masker.MaskIPv4(2)})
	log := New(&buf, masker.New(rules))
	log.Info().MaskedQuery("url", []byte("http://192.168.1.4:8080/charge?password=secret")).Msg("request")
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if want := "http://192.168.1.4:8080/charge?password=%2A%2A%2A"; got["url"] != want {
		t.Fatalf("got %q, want %q", got["url"], want)
	}
}

func TestEvent_MaskedQuery_AmbiguousRelativeURL(t *testing.T) {
	log, buf := newTestLogger()
	log.Info().MaskedQuery("url", []byte("action=pay/path?password=secret")).Msg("request")
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["url"] != "***" {
		t.Fatalf("ambiguous URL not redacted: %s", buf.String())
	}
}

func TestEvent_MaskedURL_DomainAndPassword(t *testing.T) {
	log, buf := newTestLogger()
	log.Info().MaskedURL("url", []byte("https://api.example.com:8443/path?password=secret")).Msg("request")
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if want := "https://***:8443/path?password=%2A%2A%2A"; got["url"] != want {
		t.Fatalf("got %q, want %q", got["url"], want)
	}
}
