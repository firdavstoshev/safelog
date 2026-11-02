package safelog

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/firdavstoshev/safelog/masker"
	"github.com/rs/zerolog"
)

func TestRequestIDHook_CustomExtractor(t *testing.T) {
	type serviceKey struct{}
	log, buf := newTestLogger(WithHook(RequestIDHook{
		Extract: func(ctx context.Context) string {
			id, _ := ctx.Value(serviceKey{}).(string)
			return id
		},
	}))
	// The custom extractor owns correlation, even if safelog's key is present.
	ctx := ContextWithRequestID(context.Background(), "safelog-id")
	ctx = context.WithValue(ctx, serviceKey{}, "service-id")
	log.Info().Ctx(ctx).Msg("ok")
	if strings.Count(buf.String(), `"X-Request-ID"`) != 1 ||
		!strings.Contains(buf.String(), `"X-Request-ID":"service-id"`) {
		t.Fatalf("unexpected correlation: %s", buf.String())
	}
}

func TestEvent_Ctx_RequiresRequestIDHook(t *testing.T) {
	log, buf := newTestLogger()
	log.Info().Ctx(ContextWithRequestID(context.Background(), "id")).Msg("ok")
	if strings.Contains(buf.String(), "X-Request-ID") {
		t.Fatalf("unexpected implicit request ID: %s", buf.String())
	}
}

func TestWithHook_ForwardsContextAndPreservesOrder(t *testing.T) {
	ctx := ContextWithRequestID(context.Background(), "id")
	var order []int
	hook := func(n int) zerolog.Hook {
		return zerolog.HookFunc(func(e *zerolog.Event, level zerolog.Level, msg string) {
			if e.GetCtx() != ctx || level != zerolog.WarnLevel || msg != "hello 42" {
				t.Errorf("hook did not receive context, level, and formatted message")
			}
			order = append(order, n)
			e.Int(fmt.Sprintf("hook%d", n), n)
		})
	}
	log, buf := newTestLogger(WithHook(hook(1)), WithHook(hook(2)))
	log.Warn().Ctx(ctx).Msgf("hello %d", 42)
	var fields map[string]any
	if err := json.Unmarshal(buf.Bytes(), &fields); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(order) != "[1 2]" || fields["hook1"] != float64(1) || fields["hook2"] != float64(2) {
		t.Fatalf("hooks not applied in order: %v, %s", order, buf.String())
	}
}

func TestRequestIDHook_UsesFinalContext(t *testing.T) {
	for _, clear := range []bool{false, true} {
		log, buf := newTestLogger(WithHook(RequestIDHook{}))
		e := log.Info().Ctx(ContextWithRequestID(context.Background(), "old"))
		if clear {
			e.Ctx(nil)
		} else {
			e.Ctx(ContextWithRequestID(context.Background(), "new"))
		}
		e.Msg("ok")
		if strings.Contains(buf.String(), "old") || strings.Count(buf.String(), `"X-Request-ID"`) > 1 {
			t.Fatalf("stale or duplicate request ID: %s", buf.String())
		}
		if !clear && !strings.Contains(buf.String(), `"X-Request-ID":"new"`) {
			t.Fatalf("missing final request ID: %s", buf.String())
		}
	}
}

func TestRequestIDHook_ConcurrentRequests(t *testing.T) {
	var mu sync.Mutex
	seen := make(map[string]int)
	log := New(io.Discard, masker.New(masker.DefaultRules()), WithHook(RequestIDHook{
		Extract: func(ctx context.Context) string {
			id := RequestIDFromContext(ctx)
			mu.Lock()
			seen[id]++
			mu.Unlock()
			return id
		},
	}))
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := ContextWithRequestID(context.Background(), fmt.Sprintf("req-%d", i))
			log.Info().Ctx(ctx).Msg("ok")
		}()
	}
	wg.Wait()
	if len(seen) != 32 {
		t.Fatalf("request contexts mixed: %v", seen)
	}
	for id, count := range seen {
		if count != 1 {
			t.Errorf("request %s observed %d times", id, count)
		}
	}
}
