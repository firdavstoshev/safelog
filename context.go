package safelog

import "context"

// ctxKey is unexported so other packages cannot collide with our keys.
type ctxKey int

const (
	ctxRequestID ctxKey = iota
)

// ContextWithRequestID returns a derived context carrying reqID. Services
// should put the X-Request-ID header into the context at the HTTP boundary
// so downstream code can log it without threading reqID through every call.
func ContextWithRequestID(ctx context.Context, reqID string) context.Context {
	return context.WithValue(ctx, ctxRequestID, reqID)
}

// RequestIDFromContext extracts a X-Request-ID previously stored by
// ContextWithRequestID, or returns "" if absent.
func RequestIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(ctxRequestID).(string)
	return v
}
