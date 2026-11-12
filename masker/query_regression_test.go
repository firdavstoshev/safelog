package masker

import (
	"strings"
	"testing"
)

func TestMaskQueryRegressions(t *testing.T) {
	for _, tc := range []struct{ name, input, want string }{
		{"raw query with unrelated keys", "a=1&cvv=123&b=2&pin=4321", "a=1&b=2&cvv=%2A%2A%2A&pin=%2A%2A%2A"},
		{"URL with unrelated keys", "/pay?a=1&cvv=123&b=2", "/pay?a=1&b=2&cvv=%2A%2A%2A"},
		{"malformed escape", "/pay?cvv=123&a=%ZZ&b=2", "/pay?cvv=123&a=%ZZ&b=2"},
		{"malformed raw query", "cvv=123&a=%ZZ", "cvv=123&a=%ZZ"},
		{"malformed query leaves value patterns untouched", "/pay?card=4111111111111111&bad=%ZZ", "/pay?card=4111111111111111&bad=%ZZ"},
		{"malformed URL preserved", "/cards/4111111111111111?cvv=123&bad=%ZZ#4111111111111111", "/cards/4111111111111111?cvv=123&bad=%ZZ#4111111111111111"},
		{"empty query", "/pay?", "/pay?"},
		{"semicolon", "/pay?cvv=123&a=1;b=2", "/pay?cvv=123&a=1;b=2"},
		{"repeated and encoded keys", "c%76v=123&cvv=456&a=1", "a=1&cvv=%2A%2A%2A&cvv=%2A%2A%2A"},
		{"path preserved while parameter masked", "/cards/4111111111111111/pay?cvv=123", "/cards/4111111111111111/pay?cvv=%2A%2A%2A"},
		{"fragment separated from parameter", "/pay?cvv=123#receipt", "/pay?cvv=%2A%2A%2A#receipt"},
		{"fragment preserved while parameter masked", "/pay?cvv=123#4111111111111111", "/pay?cvv=%2A%2A%2A#4111111111111111"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := string(newDefault().MaskQuery([]byte(tc.input)))
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMaskQueryDoesNotModifyInput(t *testing.T) {
	raw := []byte("/pay?cvv=123&a=1")
	newDefault().MaskQuery(raw)
	if !strings.Contains(string(raw), "cvv=123") {
		t.Fatal("input mutated")
	}
}
