package masker

import (
	"net/url"
	"strings"
)

// MaskQuery masks query parameters in a full/relative URL or a bare query
// string. All URL components outside the query are preserved verbatim. Query
// keys are sorted on output. Malformed queries are replaced in full with "***".
// Plain text without URL/query structure retains the legacy regex fallback.
func (m *Masker) MaskQuery(raw []byte) []byte {
	s := string(raw)
	// Bare queries have a parameter separator before any URL structure.
	if i := strings.IndexAny(s, "=&"); i >= 0 && !strings.ContainsAny(s[:i], "/:#?") {
		return []byte(m.maskQueryValues(s))
	}
	// A fragment is not part of a URL's query. Keep it byte-for-byte.
	end := len(s)
	if i := strings.IndexByte(s, '#'); i >= 0 {
		end = i
	}
	if q := strings.IndexByte(s[:end], '?'); q >= 0 {
		return []byte(s[:q+1] + m.maskQueryValues(s[q+1:end]) + s[end:])
	}
	if strings.ContainsAny(s, "/#") {
		return raw
	}
	return []byte(m.MaskString(s))
}

func (m *Masker) maskQueryValues(query string) string {
	return m.maskQueryValuesDepth(query, maxURLMaskDepth)
}

func (m *Masker) maskQueryValuesDepth(query string, remaining int) string {
	values, err := url.ParseQuery(query)
	if err != nil {
		return "***"
	}
	for k, vs := range values {
		fn := m.maskByKeyDepth(k, remaining)
		for i, v := range vs {
			if fn != nil {
				vs[i] = fn(v)
			} else {
				vs[i] = m.applyPatterns(v, false, remaining)
			}
		}
	}
	return values.Encode()
}
