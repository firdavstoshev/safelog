package masker

import (
	"net/url"
	"strings"
)

// MaskQuery masks a URL query string (or a full URL that contains one).
// For each parameter the key is checked against the configured rules;
// if a key-based rule matches, its MaskFunc is applied directly (Luhn
// check is skipped because the key itself already identifies PII).
// Otherwise the value is passed through value-regex rules.
//
// Inputs without '?' are treated as raw queries when they contain '=';
// other inputs are masked as plain text. When processing a query, URL paths
// and fragments are preserved unchanged. If query parsing fails, the query
// text is also preserved unchanged; no key or value rules are applied to it.
func (m *Masker) MaskQuery(raw []byte) []byte {
	input := string(raw)
	body, fragment, hasFragment := strings.Cut(input, "#")
	prefix, query, hasQuery := strings.Cut(body, "?")
	if !hasQuery {
		if !strings.Contains(body, "=") {
			return []byte(m.MaskString(input))
		}
		prefix, query = "", body
	} else {
		prefix += "?"
	}
	suffix := ""
	if hasFragment {
		suffix = "#" + fragment
	}
	values, err := url.ParseQuery(query)
	if err != nil {
		return []byte(prefix + query + suffix)
	}

	for k, vs := range values {
		fn := m.maskByKey(k)
		for i, v := range vs {
			if fn != nil {
				vs[i] = fn(v)
			} else {
				vs[i] = m.applyValueRules(v)
			}
		}
		values[k] = vs
	}

	buf := getBuf()
	defer putBuf(buf)
	buf.WriteString(prefix)
	buf.WriteString(values.Encode())
	buf.WriteString(suffix)
	out := make([]byte, buf.Len())
	copy(out, buf.Bytes())
	return out
}
