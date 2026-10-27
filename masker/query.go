package masker

import (
	"bytes"
	"net/url"
)

// MaskQuery masks a URL query string (or a full URL that contains one).
// For each parameter the key is checked against the configured rules;
// if a key-based rule matches, its MaskFunc is applied directly (Luhn
// check is skipped because the key itself already identifies PII).
// Otherwise the value is passed through value-regex rules.
//
// If raw does not contain '?', it is treated as plain text and returned
// through MaskString — this keeps the function safe to use on arbitrary
// URL-like strings without the caller needing to know their shape.
//
// Parse errors fall back to MaskString as well, so the function never
// swallows PII silently on malformed input.
func (m *Masker) MaskQuery(raw []byte) []byte {
	q := bytes.IndexByte(raw, '?')
	if q < 0 {
		return []byte(m.MaskString(string(raw)))
	}
	prefix := raw[:q+1]
	query := string(raw[q+1:])

	values, err := url.ParseQuery(query)
	if err != nil {
		return []byte(m.MaskString(string(raw)))
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
	buf.Write(prefix)
	buf.WriteString(values.Encode())
	out := make([]byte, buf.Len())
	copy(out, buf.Bytes())
	return out
}
