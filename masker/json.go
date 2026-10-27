package masker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync"
	"unicode/utf8"
)

// bufPool reuses encoding buffers across MaskJSON calls — on hot paths this
// avoids a ~1KB allocation per log line.
var bufPool = sync.Pool{
	New: func() any { return new(bytes.Buffer) },
}

func getBuf() *bytes.Buffer {
	b := bufPool.Get().(*bytes.Buffer)
	b.Reset()
	return b
}

func putBuf(b *bytes.Buffer) {
	// Drop oversized buffers so a single huge payload does not permanently
	// bloat the pool.
	const maxReuse = 64 * 1024
	if b.Cap() > maxReuse {
		return
	}
	bufPool.Put(b)
}

// MaskJSON parses raw as JSON and streams it back out with masking applied.
// Field order is preserved because the implementation walks json.Decoder
// tokens rather than decoding into a map (which randomises key order).
//
// On invalid JSON the input is treated as plain text and value-regex rules
// are applied via MaskString.
func (m *Masker) MaskJSON(raw []byte) []byte {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	buf := getBuf()
	defer putBuf(buf)
	if err := m.encodeValue(dec, buf, ""); err != nil {
		return []byte(m.MaskString(string(raw)))
	}
	out := make([]byte, buf.Len())
	copy(out, buf.Bytes())
	return out
}

// MaskAny applies rules to an already-decoded tree. Map iteration order is
// not stable in Go, so prefer MaskJSON when order matters.
func (m *Masker) MaskAny(v any) any { return m.walk("", v) }

// MaskString applies only value-pattern rules — use for plain-text payloads.
func (m *Masker) MaskString(s string) string { return m.applyValueRules(s) }

// encodeValue consumes exactly one JSON value from dec, applies masking,
// and writes the result to w. `key` is the field name under which this
// value appears in the parent object (empty for root/array elements) and
// drives key-based rules.
func (m *Masker) encodeValue(dec *json.Decoder, w *bytes.Buffer, key string) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	return m.writeToken(dec, w, key, tok)
}

func (m *Masker) writeToken(dec *json.Decoder, w *bytes.Buffer, key string, tok json.Token) error {
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			w.WriteByte('{')
			first := true
			for dec.More() {
				if !first {
					w.WriteByte(',')
				}
				first = false
				kTok, err := dec.Token()
				if err != nil {
					return err
				}
				k, ok := kTok.(string)
				if !ok {
					return fmt.Errorf("expected object key, got %T", kTok)
				}
				writeJSONString(w, k)
				w.WriteByte(':')
				if err := m.encodeValue(dec, w, k); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil { // closing '}'
				return err
			}
			w.WriteByte('}')
		case '[':
			w.WriteByte('[')
			first := true
			for dec.More() {
				if !first {
					w.WriteByte(',')
				}
				first = false
				if err := m.encodeValue(dec, w, key); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil { // closing ']'
				return err
			}
			w.WriteByte(']')
		default:
			return fmt.Errorf("unexpected delimiter %v", t)
		}
	case string:
		v := t
		if fn := m.maskByKey(key); fn != nil {
			v = fn(v)
		} else {
			v = m.applyValueRules(v)
		}
		writeJSONString(w, v)
	case json.Number:
		if fn := m.maskByKey(key); fn != nil {
			writeJSONString(w, fn(t.String()))
		} else {
			w.WriteString(t.String())
		}
	case bool:
		if fn := m.maskByKey(key); fn != nil {
			writeJSONString(w, fn(fmt.Sprint(t)))
		} else if t {
			w.WriteString("true")
		} else {
			w.WriteString("false")
		}
	case nil:
		if fn := m.maskByKey(key); fn != nil {
			writeJSONString(w, fn(""))
		} else {
			w.WriteString("null")
		}
	default:
		return fmt.Errorf("unsupported token type %T", t)
	}
	return nil
}

const hexChars = "0123456789abcdef"

// writeJSONString writes s as a quoted/escaped JSON string directly into w.
// Mirrors encoding/json with SetEscapeHTML(false): only characters that
// MUST be escaped per RFC 8259 are escaped, plus U+2028/U+2029 which Go
// escapes for safety. Invalid UTF-8 bytes are replaced with U+FFFD, same
// as encoding/json. Written without an intermediate Encoder → zero extra
// allocations on the hot path.
func writeJSONString(w *bytes.Buffer, s string) {
	w.WriteByte('"')
	start := 0
	for i := 0; i < len(s); {
		if b := s[i]; b < utf8.RuneSelf {
			// Fast path for printable ASCII that needs no escaping.
			if b >= 0x20 && b != '"' && b != '\\' {
				i++
				continue
			}
			if start < i {
				w.WriteString(s[start:i])
			}
			switch b {
			case '"', '\\':
				w.WriteByte('\\')
				w.WriteByte(b)
			case '\n':
				w.WriteString(`\n`)
			case '\r':
				w.WriteString(`\r`)
			case '\t':
				w.WriteString(`\t`)
			case '\b':
				w.WriteString(`\b`)
			case '\f':
				w.WriteString(`\f`)
			default:
				w.WriteString(`\u00`)
				w.WriteByte(hexChars[b>>4])
				w.WriteByte(hexChars[b&0xF])
			}
			i++
			start = i
			continue
		}
		c, size := utf8.DecodeRuneInString(s[i:])
		if c == utf8.RuneError && size == 1 {
			if start < i {
				w.WriteString(s[start:i])
			}
			w.WriteString("�")
			i += size
			start = i
			continue
		}
		if c == ' ' || c == ' ' {
			if start < i {
				w.WriteString(s[start:i])
			}
			w.WriteString(`\u202`)
			if c == ' ' {
				w.WriteByte('8')
			} else {
				w.WriteByte('9')
			}
			i += size
			start = i
			continue
		}
		i += size
	}
	if start < len(s) {
		w.WriteString(s[start:])
	}
	w.WriteByte('"')
}

// walk is retained for MaskAny. It mirrors the pre-stream behaviour.
func (m *Masker) walk(key string, v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			t[k] = m.walk(k, child)
		}
		return t
	case []any:
		for i, child := range t {
			t[i] = m.walk(key, child)
		}
		return t
	case string:
		if fn := m.maskByKey(key); fn != nil {
			return fn(t)
		}
		return m.applyValueRules(t)
	case json.Number:
		if fn := m.maskByKey(key); fn != nil {
			return fn(t.String())
		}
		return t
	case float64, int, int64, bool, nil:
		if fn := m.maskByKey(key); fn != nil {
			return fn(fmt.Sprint(t))
		}
		return t
	default:
		return t
	}
}
