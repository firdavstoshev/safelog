package masker

import (
	"bytes"
	"encoding/xml"
	"io"
)

// MaskXML streams the XML payload token-by-token, applying key-based rules
// to element contents and value-pattern rules to everything else. SOAP
// envelopes are supported transparently — the element local name is matched.
func (m *Masker) MaskXML(raw []byte) []byte {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	var out bytes.Buffer
	enc := xml.NewEncoder(&out)

	var stack []string
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return raw
		}
		switch t := tok.(type) {
		case xml.StartElement:
			stack = append(stack, t.Name.Local)
			for i, a := range t.Attr {
				if fn := m.maskByKey(a.Name.Local); fn != nil {
					t.Attr[i].Value = fn(a.Value)
				} else {
					t.Attr[i].Value = m.applyValueRules(a.Value)
				}
			}
			_ = enc.EncodeToken(t)
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			_ = enc.EncodeToken(t)
		case xml.CharData:
			var key string
			if len(stack) > 0 {
				key = stack[len(stack)-1]
			}
			s := string(t)
			if fn := m.maskByKey(key); fn != nil {
				s = fn(s)
			} else {
				s = m.applyValueRules(s)
			}
			_ = enc.EncodeToken(xml.CharData(s))
		default:
			_ = enc.EncodeToken(tok)
		}
	}
	if err := enc.Flush(); err != nil {
		return raw
	}
	return out.Bytes()
}
