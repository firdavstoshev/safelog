package masker

import (
	"net/netip"
	"net/url"
)

// maxURLMaskDepth bounds nested URL parsing and repeated query encoding.
// Each descent through a URLComponents rule consumes one level.
const maxURLMaskDepth = 8

// MaskURL replaces domain hosts with "***" and masks IP hosts, paths and
// fragments using value-regex rules. Decoded query parameters use key/value
// rules. URL credentials are replaced
// with "***". Invalid URLs are replaced with "***"; invalid queries are replaced
// in full. Accepts absolute and relative URLs. Nested URLs beyond eight levels
// are replaced with "***".
func (m *Masker) MaskURL(raw []byte) []byte {
	return []byte(m.maskURL(string(raw)))
}

// maskURL is also bound to URLComponents rules as a MaskFunc.
func (m *Masker) maskURL(s string) string {
	return m.maskURLDepth(s, maxURLMaskDepth)
}

func (m *Masker) maskURLDepth(s string, remaining int) string {
	if remaining <= 0 {
		return "***"
	}
	u, err := url.Parse(s)
	if err != nil {
		return "***"
	}
	// Opaque URLs do not expose separately parseable path/query components.
	if u.Opaque != "" {
		return "***"
	}
	hostname, port := u.Hostname(), u.Port()
	u.Host = m.applyComponentRules(u.Host)
	// Classify the original host before regex rules turn an IP into masked text.
	// Parsing an address is local and does not resolve DNS names.
	if _, err := netip.ParseAddr(hostname); hostname != "" && err != nil {
		u.Host = "***"
		if port != "" {
			u.Host += ":" + port
		}
	}
	if u.User != nil {
		u.User = url.User("***")
	}
	if path := m.applyComponentRules(u.Path); path != u.Path {
		u.Path, u.RawPath = path, ""
	}
	if fragment := m.applyComponentRules(u.Fragment); fragment != u.Fragment {
		u.Fragment, u.RawFragment = fragment, ""
	}
	if u.RawQuery != "" {
		u.RawQuery = m.maskQueryValuesDepth(u.RawQuery, remaining-1)
	}
	return u.String()
}
