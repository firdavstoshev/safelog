package masker

import (
	"regexp"
	"strings"
)

// Rule describes one masking rule. A rule fires when any of its Keys matches
// the current JSON/XML field name (case-insensitive) OR when Pattern matches
// the value. The resulting value is produced by Mask.
//
// A rule with LuhnCheck=true additionally requires the matched substring to
// pass the Luhn checksum — intended for PAN detection by value.
type Rule struct {
	Name      string
	Keys      []string
	Pattern   *regexp.Regexp
	LuhnCheck bool
	Mask      MaskFunc
	// URLComponents selects URL-aware masking using this Masker's rules.
	// When true, Mask is ignored.
	URLComponents bool
}

type keyRule struct {
	mask          MaskFunc
	urlComponents bool
}

// Masker applies a set of rules to JSON or XML payloads.
type Masker struct {
	rules   []Rule
	byKey   map[string]keyRule // lower-cased key -> rule
	byValue []Rule             // rules with Pattern set
}

// New builds a Masker from the given rules.
func New(rules []Rule) *Masker {
	m := &Masker{rules: rules, byKey: make(map[string]keyRule)}
	for _, r := range rules {
		if r.URLComponents {
			r.Mask = m.maskURL
		}
		for _, k := range r.Keys {
			m.byKey[strings.ToLower(k)] = keyRule{mask: r.Mask, urlComponents: r.URLComponents}
		}
		if r.Pattern != nil {
			m.byValue = append(m.byValue, r)
		}
	}
	return m
}

// maskByKey returns the mask function registered for a given field name, or
// nil if no rule applies. Case-insensitive without allocation on the hot
// path: the ASCII-fast path writes a lowercased copy into a stack buffer
// and relies on the Go compiler's `m[string(buf)]` optimisation to avoid
// a string allocation during the map lookup.
func (m *Masker) maskByKey(key string) MaskFunc {
	return m.maskByKeyDepth(key, maxURLMaskDepth)
}

func (m *Masker) maskByKeyDepth(key string, remaining int) MaskFunc {
	if len(key) == 0 || len(m.byKey) == 0 {
		return nil
	}
	// Fast path: key is already lowercase ASCII → direct lookup, no alloc.
	if isLowerASCII(key) {
		return m.byKey[key].withDepth(m, remaining)
	}
	var buf [64]byte
	if len(key) <= len(buf) {
		for i := range len(key) {
			c := key[i]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			buf[i] = c
		}
		return m.byKey[string(buf[:len(key)])].withDepth(m, remaining)
	}
	// Fallback for keys longer than 64 bytes — rare in practice.
	return m.byKey[strings.ToLower(key)].withDepth(m, remaining)
}

// withDepth preserves the caller's remaining budget instead of invoking the
// top-level maskURL wrapper, which would reset it for every query parameter.
func (r keyRule) withDepth(m *Masker, remaining int) MaskFunc {
	if r.urlComponents {
		return func(v string) string { return m.maskURLDepth(v, remaining) }
	}
	return r.mask
}

func isLowerASCII(s string) bool {
	for i := range len(s) {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			return false
		}
	}
	return true
}

// applyValueRules runs every value-pattern rule against s.
// Rules run in registration order; the input is unchanged if none match.
func (m *Masker) applyValueRules(s string) string {
	return m.applyPatterns(s, false, maxURLMaskDepth)
}

func (m *Masker) applyComponentRules(s string) string {
	return m.applyPatterns(s, true, maxURLMaskDepth)
}

func (m *Masker) applyPatterns(s string, component bool, remaining int) string {
	for _, r := range m.byValue {
		if component && r.URLComponents {
			continue
		}
		s = r.Pattern.ReplaceAllStringFunc(s, func(match string) string {
			if r.LuhnCheck {
				clean := stripNonDigits(match)
				if !Luhn(clean) {
					return match
				}
				match = clean
			}
			if r.URLComponents {
				return m.maskURLDepth(match, remaining)
			}
			return r.Mask(match)
		})
	}
	return s
}

func stripNonDigits(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// DefaultRules returns a reasonable baseline covering PAN, phone, email,
// CVV, PIN and track2. Extend or override via config.
func DefaultRules() []Rule {
	return []Rule{
		{
			Name:      "pan",
			Keys:      []string{"pan", "cardNumber", "card_number", "primaryAccountNumber"},
			Pattern:   PANRegex,
			LuhnCheck: true,
			Mask:      KeepEnds(4, 4, '*'),
		},
		{
			Name:    "phone",
			Keys:    []string{"phone", "mobile", "msisdn", "phoneNumber"},
			Pattern: PhoneRegex,
			Mask:    KeepLast(4, '*'),
		},
		{
			Name:    "email",
			Keys:    []string{"email", "mail"},
			Pattern: EmailRegex,
			Mask:    Email(),
		},
		{
			Name: "secret",
			Keys: []string{"cvv", "cvv2", "cvc", "pin", "track2", "password", "authorization"},
			Mask: Replace("***"),
		},
		{
			Name: "fio",
			Keys: []string{"firstName", "lastName", "middleName", "fio", "fullName", "holder", "cardHolder", "holderName"},
			Mask: KeepEnds(1, 0, '*'),
		},
		{
			Name: "passport",
			Keys: []string{"passport", "passportNumber", "passportSeries"},
			Mask: KeepEnds(2, 2, '*'),
		},
		{
			Name: "inn/snils",
			Keys: []string{"inn", "snils"},
			Mask: KeepEnds(0, 4, '*'),
		},
	}
}
