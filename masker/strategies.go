package masker

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaskFunc transforms a sensitive value into a masked form.
type MaskFunc func(string) string

// KeepEnds keeps `prefix` leading and `suffix` trailing characters,
// replaces the rest with `mask`. Example: KeepEnds(4, 4, '*') applied to
// "5058600012346210" returns "5058********6210".
//
// Fast path: when `v` is ASCII and `mask` is ASCII, no rune decoding or
// slice allocation happens. This is the common case for PAN/phone/etc.
func KeepEnds(prefix, suffix int, mask rune) MaskFunc {
	maskASCII := mask < utf8.RuneSelf
	return func(v string) string {
		if maskASCII && isASCII(v) {
			n := len(v)
			if n <= prefix+suffix {
				return v
			}
			out := make([]byte, n)
			copy(out, v[:prefix])
			for i := prefix; i < n-suffix; i++ {
				out[i] = byte(mask)
			}
			copy(out[n-suffix:], v[n-suffix:])
			return string(out)
		}
		n := utf8.RuneCountInString(v)
		if n <= prefix+suffix {
			return v
		}
		runes := []rune(v)
		var b strings.Builder
		b.Grow(n)
		b.WriteString(string(runes[:prefix]))
		for range n - prefix - suffix {
			b.WriteRune(mask)
		}
		b.WriteString(string(runes[n-suffix:]))
		return b.String()
	}
}

// KeepLast keeps `n` trailing characters, masks the rest.
func KeepLast(n int, mask rune) MaskFunc {
	maskASCII := mask < utf8.RuneSelf
	return func(v string) string {
		if maskASCII && isASCII(v) {
			total := len(v)
			if total <= n {
				return v
			}
			out := make([]byte, total)
			for i := range total - n {
				out[i] = byte(mask)
			}
			copy(out[total-n:], v[total-n:])
			return string(out)
		}
		total := utf8.RuneCountInString(v)
		if total <= n {
			return v
		}
		runes := []rune(v)
		var b strings.Builder
		b.Grow(total)
		for range total - n {
			b.WriteRune(mask)
		}
		b.WriteString(string(runes[total-n:]))
		return b.String()
	}
}

func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// Replace returns a constant replacement — use for CVV, PIN, track2.
func Replace(with string) MaskFunc {
	return func(string) string { return with }
}

// Email keeps the first character of the local part and the full domain:
// "ivanov@example.com" -> "i*****@example.com".
func Email() MaskFunc {
	return func(v string) string {
		at := strings.LastIndex(v, "@")
		if at <= 1 {
			return Replace("***")(v)
		}
		local := v[:at]
		return string(local[0]) + strings.Repeat("*", len(local)-1) + v[at:]
	}
}

// KeepFirst keeps `n` leading characters, masks the rest. Mirror of
// KeepLast.
func KeepFirst(n int, mask rune) MaskFunc {
	maskASCII := mask < utf8.RuneSelf
	return func(v string) string {
		if maskASCII && isASCII(v) {
			total := len(v)
			if total <= n {
				return v
			}
			out := make([]byte, total)
			copy(out, v[:n])
			for i := n; i < total; i++ {
				out[i] = byte(mask)
			}
			return string(out)
		}
		total := utf8.RuneCountInString(v)
		if total <= n {
			return v
		}
		runes := []rune(v)
		var b strings.Builder
		b.Grow(total)
		b.WriteString(string(runes[:n]))
		for range total - n {
			b.WriteRune(mask)
		}
		return b.String()
	}
}

// Initials splits the value on whitespace and emits "X." for each word,
// using the first rune uppercased:
//
//	"IVANOV IVAN SERGEEVICH" -> "I.I.S."
//	"ivan ivanov"            -> "I.I."
//
// Empty input returns "". Useful for audit-trail formatting of ФИО
// where a full name must not appear but operators still need to spot
// obvious mismatches ("I.I." instead of "P.P." for example).
func Initials() MaskFunc {
	return func(v string) string {
		fields := strings.Fields(v)
		if len(fields) == 0 {
			return ""
		}
		var b strings.Builder
		b.Grow(len(fields) * 2)
		for _, word := range fields {
			r, _ := utf8.DecodeRuneInString(word)
			if r == utf8.RuneError {
				continue
			}
			b.WriteRune(unicode.ToUpper(r))
			b.WriteByte('.')
		}
		return b.String()
	}
}

// FingerprintPAN renders a PAN as "BIN=<6>|L4=<4>" — enough for log
// correlation and fraud triage without the full number. The input is
// stripped of non-digits before formatting. Values shorter than 10
// digits fall back to "***" so a malformed/short field cannot leak
// through accidentally.
//
//	"5058 6000 1234 6210" -> "BIN=505860|L4=6210"
func FingerprintPAN() MaskFunc {
	return func(v string) string {
		digits := stripNonDigits(v)
		if len(digits) < 10 {
			return "***"
		}
		return "BIN=" + digits[:6] + "|L4=" + digits[len(digits)-4:]
	}
}

// MaskIPv4 keeps `keepOctets` leading octets, replaces the rest with
// "x". If an optional ":port" trailer is present, it is passed through
// unchanged (ports are not PII).
//
//	MaskIPv4(2) applied to "192.168.1.4:8080" -> "192.168.x.x:8080"
//	MaskIPv4(0) applied to "10.0.0.1"         -> "x.x.x.x"
func MaskIPv4(keepOctets int) MaskFunc {
	return func(v string) string {
		host, port, hasPort := splitHostPort(v)
		parts := strings.Split(host, ".")
		if len(parts) != 4 {
			return v
		}
		for i := keepOctets; i < 4; i++ {
			parts[i] = "x"
		}
		out := strings.Join(parts, ".")
		if hasPort {
			out += ":" + port
		}
		return out
	}
}

// MaskURL keeps scheme + host (+ port) and drops the path, query and
// fragment. Useful for logging outbound HTTP calls where the host is a
// safe-to-log business signal but the full URL may contain tokens or
// PII in path/query.
//
//	MaskURL()("https://api.bank.ru/v2/clients/12345?token=abc")
//	-> "https://api.bank.ru/***"
func MaskURL() MaskFunc {
	return func(v string) string {
		slash := strings.Index(v, "://")
		if slash < 0 {
			return "***"
		}
		rest := v[slash+3:]
		end := strings.IndexAny(rest, "/?#")
		if end < 0 {
			return v // scheme://host only, nothing to strip
		}
		return v[:slash+3+end] + "/***"
	}
}

// splitHostPort returns host, port, hasPort. Does not resolve IPv6
// brackets — fine for the IPv4 helper above.
func splitHostPort(s string) (string, string, bool) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return s, "", false
	}
	host, port := s[:i], s[i+1:]
	for j := 0; j < len(port); j++ {
		if port[j] < '0' || port[j] > '9' {
			return s, "", false
		}
	}
	return host, port, true
}
