package masker

import "regexp"

// PANRegex matches a 13-19 digit sequence that may contain spaces or dashes.
// After matching, strip separators and verify with Luhn before masking —
// otherwise long numeric IDs get mangled.
var PANRegex = regexp.MustCompile(`\b(?:\d[ -]?){12,18}\d\b`)

// PhoneRegex matches a Russian-style phone number.
var PhoneRegex = regexp.MustCompile(`\+?7[\s\-()]*\d{3}[\s\-()]*\d{3}[\s\-()]*\d{2}[\s\-()]*\d{2}`)

// EmailRegex matches a conservative email pattern.
var EmailRegex = regexp.MustCompile(`[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}`)

// IPv4Regex matches a dotted-decimal IPv4 address. Does not range-check
// individual octets — "999.999.999.999" matches. Combine with a Mask
// func that validates when strictness matters.
var IPv4Regex = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b`)

// IPv6Regex matches a conservative IPv6 pattern (full form or compressed
// with "::"). Zone identifiers and dot-decimal mixed form are not
// supported.
var IPv6Regex = regexp.MustCompile(`\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b|::(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4}\b`)

// URLRegex matches http/https URLs. Credentials (user:pass@) and
// query/fragment are captured as part of the match so a Mask func can
// strip them.
var URLRegex = regexp.MustCompile(`\bhttps?://[^\s"'<>]+`)

// Luhn returns true if the digits in s pass the Luhn checksum.
// Non-digit characters are ignored.
func Luhn(s string) bool {
	sum := 0
	alt := false
	count := 0
	for i := len(s) - 1; i >= 0; i-- {
		c := s[i]
		if c < '0' || c > '9' {
			continue
		}
		d := int(c - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
		count++
	}
	return count >= 12 && sum%10 == 0
}
