package masker

import (
	"strings"
	"testing"
)

func newDefault() *Masker { return New(DefaultRules()) }

func TestKeepEnds_PAN(t *testing.T) {
	m := KeepEnds(4, 4, '*')
	got := m("5058600012346210")
	want := "5058********6210"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestMaskJSON_PANByKey(t *testing.T) {
	in := []byte(`{"pan":"5058600012346210","amount":100}`)
	out := newDefault().MaskJSON(in)
	if !strings.Contains(string(out), `"pan":"5058********6210"`) {
		t.Fatalf("pan not masked: %s", out)
	}
	if !strings.Contains(string(out), `"amount":100`) {
		t.Fatalf("amount mangled: %s", out)
	}
}

func TestMaskJSON_PANByValueLuhn(t *testing.T) {
	// Key is unknown but value looks like a card and passes Luhn.
	in := []byte(`{"note":"card 4111 1111 1111 1111 charged"}`)
	out := newDefault().MaskJSON(in)
	if strings.Contains(string(out), "4111 1111 1111 1111") {
		t.Fatalf("pan leaked: %s", out)
	}
}

func TestMaskJSON_LongIdNotTouched(t *testing.T) {
	// A 16-digit identifier that does NOT pass Luhn must be preserved.
	in := []byte(`{"id":"1234567890123456"}`)
	out := newDefault().MaskJSON(in)
	if !strings.Contains(string(out), `"1234567890123456"`) {
		t.Fatalf("non-pan id was masked: %s", out)
	}
}

func TestMaskJSON_NestedAndArray(t *testing.T) {
	in := []byte(`{"client":{"phone":"+79161234567","email":"ivanov@example.com"},"cards":[{"pan":"5058600012346210"}]}`)
	out := newDefault().MaskJSON(in)
	s := string(out)
	for _, bad := range []string{"5058600012346210", "+79161234567", "ivanov@example.com"} {
		if strings.Contains(s, bad) {
			t.Fatalf("leak %q in %s", bad, s)
		}
	}
}

func TestMaskJSON_CVVReplaced(t *testing.T) {
	in := []byte(`{"cvv":"123"}`)
	out := newDefault().MaskJSON(in)
	if !strings.Contains(string(out), `"cvv":"***"`) {
		t.Fatalf("cvv not replaced: %s", out)
	}
}

func TestMaskXML_SOAPEnvelope(t *testing.T) {
	soap := []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetCard><pan>5058600012346210</pan><cvv>123</cvv></GetCard>
  </soap:Body>
</soap:Envelope>`)
	out := string(newDefault().MaskXML(soap))
	if !strings.Contains(out, "5058********6210") {
		t.Fatalf("xml pan not masked: %s", out)
	}
	if strings.Contains(out, ">123<") {
		t.Fatalf("xml cvv leaked: %s", out)
	}
}

func TestLoadYAMLRules(t *testing.T) {
	yaml := []byte(`
rules:
  - name: pan
    keys: [pan, cardNumber]
    strategy: keep_ends
    prefix: 4
    suffix: 4
  - name: secret
    keys: [cvv]
    strategy: replace
    replacement: '###'
`)
	rules, err := Load(yaml)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	m := New(rules)
	out := m.MaskJSON([]byte(`{"pan":"5058600012346210","cvv":"999"}`))
	s := string(out)
	if !strings.Contains(s, "5058********6210") || !strings.Contains(s, `"cvv":"###"`) {
		t.Fatalf("yaml rules wrong: %s", s)
	}
}

func TestMaskJSON_PreservesFieldOrder(t *testing.T) {
	// Field order matters for log readability and for byte-stable diffs.
	in := []byte(`{"status":"ok","pan":"5058600012346210","amount":100,"client":{"email":"ivanov@example.com","phone":"+79161234567"},"ts":1700000000}`)
	want := `{"status":"ok","pan":"5058********6210","amount":100,"client":{"email":"i*****@example.com","phone":"********4567"},"ts":1700000000}`
	got := string(newDefault().MaskJSON(in))
	if got != want {
		t.Fatalf("order/content mismatch\nwant %s\ngot  %s", want, got)
	}
}

func TestMaskJSON_NumberStaysNumber(t *testing.T) {
	// Non-masked numeric fields must stay numeric (no quoting).
	in := []byte(`{"amount":100.5,"count":42}`)
	got := string(newDefault().MaskJSON(in))
	if got != `{"amount":100.5,"count":42}` {
		t.Fatalf("number mangled: %s", got)
	}
}

func TestMaskJSON_BoolAndNull(t *testing.T) {
	in := []byte(`{"ok":true,"err":null}`)
	got := string(newDefault().MaskJSON(in))
	if got != `{"ok":true,"err":null}` {
		t.Fatalf("bool/null mangled: %s", got)
	}
}

func TestMaskQuery_PathAndParams(t *testing.T) {
	in := []byte("/charge?pan=5058600012346210&cvv=123&amount=100")
	got := string(newDefault().MaskQuery(in))
	if !strings.Contains(got, "pan=5058%2A%2A%2A%2A%2A%2A%2A%2A6210") &&
		!strings.Contains(got, "pan=5058********6210") {
		t.Fatalf("pan not masked: %s", got)
	}
	if !strings.Contains(got, "cvv=%2A%2A%2A") && !strings.Contains(got, "cvv=***") {
		t.Fatalf("cvv not masked: %s", got)
	}
	if !strings.Contains(got, "amount=100") {
		t.Fatalf("amount mangled: %s", got)
	}
	if !strings.HasPrefix(got, "/charge?") {
		t.Fatalf("prefix lost: %s", got)
	}
}

func TestMaskQuery_TestCardWithoutLuhn(t *testing.T) {
	// pan=... value fails Luhn but the KEY tells us it is a card.
	// Key-based rule must fire regardless.
	in := []byte("/charge?pan=1234567890123456")
	got := string(newDefault().MaskQuery(in))
	if strings.Contains(got, "1234567890123456") {
		t.Fatalf("test card leaked: %s", got)
	}
}

func TestMaskQuery_UnknownKey_FallsToRegex(t *testing.T) {
	// Unknown parameter name — value regex still catches phone.
	in := []byte("/sms?body=call+%2B79161234567")
	got := string(newDefault().MaskQuery(in))
	if strings.Contains(got, "79161234567") {
		t.Fatalf("phone leaked: %s", got)
	}
}

func TestMaskQuery_NoQueryString(t *testing.T) {
	// No '?' — treat as plain string, regex rules only.
	in := []byte("ivanov@example.com")
	got := string(newDefault().MaskQuery(in))
	if got != "i*****@example.com" {
		t.Fatalf("want masked email, got %q", got)
	}
}

func TestKeepFirst(t *testing.T) {
	got := KeepFirst(2, '*')("IVANOV")
	if got != "IV****" {
		t.Fatalf("got %q, want IV****", got)
	}
	// Short input stays unchanged.
	if KeepFirst(10, '*')("abc") != "abc" {
		t.Fatal("short input should pass through")
	}
}

func TestInitials(t *testing.T) {
	cases := map[string]string{
		"IVANOV IVAN SERGEEVICH": "I.I.S.",
		"ivan ivanov":            "I.I.",
		"Ivan":                   "I.",
		"":                       "",
		"   ":                    "",
		"Пётр Петров":            "П.П.",
	}
	for in, want := range cases {
		if got := Initials()(in); got != want {
			t.Fatalf("Initials(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFingerprintPAN(t *testing.T) {
	cases := map[string]string{
		"5058600012346210":    "BIN=505860|L4=6210",
		"5058 6000 1234 6210": "BIN=505860|L4=6210",
		"short":               "***",
		"":                    "***",
	}
	for in, want := range cases {
		if got := FingerprintPAN()(in); got != want {
			t.Fatalf("FingerprintPAN(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLoadYAMLRules_NewStrategies(t *testing.T) {
	yaml := []byte(`
rules:
  - name: fio
    keys: [firstName, lastName]
    strategy: initials
  - name: pan
    keys: [pan]
    strategy: fingerprint_pan
  - name: nick
    keys: [nick]
    strategy: keep_first
    prefix: 2
`)
	rules, err := Load(yaml)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	m := New(rules)
	in := []byte(`{"firstName":"Ivan","lastName":"Ivanov","pan":"5058600012346210","nick":"Admin"}`)
	got := string(m.MaskJSON(in))
	for _, want := range []string{
		`"firstName":"I."`,
		`"lastName":"I."`,
		`"pan":"BIN=505860|L4=6210"`,
		`"nick":"Ad***"`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in %s", want, got)
		}
	}
}

func TestMaskIPv4(t *testing.T) {
	cases := []struct {
		in, want string
		keep     int
	}{
		{"192.168.1.4", "192.168.x.x", 2},
		{"192.168.1.4:8080", "192.168.x.x:8080", 2},
		{"10.0.0.1", "x.x.x.x", 0},
		{"8.8.8.8", "8.x.x.x", 1},
		{"not-ip", "not-ip", 2},
	}
	for _, c := range cases {
		got := MaskIPv4(c.keep)(c.in)
		if got != c.want {
			t.Fatalf("MaskIPv4(%d)(%q) = %q, want %q", c.keep, c.in, got, c.want)
		}
	}
}

func TestMaskURL(t *testing.T) {
	cases := map[string]string{
		"https://api.bank.ru/v2/clients/12345?token=abc": "https://api.bank.ru/***",
		"http://localhost:8080/foo?bar=1":               "http://localhost:8080/***",
		"https://api.bank.ru":                           "https://api.bank.ru",
		"not-a-url":                                     "***",
	}
	for in, want := range cases {
		if got := MaskURL()(in); got != want {
			t.Fatalf("MaskURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIPv4Regex_InValueRule(t *testing.T) {
	rules := []Rule{{
		Name:    "ip",
		Pattern: IPv4Regex,
		Mask:    MaskIPv4(2),
	}}
	m := New(rules)
	got := m.MaskString("connection from 192.168.1.4:8080 refused")
	if !strings.Contains(got, "192.168.x.x:8080") {
		t.Fatalf("ip not masked: %s", got)
	}

}

func TestURLRegex_InValueRule(t *testing.T) {
	rules := []Rule{{
		Name:    "url",
		Pattern: URLRegex,
		Mask:    MaskURL(),
	}}
	m := New(rules)
	got := m.MaskString("fetching https://api.bank.ru/v1/pay?token=secret now")
	if !strings.Contains(got, "https://api.bank.ru/***") {
		t.Fatalf("url not masked: %s", got)
	}
	if strings.Contains(got, "token=secret") {
		t.Fatalf("token leaked: %s", got)
	}
}

func TestLuhn(t *testing.T) {
	if !Luhn("4111111111111111") {
		t.Fatal("4111... must pass Luhn")
	}
	if Luhn("1234567890123456") {
		t.Fatal("1234... must fail Luhn")
	}
}
