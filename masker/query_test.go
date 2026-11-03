package masker

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func urlTestMasker() *Masker {
	return New(append(DefaultRules(), Rule{Name: "ip", Pattern: IPv4Regex, Mask: MaskIPv4(2)}))
}

func TestMaskURLComponents(t *testing.T) {
	m := urlTestMasker()
	tests := []struct{ name, input, want string }{
		{"full URL", "http://192.168.1.4:8080/charge?password=secret&amount=100", "http://192.168.x.x:8080/charge?amount=100&password=%2A%2A%2A"},
		{"leading question", "?password=secret", "?password=%2A%2A%2A"},
		{"encoded key and repeated values", "/charge?pass%77ord=one&password=two&amount=100", "/charge?amount=100&password=%2A%2A%2A&password=%2A%2A%2A"},
		{"encoded unknown value", "/charge?note=ivanov%40example.com", "/charge?note=i%2A%2A%2A%2A%2A%40example.com"},
		{"IPv6 host retained without IPv6 rule", "http://[2001:db8::1]:8080/?password=secret", "http://[2001:db8::1]:8080/?password=%2A%2A%2A"},
		{"malformed path", "http://192.168.1.4/%ZZ?password=secret", "***"},
		{"IP query value", "http://192.168.1.4/?peer=10.20.30.40", "http://192.168.x.x/?peer=10.20.x.x"},
		{"path and fragment", "http://192.168.1.4/peer/10.20.30.40?password=secret#10.20.30.40", "http://192.168.x.x/peer/10.20.x.x?password=%2A%2A%2A#10.20.x.x"},
		{"encoded path and fragment", "https://api/peer/10%2E20%2E30%2E40#10%2E20%2E30%2E40", "https://***/peer/10.20.x.x#10.20.x.x"},
		{"unchanged escaping", "https://api/a%2Fb?amount=100#c%2Fd", "https://***/a%2Fb?amount=100#c%2Fd"},
		{"no query", "http://192.168.1.4:8080/charge", "http://192.168.x.x:8080/charge"},
		{"fragment without path", "http://192.168.1.4?password=secret#section", "http://192.168.x.x?password=%2A%2A%2A#section"},
		{"credentials", "https://user:secret@192.168.1.4/?password=secret", "https://%2A%2A%2A@192.168.x.x/?password=%2A%2A%2A"},
		{"malformed query", "http://192.168.1.4/?password=%ZZ&amount=100", "http://192.168.x.x/?***"},
		{"malformed URL", "http://[bad/charge?password=secret", "***"},
		{"empty query", "https://api/path?", "https://***/path?"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(m.MaskURL([]byte(tt.input))); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestURLComponentsStrategy(t *testing.T) {
	rules, err := Load([]byte(`rules:
  - name: url
    keys: [requestUrl]
    pattern: '\bhttps?://[^\s"''<>]+'
    strategy: mask_url_components
  - name: ip
    pattern: '\b(?:\d{1,3}\.){3}\d{1,3}\b'
    strategy: mask_ipv4
    prefix: 2
  - name: password
    keys: [password]
    strategy: replace
`))
	if err != nil {
		t.Fatal(err)
	}
	m := New(rules)
	input := "http://192.168.1.4/path?password=secret&peer=10.20.30.40"
	want := "http://192.168.x.x/path?password=%2A%2A%2A&peer=10.20.x.x"
	var decoded map[string]string
	payload, _ := json.Marshal(map[string]string{"requestUrl": input})
	if err := json.Unmarshal(m.MaskJSON(payload), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["requestUrl"] != want {
		t.Fatalf("JSON: got %q, want %q", decoded["requestUrl"], want)
	}
	if got := m.MaskAny(map[string]any{"REQUESTURL": input}).(map[string]any)["REQUESTURL"]; got != want {
		t.Fatalf("MaskAny: got %q, want %q", got, want)
	}
	if got := m.MaskString("calling " + input); got != "calling "+want {
		t.Fatalf("regex: %s", got)
	}
	if got := string(m.MaskXML([]byte("<requestUrl>" + strings.ReplaceAll(input, "&", "&amp;") + "</requestUrl>"))); !strings.Contains(got, strings.ReplaceAll(want, "&", "&amp;")) {
		t.Fatalf("XML: %s", got)
	}
}

func TestURLComponentsGoRuleAndNestedURL(t *testing.T) {
	rules := append(DefaultRules(), Rule{Pattern: IPv4Regex, Mask: MaskIPv4(2)}, Rule{Keys: []string{"callback"}, URLComponents: true})
	m := New(rules)
	nested := "http://10.20.30.40/?password=secret"
	got := string(m.MaskURL([]byte("http://192.168.1.4/?callback=" + url.QueryEscape(nested))))
	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if want := "http://10.20.x.x/?password=%2A%2A%2A"; u.Query().Get("callback") != want {
		t.Fatalf("nested URL: %s", got)
	}
	if strings.Contains(got, "192.168.1.4") {
		t.Fatalf("host exposed: %s", got)
	}
}

func TestMaskQueryPreservesURLComponents(t *testing.T) {
	m := urlTestMasker()
	tests := []struct{ input, want string }{
		{"http://192.168.1.4:8080/10.20.30.40?password=secret&peer=10.20.30.40#10.20.30.40", "http://192.168.1.4:8080/10.20.30.40?password=%2A%2A%2A&peer=10.20.x.x#10.20.30.40"},
		{"https://user:secret@192.168.1.4/a%2Fb?password=secret#c%2Fd", "https://user:secret@192.168.1.4/a%2Fb?password=%2A%2A%2A#c%2Fd"},
		{"http://192.168.1.4/path#fragment?password=secret", "http://192.168.1.4/path#fragment?password=secret"},
		{"http://192.168.1.4/path", "http://192.168.1.4/path"},
		{"relative/10.20.30.40#10.20.30.40", "relative/10.20.30.40#10.20.30.40"},
		{"callback=http://192.168.1.4/path", "callback=http%3A%2F%2F192.168.x.x%2Fpath"},
		{"password=secret&amount=100", "amount=100&password=%2A%2A%2A"},
		{"?password=secret", "?password=%2A%2A%2A"},
		{"/path?password=%ZZ#section", "/path?***#section"},
		{"password=secret;amount=100", "***"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := string(m.MaskQuery([]byte(tt.input))); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}
