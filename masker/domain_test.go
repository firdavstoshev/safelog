package masker

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func TestMaskURLDomainHost(t *testing.T) {
	m := newDefault()
	tests := []struct{ input, want string }{
		{"https://api.example.com/path?password=secret", "https://***/path?password=%2A%2A%2A"},
		{"https://api.example.com:8443/a%2Fb?amount=100#c%2Fd", "https://***:8443/a%2Fb?amount=100#c%2Fd"},
		{"https://API.Example.COM./", "https://***/"},
		{"https://xn--bcher-kva.example/", "https://***/"},
		{"https://bücher.example/", "https://***/"},
		{"http://localhost:8080/", "http://***:8080/"},
		{"//api.example.com/path?password=secret", "//***/path?password=%2A%2A%2A"},
		{"https://user:secret@api.example.com/path", "https://%2A%2A%2A@***/path"},
		{"https://api.example.com", "https://***"},
		{"/path?password=secret", "/path?password=%2A%2A%2A"},
		{"http://192.168.1.4:8080/", "http://192.168.1.4:8080/"},
		{"http://[2001:db8::1]:8080/", "http://[2001:db8::1]:8080/"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := string(m.MaskURL([]byte(tt.input))); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDomainURLFieldAndNestedCallback(t *testing.T) {
	rules, err := Load([]byte(`rules:
  - keys: [requestUrl, callback]
    pattern: '\bhttps?://[^\s"''<>]+'
    strategy: mask_url_components
`))
	if err != nil {
		t.Fatal(err)
	}
	m := New(append(DefaultRules(), rules...))
	input := "https://api.example.com/path?password=secret"
	want := "https://***/path?password=%2A%2A%2A"
	payload, _ := json.Marshal(map[string]string{"requestUrl": input})
	var got map[string]string
	if err := json.Unmarshal(m.MaskJSON(payload), &got); err != nil {
		t.Fatal(err)
	}
	if got["requestUrl"] != want {
		t.Fatal(got)
	}
	if got := m.MaskString("calling " + input); got != "calling "+want {
		t.Fatal(got)
	}
	nested := string(m.MaskURL([]byte("https://api.example.com/?callback=" + url.QueryEscape(input))))
	u, err := url.Parse(nested)
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "***" || u.Query().Get("callback") != want {
		t.Fatal(nested)
	}
	// Query-only masking preserves the domain host.
	if got := string(m.MaskQuery([]byte(input))); got != strings.Replace(want, "***", "api.example.com", 1) {
		t.Fatal(got)
	}
}
