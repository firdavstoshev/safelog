package masker

import (
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func TestMaskQueryBareValueContainingURLDelimiters(t *testing.T) {
	m := newDefault()
	for _, input := range []string{
		"password=secret?next=1",
		"password=secret#section?next=1",
		"password=http://a/path?next=1&amount=100",
	} {
		got := string(m.MaskQuery([]byte(input)))
		if strings.Contains(got, "secret") || strings.Contains(got, "http") || !strings.Contains(got, "password=%2A%2A%2A") {
			t.Errorf("MaskQuery(%q) = %q: sensitive bare-query value was not replaced", input, got)
		}
	}
	// A relative URL can contain '=' in its query; it is not a bare query.
	input := "charge?password=secret#section"
	if got := string(m.MaskQuery([]byte(input))); got != "charge?password=%2A%2A%2A#section" {
		t.Fatal(got)
	}
}

func TestNestedURLDepthBudget(t *testing.T) {
	for _, patternRule := range []bool{false, true} {
		for _, entry := range []string{"URL", "Query", "JSON", "String"} {
			t.Run(entry+map[bool]string{false: "/key", true: "/pattern"}[patternRule], func(t *testing.T) {
				visits := 0
				nestedRule := Rule{Keys: []string{"callback"}, URLComponents: true}
				if patternRule {
					nestedRule.Keys = nil
					nestedRule.Pattern = URLRegex
				}
				rules := []Rule{nestedRule, {Keys: []string{"requestUrl"}, URLComponents: true}, {Pattern: regexp.MustCompile(`\ba\b`), Mask: func(s string) string { visits++; return s }}}
				if entry == "String" && !patternRule {
					rules = append([]Rule{{Pattern: URLRegex, URLComponents: true}}, rules...)
				}
				m := New(rules)
				input := strings.Repeat("http://a/?callback=", 64) + "bottom-secret"
				var got string
				switch entry {
				case "URL":
					got = string(m.MaskURL([]byte(input)))
				case "Query":
					got = string(m.MaskQuery([]byte("?callback=" + input)))
				case "JSON":
					got = string(m.MaskJSON([]byte(`{"requestUrl":"` + input + `"}`)))
				case "String":
					got = m.MaskString(input)
				}
				// Pattern rules may also visit the outer host after masking the URL.
				if visits > 2*maxURLMaskDepth {
					t.Errorf("visited %d URL hosts; depth budget was reset", visits)
				}
				if strings.Contains(got, "bottom-secret") {
					t.Error("unprocessed nested value leaked")
				}
			})
		}
	}
}

func TestNestedURLBudgetBoundary(t *testing.T) {
	m := New(append(DefaultRules(), Rule{Keys: []string{"callback"}, Pattern: URLRegex, URLComponents: true}))
	for _, levels := range []int{maxURLMaskDepth, maxURLMaskDepth + 1} {
		input := "http://a/?password=secret"
		for i := 1; i < levels; i++ {
			input = "http://a/?callback=" + url.QueryEscape(input)
		}
		got := string(m.MaskURL([]byte(input)))
		for i := 1; i < levels; i++ {
			u, err := url.Parse(got)
			if err != nil {
				t.Fatal(err)
			}
			got = u.Query().Get("callback")
		}
		if levels > maxURLMaskDepth {
			if got != "***" {
				t.Fatalf("expected remaining URL to be replaced, got %q", got)
			}
		} else {
			u, err := url.Parse(got)
			if err != nil {
				t.Fatal(err)
			}
			if u.Query().Get("password") != "***" {
				t.Fatalf("shallow nested URL not masked: %s", got)
			}
		}
	}
}
