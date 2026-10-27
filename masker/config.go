package masker

import (
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

// Config is the YAML schema for loadable rules.
//
//	rules:
//	  - name: pan
//	    keys: [pan, cardNumber]
//	    pattern: '\b(?:\d[ -]?){12,18}\d\b'
//	    luhn: true
//	    strategy: keep_ends
//	    prefix: 4
//	    suffix: 4
//	    mask_char: '*'
//	  - name: cvv
//	    keys: [cvv, cvv2]
//	    strategy: replace
//	    replacement: '***'
type Config struct {
	Rules []RuleConfig `yaml:"rules"`
}

type RuleConfig struct {
	Name        string   `yaml:"name"`
	Keys        []string `yaml:"keys"`
	Pattern     string   `yaml:"pattern"`
	Luhn        bool     `yaml:"luhn"`
	Strategy    string   `yaml:"strategy"`
	Prefix      int      `yaml:"prefix"`
	Suffix      int      `yaml:"suffix"`
	MaskChar    string   `yaml:"mask_char"`
	Replacement string   `yaml:"replacement"`
}

// LoadFile reads a YAML config and compiles it into Rules.
func LoadFile(path string) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Load(data)
}

// Load compiles a YAML blob into Rules.
func Load(data []byte) ([]Rule, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	rules := make([]Rule, 0, len(cfg.Rules))
	for i, rc := range cfg.Rules {
		r, err := rc.compile()
		if err != nil {
			return nil, fmt.Errorf("rule[%d] %q: %w", i, rc.Name, err)
		}
		rules = append(rules, r)
	}
	return rules, nil
}

func (rc RuleConfig) compile() (Rule, error) {
	r := Rule{Name: rc.Name, Keys: rc.Keys, LuhnCheck: rc.Luhn}
	if rc.Pattern != "" {
		p, err := regexp.Compile(rc.Pattern)
		if err != nil {
			return r, fmt.Errorf("compile pattern: %w", err)
		}
		r.Pattern = p
	}
	mask := '*'
	if rc.MaskChar != "" {
		mask = []rune(rc.MaskChar)[0]
	}
	switch rc.Strategy {
	case "keep_ends":
		r.Mask = KeepEnds(rc.Prefix, rc.Suffix, mask)
	case "keep_last":
		r.Mask = KeepLast(rc.Suffix, mask)
	case "keep_first":
		r.Mask = KeepFirst(rc.Prefix, mask)
	case "initials":
		r.Mask = Initials()
	case "fingerprint_pan":
		r.Mask = FingerprintPAN()
	case "mask_ipv4":
		r.Mask = MaskIPv4(rc.Prefix)
	case "mask_url":
		r.Mask = MaskURL()
	case "replace":
		rep := rc.Replacement
		if rep == "" {
			rep = "***"
		}
		r.Mask = Replace(rep)
	case "email":
		r.Mask = Email()
	default:
		return r, fmt.Errorf("unknown strategy %q", rc.Strategy)
	}
	return r, nil
}
