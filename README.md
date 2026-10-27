# safelog

Zerolog wrapper with pluggable PII masking for banking integrations.

Designed for services that log partner request/response payloads where
PAN, phone numbers, email, passport numbers and other personal data must
be scrubbed before the log leaves the process. Masking rules are
configurable via YAML — add new keys without a service release.

- Thin wrapper around [`zerolog`](https://github.com/rs/zerolog), keeps
  the familiar chained-event API.
- Masks JSON by **field name** and by **value regex** (with Luhn check
  for PAN).
- Preserves JSON field order (token-stream encoder, not `map[string]any`).
- Also masks XML/SOAP envelopes by element name.
- Zero-allocation hot path for ASCII payloads where possible.
- ~360 MB/s parallel throughput on an M4 for a typical 3 KB response.

## Install

```bash
go get github.com/firdavstoshev/safelog
```

## Quick start

```go
package main

import (
	"os"

	"github.com/firdavstoshev/safelog"
	"github.com/firdavstoshev/safelog/masker"
)

func main() {
	m := masker.New(masker.DefaultRules())
	log := safelog.New(os.Stdout, m)

	reqID := "req-7c8f-42"
	resp := []byte(`{"pan":"5058600012346210","cvv":"123","phone":"+79161234567"}`)

	log.Info().WithRequestID(reqID).
		Str("partner", "visa").
		MaskedJSON("response", resp).
		Msg("partner response received")
}
```

Output:

```json
{"level":"info","X-Request-ID":"req-7c8f-42","partner":"visa","response":{"pan":"5058********6210","cvv":"***","phone":"********4567"},"time":"...","message":"partner response received"}
```

Field order inside `response` matches the input.

## Default rules

`masker.DefaultRules()` covers:

| rule        | keys                                                                           | strategy                                 |
|-------------|--------------------------------------------------------------------------------|------------------------------------------|
| `pan`       | `pan`, `cardNumber`, `card_number`, `primaryAccountNumber`                     | keep first 4 + last 4, PAN regex + Luhn  |
| `phone`     | `phone`, `mobile`, `msisdn`, `phoneNumber`                                     | keep last 4                              |
| `email`     | `email`, `mail`                                                                | keep first char + domain                 |
| `secret`    | `cvv`, `cvv2`, `cvc`, `pin`, `track2`, `password`, `authorization`             | replace with `***`                       |
| `fio`       | `firstName`, `lastName`, `middleName`, `fio`, `fullName`, `holder`, `cardHolder`, `holderName` | keep first char                |
| `passport`  | `passport`, `passportNumber`, `passportSeries`                                 | keep first 2 + last 2                    |
| `inn/snils` | `inn`, `snils`                                                                 | keep last 4                              |

Rules match on field name (case-insensitive). Value-regex rules fire
only when there is no key-based match.

## YAML configuration

```yaml
rules:
  - name: pan
    keys: [pan, cardNumber, primaryAccountNumber]
    pattern: '\b(?:\d[ -]?){12,18}\d\b'
    luhn: true
    strategy: keep_ends
    prefix: 4
    suffix: 4
    mask_char: '*'

  - name: cvv
    keys: [cvv, cvv2, cvc]
    strategy: replace
    replacement: '***'

  - name: internalPassport
    keys: [internalPassport]
    strategy: keep_ends
    prefix: 2
    suffix: 2
```

```go
rules, err := masker.LoadFile("masking.yaml")
if err != nil { /* ... */ }
log := safelog.New(os.Stdout, masker.New(rules))
```

### Strategies

| strategy          | parameters                      | effect                                        |
|-------------------|---------------------------------|-----------------------------------------------|
| `keep_ends`       | `prefix`, `suffix`, `mask_char` | keep N leading + N trailing, mask the rest    |
| `keep_last`       | `suffix`, `mask_char`           | keep N trailing, mask the rest                |
| `keep_first`      | `prefix`, `mask_char`           | keep N leading, mask the rest                 |
| `replace`         | `replacement`                   | replace the whole value                       |
| `email`           | —                               | keep first char of local part + full domain   |
| `initials`        | —                               | `IVANOV IVAN SERGEEVICH` → `I.I.S.`           |
| `fingerprint_pan` | —                               | `5058600012346210` → `BIN=505860\|L4=6210`    |
| `mask_ipv4`       | `prefix`                        | `192.168.1.4:8080` → `192.168.x.x:8080`       |
| `mask_url`        | —                               | `https://api/path?token=X` → `https://api/***`|

## API

### `safelog`

```go
safelog.New(w io.Writer, m *masker.Masker) *Logger
safelog.ContextWithRequestID(ctx context.Context, reqID string) context.Context
safelog.RequestIDFromContext(ctx context.Context) string

(*Logger).SetMasker(m *masker.Masker)       // atomic swap for hot-reload
(*Logger).Masker() *masker.Masker            // current masker (for tests)
(*Logger).Info()  *Event
(*Logger).Warn()  *Event
(*Logger).Error() *Event
(*Logger).Debug() *Event
```

### `Event`

```go
(*Event).WithRequestID(reqID string) *Event   // adds X-Request-ID
(*Event).Ctx(ctx context.Context) *Event      // pulls reqID from context
(*Event).Str(k, v string)        *Event   // passthrough — no masking
(*Event).Int(k string, v int)    *Event
(*Event).Err(err error)          *Event
(*Event).MaskedJSON(k string, payload []byte) *Event
(*Event).MaskedXML (k string, payload []byte) *Event
(*Event).MaskedQuery(k string, raw []byte) *Event   // URL / query string
(*Event).MaskedString(k, v string) *Event
(*Event).MaskedAny(k string, v any) *Event
(*Event).Msg(msg string)
(*Event).Msgf(format string, a ...any)
```

### `masker`

```go
masker.New(rules []Rule) *Masker
masker.DefaultRules() []Rule
masker.Load(data []byte) ([]Rule, error)
masker.LoadFile(path string) ([]Rule, error)

(*Masker).MaskJSON(raw []byte) []byte      // preserves field order
(*Masker).MaskXML (raw []byte) []byte
(*Masker).MaskQuery(raw []byte) []byte     // URL/query, key-based + regex
(*Masker).MaskString(s string) string      // value-regex only
(*Masker).MaskAny(v any) any
```

### Strategies

```go
masker.KeepEnds(prefix, suffix int, mask rune) MaskFunc
masker.KeepLast(n int, mask rune) MaskFunc
masker.KeepFirst(n int, mask rune) MaskFunc
masker.Replace(with string)        MaskFunc
masker.Email()                     MaskFunc
masker.Initials()                  MaskFunc
masker.FingerprintPAN()            MaskFunc
masker.MaskIPv4(keepOctets int)    MaskFunc
masker.MaskURL()                   MaskFunc

// regexes also exported for custom rules
masker.IPv4Regex, masker.IPv6Regex, masker.URLRegex *regexp.Regexp
masker.PANRegex, masker.PhoneRegex, masker.EmailRegex *regexp.Regexp
```

## Benchmarks

Apple M4, Go 1.26.

```
BenchmarkMaskJSON_Small-10          6.6M     540 ns/op     115 MB/s     22 allocs/op
BenchmarkMaskJSON_Large-10         127k    28590 ns/op     172 MB/s   1342 allocs/op
BenchmarkMaskJSON_Parallel-10      274k    13620 ns/op     361 MB/s   1342 allocs/op
BenchmarkMaskString-10             1.5M    2454 ns/op       23 MB/s     15 allocs/op
```

Reproduce:

```bash
go test ./masker/ -bench=. -benchmem -run=^$ -benchtime=3s
```

CPU profile:

```bash
go test ./masker/ -bench=BenchmarkMaskJSON_Large -run=^$ -benchtime=5s -cpuprofile=cpu.pprof
go tool pprof -top masker.test cpu.pprof
```

## Known limitations

- **Query parameter order.** `MaskQuery` re-serialises via
  `url.Values.Encode()`, which sorts keys alphabetically. For a human
  reading logs this is harmless; for byte-stable proxying it is not.
- **XML namespace rewrite.** `encoding/xml` re-serialises namespaces
  into a slightly different form (`xmlns:soap` → `_xmlns:soap`). The
  output is still valid XML and semantically identical, but not
  byte-stable with the input. Acceptable for log output; not suitable
  as a transparent proxy.
- **Map iteration order.** `MaskAny` on `map[string]any` cannot preserve
  key order (Go spec). Use `MaskJSON` on raw bytes when order matters.
- **PAN heuristic.** Value-regex PAN detection requires 13–19 digits
  and a passing Luhn checksum. A 16-digit internal ID that passes Luhn
  will be masked by accident. For known numeric IDs, add their field
  name to a passthrough list (empty-mask rule) or disable `luhn` in
  config.

## Running tests

```bash
go test ./...
go test ./masker/ -race
go test ./masker/ -cover
```

## Hot-reload

The active masker is held via `atomic.Pointer`, so services can swap rules
at runtime without restarting:

```go
// At startup
log := safelog.New(os.Stdout, masker.New(initial))

// Later, triggered by SIGHUP / fsnotify / HTTP admin / ConfigMap watcher
rules, err := masker.LoadFile("/etc/svc/rules.yaml")
if err != nil {
    log.Error().Err(err).Msg("reload failed, keeping previous rules")
    return
}
log.SetMasker(masker.New(rules))
```

Events started before the swap keep their original rules; events opened
after use the new ones. `SetMasker(nil)` panics — never pass nil, always
keep the previous instance on reload error.

## TODO

- **OpenTelemetry correlation.** Pull `trace_id` / `span_id` from
  `context.Context` in `(*Event).Ctx(ctx)` alongside `X-Request-ID`.
- **Sampling / rate limiting.** Delegate to zerolog `.Sample(...)`, or
  add a convenience wrapper for high-volume endpoints.
- **JSONPath / dotted keys.** Rule targeting like `client.phone` or
  `cards[].pan` for finer control over nested payloads.
- **Strict mode.** Mask everything that is not on an allow-list — for
  services where PII inventory is incomplete.
- **Custom JSON scanner.** Replace `encoding/json` tokenizer with a
  hand-rolled scanner to eliminate the remaining ~5% CPU on
  `json.Decoder.Token()` and halve allocs (~1300 → ~600 per 3KB payload).
- **XML byte-stable output.** Current `encoding/xml` rewrites namespace
  prefixes. Needed for proxy use cases; not required for logs.
