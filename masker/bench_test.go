package masker

import "testing"

var smallPayload = []byte(`{"pan":"5058600012346210","phone":"+79161234567","amount":100}`)

var largePayload = buildLargePayload()

func buildLargePayload() []byte {
	// Simulate a typical partner response: 20 transactions, each with
	// client + card fields.
	buf := []byte(`{"transactions":[`)
	for i := range 20 {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = append(buf,
			`{"id":`...)
		buf = append(buf, byte('0'+i%10))
		buf = append(buf,
			`,"client":{"firstName":"Ivan","lastName":"Ivanov","phone":"+79161234567","email":"ivanov@example.com","inn":"773401234567"},`+
				`"card":{"pan":"5058600012346210","cvv":"123","holder":"IVANOV IVAN"},`+
				`"amount":1500.50,"currency":"RUB","ok":true}`...)
	}
	buf = append(buf, `]}`...)
	return buf
}

func BenchmarkMaskJSON_Small(b *testing.B) {
	m := New(DefaultRules())
	b.ReportAllocs()
	b.SetBytes(int64(len(smallPayload)))
	for b.Loop() {
		_ = m.MaskJSON(smallPayload)
	}
}

func BenchmarkMaskJSON_Large(b *testing.B) {
	m := New(DefaultRules())
	b.ReportAllocs()
	b.SetBytes(int64(len(largePayload)))
	for b.Loop() {
		_ = m.MaskJSON(largePayload)
	}
}

func BenchmarkMaskJSON_Parallel(b *testing.B) {
	m := New(DefaultRules())
	b.ReportAllocs()
	b.SetBytes(int64(len(largePayload)))
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = m.MaskJSON(largePayload)
		}
	})
}

func BenchmarkMaskString(b *testing.B) {
	m := New(DefaultRules())
	s := "Payment approved, call +79161234567 or ivanov@example.com"
	b.ReportAllocs()
	b.SetBytes(int64(len(s)))
	for b.Loop() {
		_ = m.MaskString(s)
	}
}
