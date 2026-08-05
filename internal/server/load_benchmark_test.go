package server

import "testing"

func BenchmarkForwardedParser(b *testing.B) {
	raw := "for=192.0.2.1, for=198.51.100.2, for=203.0.113.4"
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := parseForwardedChain(raw); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRequestIDValidation(b *testing.B) {
	value := "00000000-0000-4000-8000-000000000000"
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if !validRequestID(value) {
			b.Fatal("request ID rejected")
		}
	}
}
