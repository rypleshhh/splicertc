//go:build windows

package procmap

import (
	"testing"
	"time"
)

// Refresh with a warm pid cache: the steady state of the 2 s ticker.
func BenchmarkRefresh(b *testing.B) {
	t := New()
	if err := t.Refresh(); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for b.Loop() {
		if err := t.Refresh(); err != nil {
			b.Fatal(err)
		}
	}
}

// Refresh with an empty pid cache: every process is opened again.
func BenchmarkRefreshCold(b *testing.B) {
	for b.Loop() {
		if err := New().Refresh(); err != nil {
			b.Fatal(err)
		}
	}
}

// RefreshIfOlder inside the rate limit only checks the time.
func BenchmarkRefreshIfOlderSkipped(b *testing.B) {
	t := New()
	if err := t.Refresh(); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for b.Loop() {
		if _, err := t.RefreshIfOlder(time.Hour); err != nil {
			b.Fatal(err)
		}
	}
}
