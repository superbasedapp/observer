package termsession

import (
	"testing"
	"time"
)

// TestStripOSC52RemovesClipboardSequences (WINFIX4 audit finding 2, ruling
// P-175): a session whose spec asks for it never shows a viewer an OSC 52
// sequence, also one the process wrote in two pieces; a session that does
// not ask passes the bytes as written.
func TestStripOSC52RemovesClipboardSequences(t *testing.T) {
	for _, strip := range []bool{true, false} {
		sp := &fakeSpawner{}
		m := newTestManager(t, sp, time.Now)
		spec := validSpec()
		spec.StripOSC52 = strip
		tok, err := m.Create(spec)
		if err != nil {
			t.Fatal(err)
		}
		f := sp.last()
		sub, err := m.Subscribe(tok)
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			f.emit([]byte("a\x1b]5"))
			f.emit([]byte("2;c;aGk=\x07b"))
		}()
		want := "ab"
		if !strip {
			want = "a\x1b]52;c;aGk=\x07b"
		}
		if got := readN(t, sub, len(want)); got != want {
			t.Fatalf("strip=%v: %q, want %q", strip, got, want)
		}
		m.Unsubscribe(sub)
	}
}
