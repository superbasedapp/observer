package termsession

import (
	"strings"
	"testing"
	"time"
)

// TestNoticeReachesTheViewer (lane sbx-p2e, finding 5): a daemon notice
// lands in the live session's output, where an attached viewer reads it, and
// is refused for a handle that is gone.
func TestNoticeReachesTheViewer(t *testing.T) {
	sp := &fakeSpawner{}
	m := newTestManager(t, sp, time.Now)
	tok, err := m.Create(validSpec())
	if err != nil {
		t.Fatal(err)
	}
	sub, err := m.Subscribe(tok)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Unsubscribe(sub)

	const line = "\r\n[observer] the run is ended\r\n"
	if !m.Notice(tok, line) {
		t.Fatal("Notice refused a live handle")
	}
	got := make(chan string, 1)
	go func() {
		var b strings.Builder
		buf := make([]byte, 256)
		for !strings.Contains(b.String(), line) {
			n, err := sub.Read(buf)
			b.Write(buf[:n])
			if err != nil {
				break
			}
		}
		got <- b.String()
	}()
	select {
	case s := <-got:
		if !strings.Contains(s, line) {
			t.Fatalf("viewer read %q, want the notice", s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the viewer never read the notice")
	}
	m.Close(tok)
	if m.Notice(tok, line) {
		t.Fatal("Notice accepted a closed handle")
	}
}
