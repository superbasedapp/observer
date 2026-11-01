package termoob

import (
	"bytes"
	"testing"
)

// TestSandboxEgressRefusedCarriesItsCount: the host helper's count of held
// egress refusals (Windows 11 Pro run 4, N2) survives the wire.
func TestSandboxEgressRefusedCarriesItsCount(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	enc := NewEncoder(&buf)
	if err := enc.WriteHello(Hello{AuthToken: "tok", Tool: "claude-code"}); err != nil {
		t.Fatal(err)
	}
	n := 16
	if err := enc.WriteLifecycle(Lifecycle{Phase: PhaseSandboxEgressRefused, Count: &n, At: 1}); err != nil {
		t.Fatal(err)
	}
	dec := NewDecoder(&buf, "tok")
	if _, err := dec.Read(); err != nil {
		t.Fatal(err)
	}
	f, err := dec.Read()
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != TypeLifecycle || f.Lifecycle == nil || f.Lifecycle.Phase != PhaseSandboxEgressRefused || f.Lifecycle.Count == nil || *f.Lifecycle.Count != 16 {
		t.Fatalf("frame %+v", f.Lifecycle)
	}
	if f.Lifecycle.ExitCode != nil {
		t.Fatal("a count frame carries no exit code")
	}
}
