package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestInlineLaunchersWireGenericDiscovery is a structural pin (mirrors
// tests/invariant/live_db_gate_test.go's TestLiveDBGate_StructuralPins
// approach): cursor.go, kilo.go, and opencode.go each bypass the shared
// runSeedOnlyLaunchSeeded / runEnvLauncher helpers with their own inline
// exec.Command/child.Start/child.Wait sequence, so
// prepareGenericDiscovery (WS-DISCOVERY) has to be wired into each file
// by hand rather than inherited from one shared call site. There is no
// black-box way to observe that wiring from a test process: discovery is a
// goroutine side effect gated on oobChannelActive(), which is unconditionally
// false outside a daemon-spawned launcher (see
// TestPrepareGenericDiscoveryNoOOBChannel in
// terminal_discover_generic_test.go), so calling into these launchers'
// exec-shaped functions from a test can never distinguish "wired" from
// "not wired" by behavior alone — both look like a no-op. This test instead
// pins the source text: it fails loudly if the call is removed, or if the
// tool key drifts from the one each file's own recordLaunchSeed call
// already uses for launch-seed attribution (verified against the
// internal/integration registry keys "cursor", "kilo-code-cli", and
// "opencode").
func TestInlineLaunchersWireGenericDiscovery(t *testing.T) {
	cases := []struct {
		file    string
		toolKey string
	}{
		{"cursor.go", `"cursor"`},
		{"kilo.go", `"kilo-code-cli"`},
		{"opencode.go", `"opencode"`},
	}

	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			src, err := os.ReadFile(tc.file)
			if err != nil {
				t.Fatalf("read %s: %v", tc.file, err)
			}
			body := string(src)

			wantCall := `prepareGenericDiscovery\([^,\n]+, ` + regexp.QuoteMeta(tc.toolKey)
			if !regexp.MustCompile(wantCall).MatchString(body) {
				t.Errorf("%s no longer calls %s(...) — generic post-launch session discovery is unwired for this launcher's inline exec lane", tc.file, wantCall)
			}

			if !strings.Contains(body, "recordLaunchSeed(") {
				t.Fatalf("%s no longer calls recordLaunchSeed — test assumption broken, update this pin", tc.file)
			}

			// Discovery must be cancelled via defer, matching the pattern in
			// launch.go::runEnvLauncher and qwen.go::runSeedOnlyLaunchSeeded
			// (cancel the instant the child exits) — not left dangling for
			// the process lifetime. Whitespace-tolerant: just confirm the nil
			// guard and the defer both exist, without pinning indentation.
			if !strings.Contains(body, "discoverCancel != nil") || !strings.Contains(body, "defer discoverCancel()") {
				t.Errorf("%s does not nil-check and defer-cancel discoverCancel next to the hook call — window must close on child exit", tc.file)
			}
		})
	}
}
