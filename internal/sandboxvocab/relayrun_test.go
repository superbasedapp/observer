package sandboxvocab

import "testing"

// TestRelayRunSpellings pins the relay run stamp (live run 2 finding N5):
// a run-shaped id re-keys the named session or yields the run's own key,
// and anything else yields "" so the proxy ignores the header.
func TestRelayRunSpellings(t *testing.T) {
	t.Parallel()
	if RelayRunHeader != "X-Observer-Sandbox-Run" {
		t.Fatalf("header %q", RelayRunHeader)
	}
	for _, tc := range []struct{ run, sid, want string }{
		{"run-7", "abc", "rsbx-run-7-abc"},
		{"run-7", "", "rsbx-run-7"},
		{"run 7/../x", "abc", ""},
		{"", "abc", ""},
		{string(make([]byte, relayRunIDMax+1)), "abc", ""},
	} {
		if got := RelaySessionID(tc.run, tc.sid); got != tc.want {
			t.Errorf("RelaySessionID(%q, %q) = %q, want %q", tc.run, tc.sid, got, tc.want)
		}
	}
	if RekeyID("r", "") != "" || RekeyID("r", "s") != "rsbx-r-s" {
		t.Error("RekeyID")
	}
}
