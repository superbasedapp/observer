package orgclient

import "testing"

// TestNoteReconsent: the advisory is kept only for a reason this build
// knows, and a push that carries none (or a body that does not decode)
// clears it. Nothing else is changed.
func TestNoteReconsent(t *testing.T) {
	c := &Client{}
	if got := c.ReconsentReason(); got != "" {
		t.Fatalf("fresh client reason = %q", got)
	}
	for _, tc := range []struct {
		name, body, want string
	}{
		{"offered", `{"accepted_rows":1,"reconsent":{"reason":"owner_managed"}}`, "owner_managed"},
		{"unknown reason dropped", `{"reconsent":{"reason":"something_new"}}`, ""},
		{"offered again", `{"reconsent":{"reason":"owner_managed"}}`, "owner_managed"},
		{"none clears", `{"accepted_rows":1}`, ""},
		{"offered once more", `{"reconsent":{"reason":"owner_managed"}}`, "owner_managed"},
		{"undecodable clears", `not json`, ""},
	} {
		c.noteReconsent([]byte(tc.body))
		if got := c.ReconsentReason(); got != tc.want {
			t.Errorf("%s: reason = %q, want %q", tc.name, got, tc.want)
		}
	}
	var nilClient *Client
	if nilClient.ReconsentReason() != "" {
		t.Error("nil client reason is not empty")
	}
}
