package orgcontract

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestPushResponseOwnerManagedWire pins the three states of
// PushResponse.OwnerManaged (finding F12): absent (an older server, or a
// failed org-kind read: the node changes nothing), an explicit false (clears
// the node's record) and true. An explicit false must survive the wire, which
// is why the field is a pointer.
func TestPushResponseOwnerManagedWire(t *testing.T) {
	yes, no := true, false
	for _, tc := range []struct {
		name    string
		in      *bool
		wantKey string // "" = the key must be absent
	}{
		{"absent", nil, ""},
		{"explicit false", &no, `"owner_managed":false`},
		{"true", &yes, `"owner_managed":true`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(PushResponse{AcceptedRows: 1, OwnerManaged: tc.in})
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantKey == "" {
				if strings.Contains(string(raw), "owner_managed") {
					t.Fatalf("absent value marshalled a key: %s", raw)
				}
			} else if !strings.Contains(string(raw), tc.wantKey) {
				t.Fatalf("%s lacks %s", raw, tc.wantKey)
			}
			var back PushResponse
			if err := json.Unmarshal(raw, &back); err != nil {
				t.Fatal(err)
			}
			if (back.OwnerManaged == nil) != (tc.in == nil) || (tc.in != nil && *back.OwnerManaged != *tc.in) {
				t.Fatalf("round trip %v -> %v", tc.in, back.OwnerManaged)
			}
		})
	}
}
