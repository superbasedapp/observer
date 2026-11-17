package signerd_test

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/signerd"
	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// TestDecodeVersionRecord is the reader the raise-floor verb uses (W16-D6):
// a record the signer wrote decodes to its entries in (kind, scope) order;
// every shape the signer refuses at start is refused here too.
func TestDecodeVersionRecord(t *testing.T) {
	t.Parallel()
	const org1 = "11111111-0000-4000-8000-000000000001"
	const org2 = "22222222-0000-4000-8000-000000000002"
	cases := []struct {
		name string
		raw  string
		want []signerd.RecordEntry
		err  bool
	}{
		{
			name: "entries sorted by kind then scope",
			raw:  `{"v":1,"versions":{"entitlements":{"` + org2 + `":7,"` + org1 + `":9},"availability":{"platform":3}}}`,
			want: []signerd.RecordEntry{
				{Kind: pc.KindAvailability, Scope: pc.AvailabilityScope, Version: 3},
				{Kind: pc.KindEntitlements, Scope: org1, Version: 9},
				{Kind: pc.KindEntitlements, Scope: org2, Version: 7},
			},
		},
		{name: "empty record", raw: `{"v":1,"versions":{}}`, want: nil},
		{name: "not JSON", raw: `{`, err: true},
		{name: "wrong format version", raw: `{"v":2,"versions":{}}`, err: true},
		{name: "no versions map", raw: `{"v":1}`, err: true},
		{name: "unknown kind", raw: `{"v":1,"versions":{"invoices":{"` + org1 + `":1}}}`, err: true},
		{name: "availability outside its scope", raw: `{"v":1,"versions":{"availability":{"other":1}}}`, err: true},
		{name: "a version not positive", raw: `{"v":1,"versions":{"entitlements":{"` + org1 + `":0}}}`, err: true},
		{name: "too large", raw: `{"v":1,"versions":{}}` + strings.Repeat(" ", 64<<20), err: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got, err := signerd.DecodeVersionRecord([]byte(c.raw))
			if c.err {
				if err == nil {
					t.Fatalf("DecodeVersionRecord = %+v, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("DecodeVersionRecord: %v", err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("DecodeVersionRecord = %+v, want %+v", got, c.want)
			}
		})
	}
}

// TestDecodeVersionRecordReadsWhatTheSignerWrote: a record written by the
// signer's own FileVersions (created, two commits) decodes to the
// committed versions, so the verb and the signer share one format.
func TestDecodeVersionRecordReadsWhatTheSignerWrote(t *testing.T) {
	t.Parallel()
	const org = "33333333-0000-4000-8000-000000000003"
	path := filepath.Join(t.TempDir(), "versions.json")
	if err := signerd.CreateVersionFile(path); err != nil {
		t.Fatal(err)
	}
	v, err := signerd.OpenFileVersions(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		kind  pc.DocumentKind
		scope string
		ver   int64
	}{{pc.KindEntitlements, org, 41}, {pc.KindAvailability, pc.AvailabilityScope, 5}} {
		if err := v.Commit(c.kind, c.scope, c.ver); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path) //nolint:gosec // G304: the test's own temporary file
	if err != nil {
		t.Fatal(err)
	}
	got, err := signerd.DecodeVersionRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := []signerd.RecordEntry{
		{Kind: pc.KindAvailability, Scope: pc.AvailabilityScope, Version: 5},
		{Kind: pc.KindEntitlements, Scope: org, Version: 41},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("decoded %+v, want %+v", got, want)
	}
}
