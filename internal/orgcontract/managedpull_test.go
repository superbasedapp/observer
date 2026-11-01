package orgcontract

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

// TestManagedPullRailsAreClosedAndDistinct: two rails, separate domains,
// paths, names and authorities.
func TestManagedPullRailsAreClosedAndDistinct(t *testing.T) {
	if len(ManagedPullRails) != 2 {
		t.Fatalf("want exactly the security and sandbox rails, got %d", len(ManagedPullRails))
	}
	seen := map[string]bool{}
	for _, r := range ManagedPullRails {
		for _, v := range []string{r.Name, r.Domain, r.Path, r.Authority} {
			if v == "" || seen[v] {
				t.Fatalf("rail %+v: empty or shared value %q", r, v)
			}
			seen[v] = true
		}
		if got, ok := LookupManagedPullRail(r.Name); !ok || got != r {
			t.Fatalf("LookupManagedPullRail(%q)", r.Name)
		}
	}
	sec, _ := LookupManagedPullRail("security")
	if sec.Domain != "sbo-security-managed-v1" || sec.Path != "/api/agent/security" || sec.Authority != "enforce.security" {
		t.Fatalf("security rail %+v", sec)
	}
	sbx, _ := LookupManagedPullRail("sandbox")
	if sbx.Domain != "sbo-sandbox-managed-v1" || sbx.Path != "/api/agent/sandbox" || sbx.Authority != "enforce.sandbox" {
		t.Fatalf("sandbox rail %+v", sbx)
	}
}

// TestManagedPullEveryCrossFieldReplayRefuses: a document verifies only for
// its own rail, org, subject, version, expiry and body, under its own key.
func TestManagedPullEveryCrossFieldReplayRefuses(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	sec, _ := LookupManagedPullRail("security")
	sbx, _ := LookupManagedPullRail("sandbox")
	body := []byte(`{"enable":["security.deps"]}`)
	doc, err := SignManagedPull(priv, sec, "org-1", "alice", 7, 2_000_000_000, body)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyManagedPull(pub, sec, "org-1", "alice", doc); err != nil {
		t.Fatalf("own document: %v", err)
	}
	mutate := func(f func(d *ManagedPullDoc)) ManagedPullDoc {
		d := doc
		d.Body = append([]byte(nil), doc.Body...)
		f(&d)
		return d
	}
	cases := []struct {
		name    string
		pub     ed25519.PublicKey
		rail    ManagedPullRail
		org     string
		subject string
		doc     ManagedPullDoc
	}{
		{"on the sandbox rail", pub, sbx, "org-1", "alice", doc},
		{"schema relabelled to the sandbox rail", pub, sbx, "org-1", "alice", mutate(func(d *ManagedPullDoc) { d.Schema = sbx.Domain })},
		{"for another subject", pub, sec, "org-1", "bob", doc},
		{"for another org", pub, sec, "org-2", "alice", doc},
		{"document claims another subject", pub, sec, "org-1", "bob", mutate(func(d *ManagedPullDoc) { d.Subject = "bob" })},
		{"version changed", pub, sec, "org-1", "alice", mutate(func(d *ManagedPullDoc) { d.Version = 8 })},
		{"expiry extended", pub, sec, "org-1", "alice", mutate(func(d *ManagedPullDoc) { d.ExpiresAt++ })},
		{"body changed", pub, sec, "org-1", "alice", mutate(func(d *ManagedPullDoc) { d.Body = []byte(`{"enable":["security.code"]}`) })},
		{"another key", otherPub, sec, "org-1", "alice", doc},
		{"no key", nil, sec, "org-1", "alice", doc},
		{"unsigned", pub, sec, "org-1", "alice", mutate(func(d *ManagedPullDoc) { d.Signature = "" })},
		{"zero version", pub, sec, "org-1", "alice", mutate(func(d *ManagedPullDoc) { d.Version = 0 })},
	}
	for _, c := range cases {
		if err := VerifyManagedPull(c.pub, c.rail, c.org, c.subject, c.doc); !errors.Is(err, ErrManagedPullUnverified) {
			t.Errorf("%s: verified (err=%v)", c.name, err)
		}
	}
}

// TestManagedPullMessageFraming: NUL framing refuses a header field that
// would let two different headers frame the same bytes.
func TestManagedPullMessageFraming(t *testing.T) {
	a, err := ManagedPullMessage("d", "org", "ab", 1, 1, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := ManagedPullMessage("d", "org", "a", 1, 1, []byte("bx"))
	if string(a) == string(b) {
		t.Fatal("a shifted subject/body boundary framed the same message")
	}
	for _, bad := range [][3]string{{"", "o", "s"}, {"d", "", "s"}, {"d", "o", ""}, {"d", "o\x00x", "s"}} {
		if _, err := ManagedPullMessage(bad[0], bad[1], bad[2], 1, 1, nil); !errors.Is(err, ErrManagedPullHeader) {
			t.Errorf("%q framed", bad)
		}
	}
	if _, err := ManagedPullMessage("d", "o", "s", 1, 0, nil); !errors.Is(err, ErrManagedPullHeader) {
		t.Error("a missing expiry framed")
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	sec, _ := LookupManagedPullRail("security")
	if _, err := SignManagedPull(priv, sec, "o", "s", 1, 1, []byte("not json")); err == nil {
		t.Error("a non-JSON body was signed")
	}
	for _, b := range []string{"{}", " null ", ""} {
		if !ManagedPullBodyIsEmpty([]byte(b)) {
			t.Errorf("%q must read as the signed none", b)
		}
	}
	if ManagedPullBodyIsEmpty([]byte(`{"a":1}`)) {
		t.Error("a body read as empty")
	}
}
