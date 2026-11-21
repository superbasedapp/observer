package sandboxopenshell

import (
	"bytes"
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
	"testing"
)

// keystoreNameRE is internal/keystore's ValidName rule (the planner may not
// import the keystore; the driver's test pins the two agree).
var keystoreNameRE = regexp.MustCompile(`^[A-Za-z0-9._@:-]{1,200}$`)

// memCustody is a CustodyStore in memory that records every call.
type memCustody struct {
	m     map[string]string
	saves []string
	fail  string
}

func newMemCustody() *memCustody { return &memCustody{m: map[string]string{}} }

func (s *memCustody) Load(n string) (string, bool, error) { v, ok := s.m[n]; return v, ok, nil }
func (s *memCustody) Save(n, v string) error {
	if s.fail != "" && strings.Contains(n, s.fail) {
		return errors.New("store refused")
	}
	s.saves = append(s.saves, n)
	s.m[n] = v
	return nil
}
func (s *memCustody) Remove(n string) error { delete(s.m, n); return nil }

// sentinelPKI is a complete PKI of sentinel values.
func sentinelPKI() map[string][]byte {
	out := map[string][]byte{}
	for _, f := range PKIFiles {
		out[f] = []byte("-----BEGIN SENTINEL-----\n" + f + "\n-----END SENTINEL-----\n")
	}
	return out
}

func testIdentity(t *testing.T) GatewayIdentity {
	t.Helper()
	id, err := IdentityFor("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestPKICustodyRoundTrip(t *testing.T) {
	t.Parallel()
	id := testIdentity(t)
	s := newMemCustody()
	if _, err := LoadPKI(s, id); !errors.Is(err, ErrNoCustody) {
		t.Fatalf("an empty store: %v, want ErrNoCustody", err)
	}
	files := sentinelPKI()
	if err := SavePKI(s, id, files); err != nil {
		t.Fatal(err)
	}
	if last := s.saves[len(s.saves)-1]; last != manifestRecordName(id) {
		t.Fatalf("the manifest must be written last, last was %s", last)
	}
	for _, n := range s.saves {
		if !keystoreNameRE.MatchString(n) {
			t.Fatalf("record name %q is not a keystore name", n)
		}
	}
	got, err := LoadPKI(s, id)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range files {
		if !bytes.Equal(got[k], v) {
			t.Fatalf("%s did not round-trip", k)
		}
	}
	if PKIDigest(got) != PKIDigest(files) || len(PKIDigest(got)) != 16 {
		t.Fatalf("digest differs")
	}
}

// TestPKICustodyRefusals is one case per refusal of the save and the load.
func TestPKICustodyRefusals(t *testing.T) {
	t.Parallel()
	id := testIdentity(t)
	saveCases := []struct {
		name string
		mod  func(m map[string][]byte)
	}{
		{"a missing file (partial set)", func(m map[string][]byte) { delete(m, "jwt/kid") }},
		{"an extra file", func(m map[string][]byte) { m["extra.pem"] = []byte("x") }},
		{"a wrong file in place of one", func(m map[string][]byte) { delete(m, "ca.key"); m["ca.pem"] = []byte("x") }},
		{"an empty file", func(m map[string][]byte) { m["ca.crt"] = nil }},
		{"a file over 16 KiB", func(m map[string][]byte) { m["ca.crt"] = bytes.Repeat([]byte("a"), maxPKIFile+1) }},
	}
	for _, tc := range saveCases {
		f := sentinelPKI()
		tc.mod(f)
		s := newMemCustody()
		if err := SavePKI(s, id, f); err == nil {
			t.Errorf("%s: saved", tc.name)
		}
		if _, ok := s.m[manifestRecordName(id)]; ok {
			t.Errorf("%s: a refused save wrote the manifest", tc.name)
		}
	}
	loadCases := []struct {
		name string
		mod  func(s *memCustody)
	}{
		{"a tampered file", func(s *memCustody) {
			s.m[pkiRecordName(id, "ca.key")] = base64.StdEncoding.EncodeToString([]byte("other"))
		}},
		{"a missing file record", func(s *memCustody) { delete(s.m, pkiRecordName(id, "client/tls.key")) }},
		{"a broken manifest", func(s *memCustody) { s.m[manifestRecordName(id)] = "{" }},
		{"a manifest naming fewer files", func(s *memCustody) { s.m[manifestRecordName(id)] = `{"version":1,"files":{"ca.crt":"00"}}` }},
		{"a record that is not base64", func(s *memCustody) { s.m[pkiRecordName(id, "ca.crt")] = "!!" }},
	}
	for _, tc := range loadCases {
		s := newMemCustody()
		if err := SavePKI(s, id, sentinelPKI()); err != nil {
			t.Fatal(err)
		}
		tc.mod(s)
		if _, err := LoadPKI(s, id); !errors.Is(err, ErrCustodyCorrupt) {
			t.Errorf("%s: %v, want ErrCustodyCorrupt", tc.name, err)
		}
	}
	// A store that refuses a file never gets a manifest.
	s := newMemCustody()
	s.fail = "server:tls.key"
	if err := SavePKI(s, id, sentinelPKI()); err == nil {
		t.Fatal("a failing store saved")
	}
	if _, err := LoadPKI(s, id); !errors.Is(err, ErrNoCustody) {
		t.Fatalf("after a failed save: %v, want ErrNoCustody", err)
	}
}

func TestKEKCustody(t *testing.T) {
	t.Parallel()
	id := testIdentity(t)
	s := newMemCustody()
	v, err := LoadOrCreateKEK(s, id, bytes.NewReader(bytes.Repeat([]byte{7}, KEKBytes)))
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := base64.StdEncoding.DecodeString(v); len(b) != KEKBytes {
		t.Fatalf("KEK %d bytes", len(b))
	}
	again, err := LoadOrCreateKEK(s, id, bytes.NewReader(nil))
	if err != nil || again != v {
		t.Fatalf("the held KEK must be reused: %v", err)
	}
	if _, err := LoadOrCreateKEK(newMemCustody(), id, bytes.NewReader([]byte{1})); err == nil {
		t.Fatal("a short random source made a key")
	}
	s.m[kekRecordName(id)] = base64.StdEncoding.EncodeToString([]byte("short"))
	if _, err := LoadOrCreateKEK(s, id, bytes.NewReader(nil)); err == nil {
		t.Fatal("a held key of the wrong length was used")
	}
	for i := 0; i < len(GatewayKEKEnv); i++ {
		c := GatewayKEKEnv[i]
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			t.Fatalf("the KEK variable %q must be letters, digits and underscores", GatewayKEKEnv)
		}
	}
}

func TestForgetCustody(t *testing.T) {
	t.Parallel()
	id := testIdentity(t)
	s := newMemCustody()
	_ = SavePKI(s, id, sentinelPKI())
	_, _ = LoadOrCreateKEK(s, id, bytes.NewReader(bytes.Repeat([]byte{1}, KEKBytes)))
	if err := ForgetCustody(s, id); err != nil {
		t.Fatal(err)
	}
	if len(s.m) != 0 {
		t.Fatalf("records left: %v", s.m)
	}
	if n := CustodyRecordNames(id); n[0] != manifestRecordName(id) {
		t.Fatalf("the manifest goes first: %v", n)
	}
}
