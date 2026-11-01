package orgcontract

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// TestSecurityOrgDedupeCacheRoundTrip (lane LEFT-SHARED merge audit finding
// 4): the stripped body keeps no key and differs from the served body only in
// the key's value; the held key at the body's version restores it byte for
// byte; another version, no key, and a malformed body are refused.
func TestSecurityOrgDedupeCacheRoundTrip(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, SecurityOrgDedupeKeyBytes))
	d := &SecurityOrgDedupe{Version: 3, Key: key}
	served, err := ComposeSecurityServed([]byte(`{"version":1,"finding_share":"findings"}`), []string{SecurityCapabilityOrgDedupe}, SecurityServedInput{Dedupe: d})
	if err != nil || !bytes.Contains(served, []byte(key)) {
		t.Fatalf("compose: %s %v", served, err)
	}
	stripped, err := StripSecurityOrgDedupeKey(served)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stripped, []byte(key)) || !bytes.Contains(stripped, []byte(`"key":""`)) {
		t.Fatalf("stripped body still carries the key: %s", stripped)
	}
	if len(served)-len(stripped) != len(key) {
		t.Fatalf("strip changed more than the key: %s vs %s", served, stripped)
	}
	held := func(v int64) func() (SecurityOrgDedupe, bool) {
		return func() (SecurityOrgDedupe, bool) { return SecurityOrgDedupe{Version: v, Key: key}, true }
	}
	back, err := RestoreSecurityOrgDedupeKey(stripped, held(3))
	if err != nil || !bytes.Equal(back, served) {
		t.Fatalf("restore: %s (%v), want %s", back, err, served)
	}
	if _, err := RestoreSecurityOrgDedupeKey(stripped, held(4)); !errors.Is(err, ErrSecurityOrgDedupeNotHeld) {
		t.Fatalf("another version: %v", err)
	}
	if _, err := RestoreSecurityOrgDedupeKey(stripped, nil); !errors.Is(err, ErrSecurityOrgDedupeNotHeld) {
		t.Fatalf("no key held: %v", err)
	}
	// A body that never carried the key, and one cached before the strip
	// existed (key still in place), come back unchanged.
	for _, b := range [][]byte{[]byte(`{"version":1}`), []byte(`{}`), []byte(`null`), []byte(``), served} {
		s, err := StripSecurityOrgDedupeKey(b)
		if string(b) != string(served) && (err != nil || !bytes.Equal(s, b)) {
			t.Errorf("strip %q = %q %v", b, s, err)
		}
		r, err := RestoreSecurityOrgDedupeKey(b, nil)
		if err != nil || !bytes.Equal(r, b) {
			t.Errorf("restore %q = %q %v", b, r, err)
		}
	}
	// Whitespace around the value is kept.
	spaced := []byte(`{ "org_dedupe" : { "version" : 3 , "key" : "` + key + `" } , "version" : 1 }`)
	s, err := StripSecurityOrgDedupeKey(spaced)
	if err != nil || strings.Contains(string(s), key) {
		t.Fatalf("spaced strip: %s %v", s, err)
	}
	if r, err := RestoreSecurityOrgDedupeKey(s, held(3)); err != nil || !bytes.Equal(r, spaced) {
		t.Fatalf("spaced restore: %s %v", r, err)
	}
	for _, bad := range []string{`{"org_dedupe":{"version":3}}`, `{"org_dedupe":{"key":"x"}}`, `{"org_dedupe":[1]}`, `{"org_dedupe":{"version":3,"key":""},"org_dedupe":{"version":3,"key":""}}`, `{"org_dedupe":`} {
		if _, err := StripSecurityOrgDedupeKey([]byte(bad)); err == nil {
			t.Errorf("malformed %s was stripped", bad)
		}
	}
}
