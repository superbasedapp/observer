package update

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

// TestContentFeedKeySlotsFailClosed walks the accepted-set builder over the
// slot shapes a key generation or a rotation can produce: the EMPTY slots
// shipped today contribute no key, a set slot parses, and nothing falls back
// to the release vendor key or to "accept anything".
func TestContentFeedKeySlotsFailClosed(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	other, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	otherB64 := base64.StdEncoding.EncodeToString(other)

	cases := []struct {
		name  string
		slots []string
		want  []ed25519.PublicKey
	}{
		{"compiled slots", []string{ContentFeedPublicKeyV1, ContentFeedPublicKeyV0Previous}, nil},
		{"empty slots only", []string{"", ""}, nil},
		{"current set", []string{pubB64, ""}, []ed25519.PublicKey{pub}},
		{"rotation overlap", []string{pubB64, otherB64}, []ed25519.PublicKey{pub, other}},
		{"placeholder only", []string{vendorPlaceholderKey, ""}, nil},
		{"malformed current", []string{"not base64", ""}, nil},
		{"short current with real previous", []string{"YWJj", otherB64}, []ed25519.PublicKey{other}},
	}
	saved := contentFeedPublicKeysB64
	t.Cleanup(func() { contentFeedPublicKeysB64 = saved })
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			contentFeedPublicKeysB64 = tc.slots
			got := ContentFeedPublicKeys()
			if tc.name == "compiled slots" && ContentFeedPublicKeyV1 != "" {
				t.Skip("a content-feed key is compiled in; the set-slot rows cover parsing")
			}
			if len(got) != len(tc.want) {
				t.Fatalf("ContentFeedPublicKeys() = %d keys, want %d", len(got), len(tc.want))
			}
			for i := range got {
				if !got[i].Equal(tc.want[i]) {
					t.Errorf("key %d differs", i)
				}
			}
		})
	}
}

// TestContentFeedKeyIsNotTheReleaseKey pins the separation the key exists
// for: no compiled-in content-feed key may be a release vendor key, or the
// online publisher would hold the key that signs agent binaries.
func TestContentFeedKeyIsNotTheReleaseKey(t *testing.T) {
	for _, f := range ContentFeedPublicKeys() {
		for _, v := range VendorPublicKeys() {
			if f.Equal(v) {
				t.Fatal("a content-feed key equals a release vendor key")
			}
		}
	}
}
