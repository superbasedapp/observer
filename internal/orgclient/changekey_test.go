package orgclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/secchange"
)

// TestAcceptChangeKeyCertificate (lane SEC-F2B): an enrolment answer is
// accepted only when its org root is the pinned org key.
func TestAcceptChangeKeyCertificate(t *testing.T) {
	rootPub, root, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	machine := strings.Repeat("ab", 32)
	keyID := secchange.KeyID(pub)
	answer := func(signer ed25519.PrivateKey, mach string) []byte {
		c, err := secchange.SignCertificate(secchange.Certificate{
			KeyID: keyID, PublicKey: base64.StdEncoding.EncodeToString(pub), MachineIdentity: mach, OrgID: "org-1",
			NotBefore: "2026-10-23T00:00:00Z", NotAfter: "2027-01-21T00:00:00Z",
		}, signer)
		if err != nil {
			t.Fatal(err)
		}
		cb, _ := json.Marshal(c)
		sp, _ := signer.Public().(ed25519.PublicKey)
		b, _ := json.Marshal(orgcontract.ChangeKeyEnrolResponse{Certificate: cb, OrgRoot: orgcontract.ChangeKeyOrgRoot{KeyID: secchange.KeyID(sp), PublicKey: base64.StdEncoding.EncodeToString(sp)}})
		return b
	}
	pinned := orgcontract.PublicKeyPinHash(rootPub)
	got, err := acceptChangeKeyCertificate(answer(root, machine), pinned)
	if err != nil || len(got.Certificate) == 0 || got.OrgRoot.PublicKey == "" {
		t.Fatalf("an answer from the pinned org key was refused: %v", err)
	}
	for name, body := range map[string][]byte{
		"issued by an unpinned key": answer(other, machine),
		"not json":                  []byte("{"),
	} {
		if _, err := acceptChangeKeyCertificate(body, pinned); !errors.Is(err, ErrChangeKeyCertificate) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
