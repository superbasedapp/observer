package orgclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// TestSandboxContentKindTable pins the sandbox rows (lane SBX-P3D): each
// names its consumer and the driver component that gates the fetch, and
// no row repeats a security kind.
func TestSandboxContentKindTable(t *testing.T) {
	want := map[content.Kind]string{
		content.SandboxImage: "terminals.sandbox.oci", content.SandboxNative: "terminals.sandbox.mxc",
		// lane SBX-P4: the microVM driver's two kinds.
		content.SandboxRootfs: "terminals.sandbox.vm", content.SandboxGuest: "terminals.sandbox.vm",
	}
	if len(SandboxContentKinds) != len(want) {
		t.Fatalf("rows: %+v", SandboxContentKinds)
	}
	for _, r := range SandboxContentKinds {
		if want[r.Kind] != r.Component || r.Consumer == "" {
			t.Errorf("row %+v", r)
		}
		if _, ok := LookupSecurityContentKind(r.Kind); ok {
			t.Errorf("%s is in both tables", r.Kind)
		}
	}
}

// TestInstallSandboxContentFromTheOrgMirror: a sandbox kind installs
// through the one mirror fetch path, with the same vendor-signature rule.
func TestInstallSandboxContentFromTheOrgMirror(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	desc := []byte(`{"files":[]}`)
	now := time.Now().UTC()
	m := content.Manifest{
		Schema: content.SchemaV1, Kind: content.SandboxNative, ManifestVersion: 1, Epoch: 1,
		IssuedAt: now.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: now.Add(48 * time.Hour).Format(time.RFC3339),
		Entries: []content.Entry{{Name: "mxc-files.json", SizeBytes: int64(len(desc)), SHA256: content.HashBytes(desc), Upstream: content.UpstreamCheck{Method: content.UpstreamAuthenticode}}},
	}
	env, _ := content.Sign(m, priv)
	envB, _ := content.EncodeEnvelope(env)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, orgcontract.AgentSecurityContentPath)
		switch rest {
		case "sandbox.native_files/manifest.json":
			_, _ = w.Write(envB)
		case "sandbox.native_files/mxc-files.json":
			_, _ = w.Write(desc)
		default:
			http.Error(w, `{"error":"not_mirrored"}`, http.StatusNotFound)
		}
	}))
	defer srv.Close()
	c, _, _ := enrolledClient(t, srv.URL)
	st := contentchan.Store{Root: t.TempDir() + "/sandbox-content"}
	res, err := c.InstallSecurityContent(context.Background(), st, content.SandboxNative, contentchan.Trust{VendorKeys: []ed25519.PublicKey{pub}})
	if err != nil || res.State.Accepted == nil || res.State.Accepted.ManifestVersion != 1 {
		t.Fatalf("install: %+v %v", res, err)
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	st2 := contentchan.Store{Root: t.TempDir() + "/sandbox-content"}
	if _, err := c.InstallSecurityContent(context.Background(), st2, content.SandboxNative, contentchan.Trust{VendorKeys: []ed25519.PublicKey{other}}); content.ReasonOf(err) != content.ContentReasonVendorSig {
		t.Fatalf("another key: %v", err)
	}
}
