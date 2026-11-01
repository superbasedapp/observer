//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// sandboxSignedKind signs a one-artifact manifest of kind with priv.
func sandboxSignedKind(t *testing.T, priv ed25519.PrivateKey, kind content.Kind, version int64, name string, art []byte) []byte {
	t.Helper()
	now := time.Now().UTC()
	m := content.Manifest{
		Schema: content.SchemaV1, Kind: kind, ManifestVersion: version, Epoch: 1,
		IssuedAt: now.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: now.Add(48 * time.Hour).Format(time.RFC3339),
		Entries: []content.Entry{{Name: name, SizeBytes: int64(len(art)), SHA256: content.HashBytes(art), Upstream: content.UpstreamCheck{Method: content.UpstreamNone}}},
	}
	env, err := content.Sign(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := content.EncodeEnvelope(env)
	return b
}

// fakeSandboxFeed serves files of one kind; calls counts every request.
type fakeSandboxFeed struct {
	files map[string][]byte
	calls atomic.Int64
}

func (f *fakeSandboxFeed) FetchFeedFile(_ context.Context, kind, file string) ([]byte, error) {
	f.calls.Add(1)
	b, ok := f.files[kind+"/"+file]
	if !ok {
		return nil, errors.New("not published")
	}
	return b, nil
}

// fakeSandboxOrg installs from an in-memory mirror through the content
// channel, as orgclient.InstallSecurityContent does.
type fakeSandboxOrg struct {
	env   []byte
	art   map[string][]byte
	err   error
	calls atomic.Int64
}

func (f *fakeSandboxOrg) InstallSecurityContent(_ context.Context, st contentchan.Store, kind content.Kind, tr contentchan.Trust) (orgclient.SecurityContentResult, error) {
	f.calls.Add(1)
	if f.err != nil {
		s, _ := st.State(kind)
		return orgclient.SecurityContentResult{Kind: kind, State: s}, f.err
	}
	s, err := st.Install(kind, f.env, f.art, tr)
	return orgclient.SecurityContentResult{Kind: kind, State: s}, err
}

type sandboxContentRig struct {
	env  sandboxContentEnv
	feed *fakeSandboxFeed
	org  *fakeSandboxOrg
	priv ed25519.PrivateKey
}

func newSandboxContentRig(t *testing.T, enrolled bool) *sandboxContentRig {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	art := []byte(`{"files":[]}`)
	env := sandboxSignedKind(t, priv, content.SandboxNative, 1, "mxc-files.json", art)
	feed := &fakeSandboxFeed{files: map[string][]byte{"sandbox.native_files/manifest.json": env, "sandbox.native_files/mxc-files.json": art}}
	org := &fakeSandboxOrg{env: env, art: map[string][]byte{"mxc-files.json": art}}
	r := &sandboxContentRig{feed: feed, org: org, priv: priv}
	r.env = sandboxContentEnv{
		store:    contentchan.Store{Root: t.TempDir() + "/" + sandboxContentDir},
		trust:    contentchan.Trust{VendorKeys: []ed25519.PublicKey{pub}},
		enrolled: func(context.Context) (bool, error) { return enrolled, nil },
		org: func(context.Context) (sandboxMirrorInstaller, func(), error) {
			return org, func() {}, nil
		},
		feed:   func() sandboxFeedClient { return feed },
		active: func(content.Kind) bool { return true },
	}
	return r
}

func TestSandboxContentFetchFromTheVendorFeed(t *testing.T) {
	r := newSandboxContentRig(t, false)
	out, err := r.env.fetch(context.Background(), content.SandboxNative)
	if err != nil || out.Source != sandboxSourceFeed || out.State.Accepted == nil {
		t.Fatalf("fetch: %+v %v", out, err)
	}
	if r.org.calls.Load() != 0 {
		t.Fatal("a node that is not enrolled asked an org server")
	}
	line := sandboxContentStatusLine(r.env.store, r.env.trust, content.SandboxNative)
	if !strings.Contains(line, "version 1, fresh") || !strings.Contains(line, "last fetch ok") {
		t.Fatalf("status: %s", line)
	}
}

func TestSandboxContentFetchFromTheOrgMirrorOnly(t *testing.T) {
	r := newSandboxContentRig(t, true)
	out, err := r.env.fetch(context.Background(), content.SandboxNative)
	if err != nil || out.Source != sandboxSourceOrg || out.State.Accepted == nil {
		t.Fatalf("fetch: %+v %v", out, err)
	}
	// The org mirror down: an enrolled node never falls back to the feed.
	r.org.err = errors.New("org server unreachable")
	if _, err := r.env.fetch(context.Background(), content.SandboxNative); err == nil {
		t.Fatal("an org failure reported success")
	}
	if r.feed.calls.Load() != 0 {
		t.Fatal("an enrolled node reached the vendor feed")
	}
	line := sandboxContentStatusLine(r.env.store, r.env.trust, content.SandboxNative)
	if !strings.Contains(line, "version 1") || !strings.Contains(line, "last fetch FAILED") {
		t.Fatalf("status after a failure: %s", line)
	}
}

func TestSandboxContentFailedFetchKeepsLastKnownGood(t *testing.T) {
	r := newSandboxContentRig(t, false)
	if _, err := r.env.fetch(context.Background(), content.SandboxNative); err != nil {
		t.Fatal(err)
	}
	// A newer manifest signed by a key the node does not carry.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	r.feed.files["sandbox.native_files/manifest.json"] = sandboxSignedKind(t, other, content.SandboxNative, 2, "mxc-files.json", []byte(`{"files":[2]}`))
	if _, err := r.env.fetch(context.Background(), content.SandboxNative); content.ReasonOf(errors.Unwrap(err)) != content.ContentReasonVendorSig && !strings.Contains(err.Error(), "vendor_signature") {
		t.Fatalf("forged: %v", err)
	}
	if s, _ := r.env.store.State(content.SandboxNative); s.Accepted == nil || s.Accepted.ManifestVersion != 1 {
		t.Fatalf("the last-known-good moved: %+v", s)
	}
	// The feed down: still version 1, and the status says the fetch failed.
	delete(r.feed.files, "sandbox.native_files/manifest.json")
	if _, err := r.env.fetch(context.Background(), content.SandboxNative); err == nil {
		t.Fatal("a feed outage reported success")
	}
	if line := sandboxContentStatusLine(r.env.store, r.env.trust, content.SandboxNative); !strings.Contains(line, "version 1") || !strings.Contains(line, "FAILED") {
		t.Fatalf("status: %s", line)
	}
}

func TestSandboxContentNothingFetchedWhileTheDriverIsInactive(t *testing.T) {
	for _, enrolled := range []bool{false, true} {
		r := newSandboxContentRig(t, enrolled)
		r.env.active = func(content.Kind) bool { return false }
		out, err := r.env.fetch(context.Background(), content.SandboxImage)
		if err != nil || out.Skipped == "" || !strings.Contains(out.Skipped, "terminals.sandbox.oci") {
			t.Fatalf("inactive: %+v %v", out, err)
		}
		if r.feed.calls.Load()+r.org.calls.Load() != 0 {
			t.Fatal("an inactive driver's kind was fetched")
		}
	}
}

func TestSandboxContentRefusals(t *testing.T) {
	r := newSandboxContentRig(t, false)
	// An unreadable enrolment fetches from neither source.
	r.env.enrolled = func(context.Context) (bool, error) { return false, errors.New("store locked") }
	if _, err := r.env.fetch(context.Background(), content.SandboxNative); err == nil {
		t.Fatal("an unreadable enrolment fetched")
	}
	if r.feed.calls.Load()+r.org.calls.Load() != 0 {
		t.Fatal("an unreadable enrolment reached a source")
	}
	// No vendor feed client in this build.
	r = newSandboxContentRig(t, false)
	r.env.feed = func() sandboxFeedClient { return nil }
	if _, err := r.env.fetch(context.Background(), content.SandboxNative); !errors.Is(err, errSandboxContentNoFeed) {
		t.Fatalf("no feed: %v", err)
	}
	// A kind outside the sandbox table.
	if _, err := r.env.fetch(context.Background(), content.SandboxRootfs); err == nil {
		t.Fatal("sandbox.rootfs fetched before P4")
	}
}

// TestSandboxContentEnsureOnlyInTheDaemon: the first-use fetch never runs
// outside the daemon process.
func TestSandboxContentEnsureOnlyInTheDaemon(t *testing.T) {
	old := daemonConfigPathSetting.Load()
	daemonConfigPathSetting.Store(nil)
	t.Cleanup(func() { daemonConfigPathSetting.Store(old) })
	dir := t.TempDir()
	sandboxContentEnsure(content.SandboxImage, dir)
	if len(readSandboxContentFetches(sandboxContentStore(dir))) != 0 {
		t.Fatal("a non-daemon process fetched")
	}
}
