package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/sandboximage"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// asMainEnv makes the test binary act as vendorsign, so publish.sh's tests
// drive the real verb without a separate build.
const asMainEnv = "VENDORSIGN_TEST_AS_MAIN"

func TestMain(m *testing.M) {
	if os.Getenv(asMainEnv) == "1" {
		if err := run(os.Args[1:], os.Stdout); err != nil {
			_, _ = os.Stderr.WriteString(err.Error() + "\n")
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// fakeSkopeo is the push tool stand-in: it answers the pinned version,
// logs a copy, and serves FAKE_RAW for an inspect --raw.
const fakeSkopeo = `#!/bin/sh
case "$1" in
--version) echo "${FAKE_VERSION:-skopeo version 1.16.1}" ;;
copy) echo "$*" >>"$FAKE_LOG" ;;
inspect) cat "$FAKE_RAW" ;;
*) exit 9 ;;
esac
`

type publishRig struct {
	t      *testing.T
	out    string
	log    string
	raw    string
	tool   string
	layout *fakeLayout
	opts   sandboxImageOptions
}

func newPublishRig(t *testing.T) *publishRig {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("publish.sh is a bash script")
	}
	for _, b := range []string{"bash", "sha256sum"} {
		if _, err := exec.LookPath(b); err != nil {
			t.Skipf("%s not available", b)
		}
	}
	o, f := sandboxFixture(t, "linux/amd64", "linux/arm64")
	if _, err := buildSandboxImage(o); err != nil {
		t.Fatal(err)
	}
	// build.sh's layout: the tarball beside sandbox.image/.
	b, err := os.ReadFile(o.OCI)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(o.Out, "image.oci.tar"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	r := &publishRig{t: t, out: o.Out, log: filepath.Join(dir, "push.log"), raw: filepath.Join(dir, "raw"),
		tool: filepath.Join(dir, "skopeo"), layout: f, opts: o}
	if err := os.WriteFile(r.tool, []byte(fakeSkopeo), 0o700); err != nil { //nolint:gosec // test fake must be executable
		t.Fatal(err)
	}
	if err := os.WriteFile(r.raw, f.blobs[f.top], 0o600); err != nil {
		t.Fatal(err)
	}
	return r
}

// run runs publish.sh and returns its exit code and combined output.
func (r *publishRig) run(env []string, args ...string) (int, string) {
	r.t.Helper()
	self, err := os.Executable()
	if err != nil {
		r.t.Fatal(err)
	}
	script := filepath.Join("..", "..", "deploy", "sandbox-image", "publish.sh")
	cmd := exec.Command("bash", append([]string{script}, args...)...) //nolint:gosec // test drives the repo's own script
	cmd.Env = append(os.Environ(), asMainEnv+"=1", "VENDORSIGN="+self, "SKOPEO="+r.tool,
		"FAKE_LOG="+r.log, "FAKE_RAW="+r.raw)
	cmd.Env = append(cmd.Env, env...)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err = cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), buf.String()
	}
	if err != nil {
		r.t.Fatal(err)
	}
	return 0, buf.String()
}

func (r *publishRig) pushed() string {
	b, _ := os.ReadFile(r.log)
	return string(b)
}

func (r *publishRig) manifestExists() bool {
	_, err := os.Stat(filepath.Join(r.out, string(content.SandboxImage), "manifest.json"))
	return err == nil
}

func TestPublishArgumentChecks(t *testing.T) {
	r := newPublishRig(t)
	key := filepath.Join(t.TempDir(), "key")
	_, priv := testKey(t)
	if err := os.WriteFile(key, []byte(base64.StdEncoding.EncodeToString(priv.Seed())), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		env  []string
		args []string
		code int
		want string
	}{
		{"no registry", nil, []string{"--out", r.out}, 2, "--registry is required"},
		{"bad registry", nil, []string{"--out", r.out, "--registry", "Bad Registry"}, 2, "not a registry name"},
		{"unknown argument", nil, []string{"--out", r.out, "--registry", "ghcr.io/example", "--push-now"}, 2, "unknown argument"},
		{"no build", nil, []string{"--out", t.TempDir(), "--registry", "ghcr.io/example"}, 2, "no build output"},
		{"key without version", nil, []string{"--out", r.out, "--registry", "ghcr.io/example", "--key", key}, 2, "needs --manifest-version"},
		{"bad manifest version", nil, []string{"--out", r.out, "--registry", "ghcr.io/example", "--manifest-version", "0"}, 2, "positive integer"},
		{"bad revoke", nil, []string{"--out", r.out, "--registry", "ghcr.io/example", "--revoke", "abc"}, 2, "sha256 digest"},
		{"unpinned tool", []string{"FAKE_VERSION=skopeo version 1.17.0"}, []string{"--out", r.out, "--registry", "ghcr.io/example"}, 2, "pinned skopeo 1.16.1"},
		{"other registry", nil, []string{"--out", r.out, "--registry", "quay.io/other", "--dry-run"}, 1, "is not under the registry"},
	}
	for _, tc := range cases {
		code, out := r.run(tc.env, tc.args...)
		if code != tc.code || !strings.Contains(out, tc.want) {
			t.Errorf("%s: exit %d, want %d with %q; output:\n%s", tc.name, code, tc.code, tc.want, out)
		}
	}
	if r.pushed() != "" || r.manifestExists() {
		t.Fatal("a refused run pushed or signed")
	}
}

func TestPublishDryRunPushesAndSignsNothing(t *testing.T) {
	r := newPublishRig(t)
	code, out := r.run(nil, "--out", r.out, "--registry", "ghcr.io/example", "--dry-run")
	if code != 0 || !strings.Contains(out, "would push") || !strings.Contains(out, r.layout.top) ||
		!strings.Contains(out, "sandbox_image_signing_key_missing") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if r.pushed() != "" || r.manifestExists() {
		t.Fatal("a dry run pushed or signed")
	}
}

func TestPublishStopsAtSigningSeamWithoutKey(t *testing.T) {
	r := newPublishRig(t)
	code, out := r.run(nil, "--out", r.out, "--registry", "ghcr.io/example")
	if code != 3 || !strings.Contains(out, "sandbox_image_signing_key_missing") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	push := r.pushed()
	if !strings.Contains(push, "--preserve-digests") || !strings.Contains(push, "docker://ghcr.io/example/observer-sandbox:1.0.0") {
		t.Fatalf("push: %q", push)
	}
	if r.manifestExists() {
		t.Fatal("the seam wrote a manifest without a key")
	}
	rec, _ := os.ReadFile(filepath.Join(r.out, "publish-record.txt"))
	if !strings.Contains(string(rec), "tool=skopeo 1.16.1") || !strings.Contains(string(rec), "signed=no") {
		t.Fatalf("record: %s", rec)
	}
}

func TestPublishRefusesRebuiltLayout(t *testing.T) {
	r := newPublishRig(t)
	// A rebuild that is not reproducible: another layout at the same path.
	newFakeLayout("linux/amd64").write(t, filepath.Join(r.out, "image.oci.tar"), false)
	code, out := r.run(nil, "--out", r.out, "--registry", "ghcr.io/example", "--dry-run")
	if code != 4 || !strings.Contains(out, "sandbox_image_digest_mismatch") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if r.pushed() != "" {
		t.Fatal("a mismatched layout was pushed")
	}
}

func TestPublishRefusesRegistryServingOtherBytes(t *testing.T) {
	r := newPublishRig(t)
	if err := os.WriteFile(r.raw, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out := r.run(nil, "--out", r.out, "--registry", "ghcr.io/example")
	if code != 1 || !strings.Contains(out, "the registry serves") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
}

// TestPublishSignsWithTestKey runs the whole path with a TEST key and
// installs the result through the node's content store.
func TestPublishSignsWithTestKey(t *testing.T) {
	r := newPublishRig(t)
	pub, priv := testKey(t)
	key := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(key, []byte(base64.StdEncoding.EncodeToString(priv.Seed())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out := r.run(nil, "--out", r.out, "--registry", "ghcr.io/example", "--key", key,
		"--manifest-version", "1", "--valid-days", "30", "--allow-unpinned-key")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	dir := filepath.Join(r.out, string(content.SandboxImage))
	read := func(n string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	store := contentchan.Store{Root: t.TempDir(), GOOS: "linux", GOARCH: "amd64"}
	tr := contentchan.Trust{VendorKeys: []ed25519.PublicKey{pub}}
	arts := map[string][]byte{sandboximage.DescriptorName: read(sandboximage.DescriptorName), sandboximage.SBOMName: read(sandboximage.SBOMName)}
	if _, err := store.Install(content.SandboxImage, read("manifest.json"), arts, tr); err != nil {
		t.Fatal(err)
	}
	other, _ := testKey(t)
	if _, err := (contentchan.Store{Root: t.TempDir()}).Install(content.SandboxImage, read("manifest.json"), arts,
		contentchan.Trust{VendorKeys: []ed25519.PublicKey{other}}); err == nil {
		t.Fatal("a manifest signed by the test key verified under another key")
	}
}
