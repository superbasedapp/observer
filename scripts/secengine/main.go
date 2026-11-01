package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secengine"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// cosignSHA256 is the cosign v2.6.5 linux-amd64 release binary the release
// pipeline installs (npm-release.yml COSIGN_SHA256). Another cosign is
// refused unless -cosign-sha256 names it explicitly.
const cosignSHA256 = "c3b4f5410e608af03a5eb0aaac84a4313d8da131248e08ff1759ac70c79d1644"

// trustRoots are the pre-check's trust anchors: the embedded Fulcio pair
// (a variable so the tests can stand in their own certificate authority).
var trustRoots = secengine.FulcioRoots

// maxAssetBytes caps the asset read (the linux amd64 asset is 46.6 MB).
const maxAssetBytes = 512 << 20

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout, execCosign, time.Now); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

const usage = `usage:
  secengine verify -asset FILE -sig FILE -cert FILE -cosign PATH [-version 1.30.1] [-os linux] [-arch amd64] [-where release_pipeline] [-cosign-sha256 HEX]`

// cosignFunc starts cosign with args and returns its combined output and
// whether it exited 0. Tests replace it.
type cosignFunc func(ctx context.Context, path string, args []string) (out []byte, ok bool, err error)

func execCosign(ctx context.Context, path string, args []string) ([]byte, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...) //nolint:gosec // G204: the binary's sha256 was checked against the pin first; the arguments are fixed flags and files the operator named.
	// cosign gets a scratch HOME (its TUF cache) and the proxy and CA
	// settings an online verification may need, nothing else.
	cmd.Env = []string{"HOME=" + os.TempDir(), "PATH=/usr/bin:/bin"}
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR"} {
		if v, ok := os.LookupEnv(k); ok {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return out, true, nil
	case errors.As(err, &exit):
		return out, false, nil
	}
	return out, false, err
}

func run(ctx context.Context, args []string, out io.Writer, cosign cosignFunc, now func() time.Time) error {
	if len(args) == 0 || args[0] != "verify" {
		return errors.New(usage)
	}
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	asset := fs.String("asset", "", "the release asset")
	sigPath := fs.String("sig", "", "the asset's .sig file")
	certPath := fs.String("cert", "", "the asset's .cert file")
	cosignPath := fs.String("cosign", "", "the cosign binary")
	cosignPin := fs.String("cosign-sha256", cosignSHA256, "the cosign binary's expected sha256")
	version := fs.String("version", secengine.TestedVersion, "the Opengrep version")
	goos := fs.String("os", "linux", "the asset's GOOS")
	goarch := fs.String("arch", "amd64", "the asset's GOARCH")
	where := fs.String("where", "release_pipeline", "release_pipeline or org_mirror_import")
	if err := fs.Parse(args[1:]); err != nil {
		return fmt.Errorf("%w\n%s", err, usage)
	}
	if *asset == "" || *sigPath == "" || *certPath == "" || *cosignPath == "" {
		return errors.New(usage)
	}
	if *where != "release_pipeline" && *where != "org_mirror_import" {
		return fmt.Errorf("-where %q: want release_pipeline or org_mirror_import", *where)
	}
	if secengine.ParseVersion(*version) == nil {
		return fmt.Errorf("-version %q is not MAJOR.MINOR.PATCH", *version)
	}
	digest, size, err := hashFile(*asset, maxAssetBytes)
	if err != nil {
		return fmt.Errorf("asset: %w", err)
	}
	sig, err := readSmall(*sigPath)
	if err != nil {
		return fmt.Errorf("sig: %w", err)
	}
	cert, err := readSmall(*certPath)
	if err != nil {
		return fmt.Errorf("cert: %w", err)
	}
	identity := secengine.Identity(*version)
	root, inter := trustRoots()
	if _, err := secengine.Precheck(secengine.PrecheckInput{
		Digest: digest, SigB64: sig, CertB64: cert, Identity: identity, Issuer: secengine.Issuer,
		RootPEM: root, IntermediatePEM: inter,
	}); err != nil {
		return fmt.Errorf("refused before going online: %w", err)
	}
	got, _, err := hashFile(*cosignPath, 1<<30)
	if err != nil {
		return fmt.Errorf("cosign: %w", err)
	}
	if !strings.EqualFold(got, *cosignPin) {
		return fmt.Errorf("cosign %s has sha256 %s, not the pinned %s", *cosignPath, got, *cosignPin)
	}
	cargs := []string{
		"verify-blob", *asset, "--signature", *sigPath, "--certificate", *certPath,
		"--certificate-identity", identity, "--certificate-oidc-issuer", secengine.Issuer,
	}
	cout, ok, err := cosign(ctx, *cosignPath, cargs)
	if err != nil {
		return fmt.Errorf("cosign did not run: %w", err)
	}
	if !ok || !bytes.Contains(cout, []byte("Verified OK")) {
		return fmt.Errorf("cosign verify-blob did not verify (online, against Rekor):\n%s", strings.TrimSpace(string(cout)))
	}
	e := content.Entry{
		Name: filepath.Base(*asset), Version: *version, OS: *goos, Arch: *goarch, SizeBytes: size, SHA256: digest,
		Source: "github.com/opengrep/opengrep", License: "LGPL-2.1-only",
		Upstream: content.UpstreamCheck{
			Method: content.UpstreamCosignKeylessOnline, Identity: identity, Issuer: secengine.Issuer,
			VerifiedAt: now().UTC().Format(time.RFC3339), VerifiedWhere: *where,
		},
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(e)
}

// hashFile returns a regular file's sha256 and size, refusing one over limit.
func hashFile(path string, limit int64) (string, int64, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return "", 0, err
	}
	if !fi.Mode().IsRegular() {
		return "", 0, fmt.Errorf("%s is not a regular file", path)
	}
	if fi.Size() > limit {
		return "", 0, fmt.Errorf("%s is over %d bytes", path, limit)
	}
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, limit+1))
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func readSmall(path string) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > 64<<10 {
		return nil, fmt.Errorf("%s is not a small regular file", path)
	}
	return os.ReadFile(path)
}
