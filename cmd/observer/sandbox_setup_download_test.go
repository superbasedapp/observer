//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/dblease"
	"github.com/marmutapp/superbased-observer/internal/sandboxsetup"
	"github.com/marmutapp/superbased-observer/internal/sandboxsetupnet"
)

// fakeSandboxFetcher serves body through the fetcher contract (cap
// included); no network is touched.
type fakeSandboxFetcher struct {
	body  []byte
	calls int
	url   string
}

func (f *fakeSandboxFetcher) Download(_ context.Context, raw string, limit int64, w io.Writer) (int64, string, error) {
	f.calls++
	f.url = raw
	h := sha256.New()
	b := f.body
	if int64(len(b)) > limit {
		b = b[:limit+1]
	}
	n, err := io.MultiWriter(w, h).Write(b)
	if err != nil {
		return int64(n), "", err
	}
	if int64(n) > limit {
		return int64(n), "", sandboxsetupnet.ErrTooLarge
	}
	return int64(n), hex.EncodeToString(h.Sum(nil)), nil
}

type sandboxDLEnv struct {
	home, data string
	pin        sandboxsetup.Pin
	body       []byte
	fetch      *fakeSandboxFetcher
}

// sandboxDLTest points the seams at a temp home and data home, a test pin
// over body and a fake fetcher serving fetched.
func sandboxDLTest(t *testing.T, body, fetched []byte, status string) *sandboxDLEnv {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("sandbox tool downloads are pinned for Linux hosts only")
	}
	e := &sandboxDLEnv{home: t.TempDir(), data: t.TempDir(), body: body, fetch: &fakeSandboxFetcher{body: fetched}}
	s := sha256.Sum256(body)
	e.pin = sandboxsetup.Pin{
		ID: "test-tool", Version: "1.0", GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
		URL: "https://github.com/o/r/releases/download/v1.0/test-tool", SHA256: hex.EncodeToString(s[:]), Size: int64(len(body)), Status: status,
	}
	oldPin, oldFetch, oldEnv, oldHome := sandboxDownloadPinFor, sandboxDownloadFetcher, sandboxDownloadGetenv, sandboxDownloadHome
	t.Cleanup(func() {
		sandboxDownloadPinFor, sandboxDownloadFetcher, sandboxDownloadGetenv, sandboxDownloadHome = oldPin, oldFetch, oldEnv, oldHome
	})
	sandboxDownloadPinFor = func(id string) (sandboxsetup.Pin, bool) { return e.pin, id == e.pin.ID }
	sandboxDownloadFetcher = func() sandboxFetcher { return e.fetch }
	sandboxDownloadGetenv = func(k string) string {
		if k == "XDG_DATA_HOME" {
			return e.data
		}
		return ""
	}
	sandboxDownloadHome = func() (string, error) { return e.home, nil }
	return e
}

func (e *sandboxDLEnv) dir() string {
	return filepath.Join(e.data, "superbased-observer", "sandbox-tools", e.pin.ID, e.pin.Version)
}

func (e *sandboxDLEnv) final() string { return filepath.Join(e.dir(), e.pin.ID) }

// assertNoTemp: no temporary file is left in the target directory.
func (e *sandboxDLEnv) assertNoTemp(t *testing.T) {
	t.Helper()
	ents, _ := os.ReadDir(e.dir())
	for _, d := range ents {
		if strings.HasPrefix(d.Name(), ".download-") {
			t.Errorf("temporary file %s left behind", d.Name())
		}
	}
}

func TestSandboxSetupDownload_FetchPlaces0755(t *testing.T) {
	body := bytes.Repeat([]byte("ch"), 40000)
	e := sandboxDLTest(t, body, body, sandboxsetup.PinGrounded)
	var last, total int64
	res, err := sandboxSetupDownload(context.Background(), sandboxDownloadRequest{Pin: e.pin.ID, Progress: func(d, tt int64) { last, total = d, tt }})
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if res.Path != e.final() || res.SHA256 != e.pin.SHA256 || res.Bytes != e.pin.Size || res.Version != "1.0" || res.Source != sandboxsetup.SourceVendorRelease {
		t.Errorf("result = %+v", res)
	}
	if e.fetch.calls != 1 || e.fetch.url != e.pin.URL {
		t.Errorf("fetcher calls %d url %q", e.fetch.calls, e.fetch.url)
	}
	if last != e.pin.Size || total != e.pin.Size {
		t.Errorf("progress = %d/%d", last, total)
	}
	fi, err := os.Lstat(res.Path)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o755 {
		t.Fatalf("placed file %v mode %v", err, fi.Mode())
	}
	if got, _ := os.ReadFile(res.Path); !bytes.Equal(got, body) {
		t.Error("placed bytes differ")
	}
	di, _ := os.Stat(e.dir())
	if di.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %o", di.Mode().Perm())
	}
	e.assertNoTemp(t)
}

func TestSandboxSetupDownload_DigestMismatchRefused(t *testing.T) {
	body := []byte("the real binary")
	e := sandboxDLTest(t, body, []byte("the evil binary"), sandboxsetup.PinGrounded)
	_, err := sandboxSetupDownload(context.Background(), sandboxDownloadRequest{Pin: e.pin.ID})
	if !errors.Is(err, errSandboxDownloadMismatch) {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Lstat(e.final()); !os.IsNotExist(err) {
		t.Errorf("final path exists after a mismatch: %v", err)
	}
	e.assertNoTemp(t)
}

func TestSandboxSetupDownload_SizeOverCapRefused(t *testing.T) {
	body := []byte("0123456789")
	e := sandboxDLTest(t, body, append(append([]byte{}, body...), 'x'), sandboxsetup.PinGrounded)
	if _, err := sandboxSetupDownload(context.Background(), sandboxDownloadRequest{Pin: e.pin.ID}); !errors.Is(err, sandboxsetupnet.ErrTooLarge) {
		t.Fatalf("err = %v", err)
	}
	e.assertNoTemp(t)
	big := filepath.Join(t.TempDir(), "big")
	if err := os.WriteFile(big, bytes.Repeat([]byte("x"), 11), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := sandboxSetupDownload(context.Background(), sandboxDownloadRequest{Pin: e.pin.ID, FromFile: big}); !errors.Is(err, sandboxsetup.ErrFromFileSize) {
		t.Errorf("from_file over the cap: %v", err)
	}
	if _, err := os.Lstat(e.final()); !os.IsNotExist(err) {
		t.Error("a file was placed")
	}
}

func TestSandboxSetupDownload_FromFile(t *testing.T) {
	body := []byte("a verified offline copy")
	e := sandboxDLTest(t, body, nil, sandboxsetup.PinGrounded)
	src := filepath.Join(t.TempDir(), "ch")
	if err := os.WriteFile(src, body, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Run("symlink refused", func(t *testing.T) {
		link := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(src, link); err != nil {
			t.Skip("no symlinks here")
		}
		if _, err := sandboxSetupDownload(context.Background(), sandboxDownloadRequest{Pin: e.pin.ID, FromFile: link}); !errors.Is(err, sandboxsetup.ErrFromFileSymlink) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("wrong bytes refused", func(t *testing.T) {
		bad := filepath.Join(t.TempDir(), "bad")
		if err := os.WriteFile(bad, []byte("a tampered offline copy"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := sandboxSetupDownload(context.Background(), sandboxDownloadRequest{Pin: e.pin.ID, FromFile: bad}); !errors.Is(err, errSandboxDownloadMismatch) {
			t.Errorf("err = %v", err)
		}
		e.assertNoTemp(t)
	})
	t.Run("verified and placed, no network", func(t *testing.T) {
		res, err := sandboxSetupDownload(context.Background(), sandboxDownloadRequest{Pin: e.pin.ID, FromFile: src})
		if err != nil || res.Source != sandboxSourceFromFile || res.SHA256 != e.pin.SHA256 || res.Path != e.final() {
			t.Fatalf("result = %+v, %v", res, err)
		}
		if e.fetch.calls != 0 {
			t.Error("from_file reached the fetcher")
		}
	})
	t.Run("managed node may place a from_file", func(t *testing.T) {
		if _, err := sandboxSetupDownload(context.Background(), sandboxDownloadRequest{Pin: e.pin.ID, FromFile: src, Managed: true}); err != nil {
			t.Errorf("err = %v", err)
		}
	})
}

func TestSandboxSetupDownload_ManagedFetchRefused(t *testing.T) {
	body := []byte("x")
	e := sandboxDLTest(t, body, body, sandboxsetup.PinGrounded)
	_, err := sandboxSetupDownload(context.Background(), sandboxDownloadRequest{Pin: e.pin.ID, Managed: true})
	if !errors.Is(err, errSandboxDownloadManaged) || !strings.Contains(err.Error(), sandboxMirrorKind) {
		t.Fatalf("err = %v", err)
	}
	if e.fetch.calls != 0 {
		t.Error("a managed node reached the vendor release")
	}
}

func TestSandboxSetupDownload_PinRefusals(t *testing.T) {
	body := []byte("x")
	e := sandboxDLTest(t, body, body, sandboxsetup.PinOwed)
	if _, err := sandboxSetupDownload(context.Background(), sandboxDownloadRequest{Pin: e.pin.ID}); !errors.Is(err, errSandboxDownloadOwed) {
		t.Errorf("owed: %v", err)
	}
	if _, err := sandboxSetupDownload(context.Background(), sandboxDownloadRequest{Pin: "nope"}); !errors.Is(err, errSandboxDownloadNoPin) {
		t.Errorf("unknown: %v", err)
	}
	if e.fetch.calls != 0 {
		t.Error("a refused pin reached the fetcher")
	}
}

func TestSandboxSetupDownload_PlacementUnderObserverRefused(t *testing.T) {
	body := []byte("x")
	e := sandboxDLTest(t, body, body, sandboxsetup.PinGrounded)
	e.data = filepath.Join(e.home, ".observer", "share")
	if _, err := sandboxSetupDownload(context.Background(), sandboxDownloadRequest{Pin: e.pin.ID}); !errors.Is(err, sandboxsetup.ErrPlacementForbidden) {
		t.Errorf("err = %v", err)
	}
	if e.fetch.calls != 0 {
		t.Error("a forbidden placement reached the fetcher")
	}
}

func TestSandboxSetupDownload_OneAtATime(t *testing.T) {
	if !dblease.Available() {
		t.Skip("no advisory lease on this platform")
	}
	body := []byte("x")
	e := sandboxDLTest(t, body, body, sandboxsetup.PinGrounded)
	root := filepath.Join(e.data, "superbased-observer", "sandbox-tools")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	release, ok, err := dblease.TryAcquire(root, sandboxDownloadLeaseName)
	if err != nil || !ok {
		t.Fatalf("lease: %v %v", ok, err)
	}
	defer release()
	if _, err := sandboxSetupDownload(context.Background(), sandboxDownloadRequest{Pin: e.pin.ID}); !errors.Is(err, errSandboxDownloadBusy) {
		t.Errorf("err = %v", err)
	}
	if e.fetch.calls != 0 {
		t.Error("a second download reached the fetcher")
	}
}

func TestSandboxSetupDownload_CompiledPinResolves(t *testing.T) {
	for _, p := range sandboxsetup.Pins() {
		if p.GOOS == runtime.GOOS && p.GOARCH == runtime.GOARCH {
			if got, ok := sandboxDownloadPinFor(p.ID); !ok || got != p {
				t.Errorf("PinFor(%s) = %+v, %v", p.ID, got, ok)
			}
		}
	}
}
