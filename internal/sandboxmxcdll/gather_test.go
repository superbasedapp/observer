package sandboxmxcdll

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxmxc"
)

// fakeFS and fakeLib stand in for the files and the C ABI; every call is
// recorded so the order and the stops are pinned.
type fakeFS struct {
	content  map[string][]byte
	unsigned map[string]bool
	calls    []string
	open     int
}

type heldBuf struct {
	*bytes.Reader
	fs     *fakeFS
	closed bool
}

func (h *heldBuf) Close() error {
	if !h.closed {
		h.closed = true
		h.fs.open--
	}
	return nil
}

type fakeLib struct {
	calls   *[]string
	version string
	probe   string
	probeE  error
	run     RunResult
	closed  bool
}

func (l *fakeLib) Version() string { *l.calls = append(*l.calls, "version"); return l.version }
func (l *fakeLib) ProbeRequest(doc []byte) ([]byte, error) {
	*l.calls = append(*l.calls, "probe:"+string(doc))
	return []byte(l.probe), l.probeE
}

func (l *fakeLib) RunOneShot(doc []byte) (RunResult, error) {
	*l.calls = append(*l.calls, "run:"+string(doc))
	return l.run, nil
}

func (l *fakeLib) Close() error { l.closed = true; *l.calls = append(*l.calls, "close"); return nil }

const goodProbe = `{"tier":"base-container","needsDaclAugmentation":false,"warnings":[],"probes":{"baseContainerSupportsIngressHostLoopbackAllow":true,"baseContainerSupportsIdentitylessLoopbackProxy":true}}`

func fixture(t *testing.T) (*fakeFS, *fakeLib, Env) {
	t.Helper()
	fs := &fakeFS{content: map[string][]byte{}, unsigned: map[string]bool{}}
	m := sandboxmxc.Manifest{Version: "1.0.1"}
	dir := filepath.Join(t.TempDir(), "mxc")
	for _, name := range []string{sandboxmxc.FileFFI, sandboxmxc.FileExec} {
		b := []byte("bytes of " + name)
		sum := sha256.Sum256(b)
		fs.content[filepath.Join(dir, name)] = b
		m.Files = append(m.Files, sandboxmxc.BundledFile{Name: name, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(b))})
	}
	lib := &fakeLib{calls: &fs.calls, version: "1.0.1", probe: goodProbe}
	env := Env{
		Windows: true, Active: true, Dir: dir, Manifest: m, HasPinnedSet: true,
		Build: func() (int, int, string) { return 26200, 9711, "Core" },
		Open: func(p string) (HeldFile, error) {
			fs.calls = append(fs.calls, "open:"+filepath.Base(p))
			b, ok := fs.content[p]
			if !ok {
				return nil, errors.New("not found")
			}
			fs.open++
			return &heldBuf{Reader: bytes.NewReader(b), fs: fs}, nil
		},
		Verify: func(p string, _ HeldFile) error {
			fs.calls = append(fs.calls, "verify:"+filepath.Base(p))
			if fs.unsigned[filepath.Base(p)] {
				return errors.New("TRUST_E_NOSIGNATURE")
			}
			return nil
		},
		Load: func(p string, f HeldFile) (Library, error) {
			if f == nil || filepath.Base(p) != sandboxmxc.FileFFI {
				t.Fatalf("load of %s without its held handle", p)
			}
			fs.calls = append(fs.calls, "load:"+filepath.Base(p))
			return lib, nil
		},
		ProbeDoc: []byte("P"), CheckDoc: []byte("C"),
	}
	return fs, lib, env
}

// TestGatherOrder is milestone 2's lifecycle pin: each file is opened,
// hashed and verified before the library loads; the version is read before
// the probe; the create-and-close check runs last; everything is released.
func TestGatherOrder(t *testing.T) {
	t.Parallel()
	fs, lib, env := fixture(t)
	f, v := Gather(env, false)
	if r := sandboxmxc.Probe(f, env.Manifest); !r.Verdict.OK() {
		t.Fatalf("verdict %+v", r)
	}
	want := "open:mxc_ffi.dll verify:mxc_ffi.dll open:wxc-exec.exe verify:wxc-exec.exe load:mxc_ffi.dll version probe:P run:C close"
	if got := strings.Join(fs.calls, " "); got != want {
		t.Fatalf("calls\n got %s\nwant %s", got, want)
	}
	if v != nil || fs.open != 0 || !lib.closed {
		t.Fatalf("not released: v=%v open=%d", v, fs.open)
	}
}

func TestGatherKeepOpen(t *testing.T) {
	t.Parallel()
	fs, lib, env := fixture(t)
	_, v := Gather(env, true)
	if v == nil || v.Library == nil || fs.open != 2 {
		t.Fatalf("kept: %v open=%d", v, fs.open)
	}
	if v.Path(sandboxmxc.FileExec) != filepath.Join(env.Dir, sandboxmxc.FileExec) {
		t.Fatalf("path %q", v.Path(sandboxmxc.FileExec))
	}
	v.Release()
	if fs.open != 0 || !lib.closed {
		t.Fatal("release")
	}
}

// TestGatherStops: nothing is opened or loaded past the first refusal.
func TestGatherStops(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		mut     func(*fakeFS, *fakeLib, *Env)
		code    string
		notCall string
	}{
		{"inactive opens nothing", func(_ *fakeFS, _ *fakeLib, e *Env) { e.Active = false }, sandboxmxc.VerdictDisabledByConfig, "open:"},
		{"not windows opens nothing", func(_ *fakeFS, _ *fakeLib, e *Env) { e.Windows = false }, sandboxmxc.VerdictUnsupportedPlatform, "open:"},
		{"below the floor opens nothing", func(_ *fakeFS, _ *fakeLib, e *Env) {
			e.Build = func() (int, int, string) { return 26200, 9168, "Core" }
		}, sandboxmxc.VerdictPSECBuildTooOld, "open:"},
		{"no pinned set", func(_ *fakeFS, _ *fakeLib, e *Env) { e.HasPinnedSet = false }, sandboxmxc.VerdictArtifactMissing, "open:"},
		{"missing dll never loads", func(fs *fakeFS, _ *fakeLib, e *Env) {
			delete(fs.content, filepath.Join(e.Dir, sandboxmxc.FileFFI))
		}, sandboxmxc.VerdictArtifactMissing, "load:"},
		{"tampered dll is never verified or loaded", func(fs *fakeFS, _ *fakeLib, e *Env) {
			fs.content[filepath.Join(e.Dir, sandboxmxc.FileFFI)] = []byte("bytes of mxc_ffi.dlX")
		}, sandboxmxc.VerdictArtifactUnverified, "verify:mxc_ffi"},
		{"truncated dll", func(fs *fakeFS, _ *fakeLib, e *Env) {
			fs.content[filepath.Join(e.Dir, sandboxmxc.FileFFI)] = []byte("bytes")
		}, sandboxmxc.VerdictArtifactUnverified, "load:"},
		{"unsigned exec never loads the dll", func(fs *fakeFS, _ *fakeLib, _ *Env) { fs.unsigned[sandboxmxc.FileExec] = true }, sandboxmxc.VerdictArtifactUnverified, "load:"},
		{"old library is never probed", func(_ *fakeFS, l *fakeLib, _ *Env) { l.version = "0.9.0" }, sandboxmxc.VerdictBackendVersionUntested, "probe:"},
		{"a native probe failure creates nothing", func(_ *fakeFS, l *fakeLib, _ *Env) {
			l.probeE = &NativeError{Status: 4, Message: "BaseContainer unavailable"}
		}, sandboxmxc.VerdictPSECUnavailable, "run:"},
		// Live check 2026-10-22 (finding L2): MXC rejected the request; the
		// verdict says so instead of blaming the platform.
		{"a rejected request creates nothing", func(_ *fakeFS, l *fakeLib, _ *Env) {
			l.probeE = &NativeError{Status: 1, Message: "Configuration parse error: ProcessContainer runtimeConfig.networkProxy requires network.ingress.default='allow'"}
		}, sandboxmxc.VerdictRequestRejected, "run:"},
		{"a weaker tier creates nothing", func(_ *fakeFS, l *fakeLib, _ *Env) {
			l.probe = `{"tier":"appcontainer-dacl","needsDaclAugmentation":true,"warnings":[],"probes":{}}`
		}, sandboxmxc.VerdictPSECUnavailable, "run:"},
		{"create-and-close failure", func(_ *fakeFS, l *fakeLib, _ *Env) {
			l.run = RunResult{Status: 12, Error: &NativeError{Status: 12, Message: "x"}}
		}, sandboxmxc.VerdictPSECUnavailable, ""},
	}
	for _, c := range cases {
		fs, lib, env := fixture(t)
		c.mut(fs, lib, &env)
		f, v := Gather(env, true)
		r := sandboxmxc.Probe(f, env.Manifest)
		if r.Verdict.Code != c.code {
			t.Errorf("%s: got %s (%s)", c.name, r.Verdict.Code, r.Verdict.Reason)
		}
		if v != nil {
			t.Errorf("%s: a refused gather kept files open", c.name)
		}
		if fs.open != 0 {
			t.Errorf("%s: %d files left open", c.name, fs.open)
		}
		if c.notCall != "" {
			for _, call := range fs.calls {
				if strings.HasPrefix(call, c.notCall) {
					t.Errorf("%s: called %s", c.name, call)
				}
			}
		}
	}
}

func TestNativeErrorText(t *testing.T) {
	t.Parallel()
	e := &NativeError{Status: 4, Message: "no BaseContainer", NativeCode: "0x80070490"}
	if e.Error() != "backend_unavailable: no BaseContainer (0x80070490)" {
		t.Fatal(e.Error())
	}
	for st, want := range map[int]string{0: "success", 1: "malformed_request", 11: "policy_validation", 99: "backend_error"} {
		if StatusName(st) != want {
			t.Errorf("%d: %s", st, StatusName(st))
		}
	}
}

func TestOtherHostEnvNeverLoads(t *testing.T) {
	t.Parallel()
	env := HostEnv(t.TempDir(), true, nil, nil)
	if env.Windows {
		t.Skip("windows host")
	}
	if env.Load != nil || env.Open != nil {
		t.Fatal("a non-Windows host env can open or load")
	}
	if InsideAppContainer() {
		t.Fatal("not an AppContainer")
	}
	if _, inside := AppContainerSID(); inside {
		t.Fatal("an AppContainer SID off Windows")
	}
	if _, err := AppContainerProfileSID("observer-r1"); err == nil {
		t.Fatal("a profile SID off Windows")
	}
}

// TestGatherStages: the live checks' early stops create nothing.
func TestGatherStages(t *testing.T) {
	t.Parallel()
	fs, _, env := fixture(t)
	env.Stage = StageVersion
	f, v := Gather(env, true)
	if v != nil || f.LibraryVersion != "1.0.1" || f.ProbeJSON != "" {
		t.Fatalf("version stage %+v", f)
	}
	for _, c := range fs.calls {
		if strings.HasPrefix(c, "probe:") || strings.HasPrefix(c, "run:") {
			t.Fatalf("version stage called %s", c)
		}
	}
	fs, _, env = fixture(t)
	env.Stage = StageRequest
	f, v = Gather(env, true)
	if v != nil || f.ProbeJSON == "" || f.CreateClose != nil {
		t.Fatalf("request stage %+v", f)
	}
	for _, c := range fs.calls {
		if strings.HasPrefix(c, "run:") {
			t.Fatal("the request stage created a container")
		}
	}
	if fs.open != 0 {
		t.Fatal("files left open")
	}
}
