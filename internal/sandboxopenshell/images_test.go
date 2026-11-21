package sandboxopenshell

import (
	"strings"
	"testing"
)

var v016 = Version{Major: 0, Minor: 1, Patch: 6}

// TestTestedRowsPinImages: every tested-version row pins both runtime
// images by well-formed digests (ledger row OSH-48), so the managed config
// always names digest references and probe row P8i can pass.
func TestTestedRowsPinImages(t *testing.T) {
	t.Parallel()
	for _, r := range TestedVersions() {
		if !r.Supervisor.pinned() || !r.Sandbox.pinned() {
			t.Errorf("%s: images not pinned: %+v %+v", r.Version, r.Supervisor, r.Sandbox)
		}
		if _, ok := PinnedRuntimeImages(r.Version); !ok {
			t.Errorf("%s: no pinned references", r.Version)
		}
	}
}

// TestPinnedRuntimeImages: the managed config's references are the default
// repositories at the index digests; an untested version has none.
func TestPinnedRuntimeImages(t *testing.T) {
	t.Parallel()
	got, ok := PinnedRuntimeImages(v016)
	if !ok || got.Supervisor != "ghcr.io/nvidia/openshell/supervisor@sha256:ce859a7d77ee515d3fe0b3c7dc61286516f402eb1d25c761d806d9ae5ed96c0b" ||
		got.Sandbox != "ghcr.io/nvidia/openshell/sandbox@sha256:1038eb5c1f191fa3c34684fd7041b891c78ec570979d487f36e06e08f91bfb63" {
		t.Fatalf("got %+v %v", got, ok)
	}
	if !digestRef(got.Supervisor) || !digestRef(got.Sandbox) {
		t.Fatal("not digest references")
	}
	for _, v := range []Version{{Major: 0, Minor: 1, Patch: 7}, {Major: 0, Minor: 1, Patch: 6, Build: "local"}} {
		if _, ok := PinnedRuntimeImages(v); ok {
			t.Errorf("%s: pinned", v)
		}
	}
}

// TestEffectiveRuntimeImages: a configured reference wins per role, else
// the version's default.
func TestEffectiveRuntimeImages(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		cfg  RuntimeImages
		want RuntimeImages
	}{
		{"defaults", RuntimeImages{}, RuntimeImages{Supervisor: "ghcr.io/nvidia/openshell/supervisor:0.1.6", Sandbox: "ghcr.io/nvidia/openshell/sandbox:0.1.6"}},
		{"mirror supervisor", RuntimeImages{Supervisor: " mirror.example/os/supervisor:0.1.6 "}, RuntimeImages{Supervisor: "mirror.example/os/supervisor:0.1.6", Sandbox: "ghcr.io/nvidia/openshell/sandbox:0.1.6"}},
		{"both", RuntimeImages{Supervisor: "a@sha256:x", Sandbox: "b:1"}, RuntimeImages{Supervisor: "a@sha256:x", Sandbox: "b:1"}},
	} {
		if got := EffectiveRuntimeImages(tc.cfg, v016); got != tc.want {
			t.Errorf("%s: got %+v", tc.name, got)
		}
	}
}

// TestClassifyImageInspect: one case per answer shape of `docker image
// inspect --format '{{json .RepoDigests}}'`.
func TestClassifyImageInspect(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name            string
		started         bool
		code            int
		stdout, stderr  string
		read, missing   bool
		digests, detail string
	}{
		{"docker did not start", false, -1, "", "", false, false, "", "did not answer"},
		{"docker 29 no such image", true, 1, "", "Error response from daemon: No such image: x:1\n", true, true, "", ""},
		{"older no such object", true, 1, "", "Error: No such object: x:1\n", true, true, "", ""},
		{"daemon down", true, 1, "", "Cannot connect to the Docker daemon\n", false, false, "", "Cannot connect"},
		{"digests", true, 0, `["r@sha256:aa","m/r@sha256:bb"]` + "\n", "", true, false, "r@sha256:aa,m/r@sha256:bb", ""},
		{"no digests (a local build)", true, 0, "[]\n", "", true, false, "", ""},
		{"not json", true, 0, "<no value>\n", "", false, false, "", "not a digest list"},
	} {
		f := ClassifyImageInspect(ImageSupervisor, "x:1", tc.started, tc.code, tc.stdout, tc.stderr)
		if f.Read != tc.read || f.Missing != tc.missing || strings.Join(f.RepoDigests, ",") != tc.digests || !strings.Contains(f.Detail, tc.detail) {
			t.Errorf("%s: got %+v", tc.name, f)
		}
	}
}

// TestImageVerdict: one case per row of the image table, and the match
// rules (any repository, the index or a platform digest).
func TestImageVerdict(t *testing.T) {
	t.Parallel()
	row, _ := testedRow(v016)
	good := func() []ImageFact {
		return []ImageFact{
			{Role: ImageSupervisor, Ref: "s", Read: true, RepoDigests: []string{"ghcr.io/nvidia/openshell/supervisor@" + row.Supervisor.Index}},
			{Role: ImageSandbox, Ref: "b", Read: true, RepoDigests: []string{"ghcr.io/nvidia/openshell/sandbox@" + row.Sandbox.Index}},
		}
	}
	for _, tc := range []struct {
		name    string
		row     TestedVersion
		mut     func([]ImageFact) []ImageFact
		verdict string
		says    string
	}{
		{"both pinned", row, func(f []ImageFact) []ImageFact { return f }, "", ""},
		{"a mirror keeps the digest", row, func(f []ImageFact) []ImageFact {
			f[0].RepoDigests = []string{"mirror.example:5000/os/supervisor@" + row.Supervisor.Index}
			return f
		}, "", ""},
		{"a platform digest", row, func(f []ImageFact) []ImageFact {
			f[1].RepoDigests = []string{"x/sandbox@" + row.Sandbox.Platforms[0]}
			return f
		}, "", ""},
		{"row without digests (U1)", TestedVersion{Version: v016}, func(f []ImageFact) []ImageFact { return f }, VerdictImageUnpinned, "no pinned digest"},
		{"supervisor not read (U2)", row, func(f []ImageFact) []ImageFact { f[0].Read = false; f[0].Detail = "daemon down"; return f }, VerdictImageUnread, `("daemon down")`},
		{"sandbox fact absent (U2)", row, func(f []ImageFact) []ImageFact { return f[:1] }, VerdictImageUnread, "sandbox runtime image"},
		{"supervisor missing (U3)", row, func(f []ImageFact) []ImageFact { f[0].Missing = true; return f }, VerdictImageMissing, row.Supervisor.Index},
		{"local build, no digest (U4)", row, func(f []ImageFact) []ImageFact { f[0].RepoDigests = nil; return f }, VerdictImageDigestMismatch, "none recorded"},
		{"re-pushed tag (U4)", row, func(f []ImageFact) []ImageFact {
			f[1].RepoDigests = []string{"ghcr.io/nvidia/openshell/sandbox@sha256:" + strings.Repeat("1", 64)}
			return f
		}, VerdictImageDigestMismatch, "sandbox_runtime_image"},
		{"a digest without a repository is not read as one", row, func(f []ImageFact) []ImageFact { f[0].RepoDigests = []string{row.Supervisor.Index}; return f }, VerdictImageDigestMismatch, "supervisor_image"},
	} {
		v, r := ImageVerdict(tc.row, v016, "docker", tc.mut(good()))
		if v != tc.verdict || !strings.Contains(r, tc.says) {
			t.Errorf("%s: got %q %q", tc.name, v, r)
		}
	}
}

// TestImageInspectArgv refuses a reference the argv cannot carry.
func TestImageInspectArgv(t *testing.T) {
	t.Parallel()
	if a, ok := ImageInspectArgv("ghcr.io/nvidia/openshell/sandbox@sha256:" + strings.Repeat("a", 64)); !ok || a[len(a)-1] != "ghcr.io/nvidia/openshell/sandbox@sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("got %v", a)
	}
	for _, bad := range []string{"", "-x", "a b", "a\"b", "a;b"} {
		if _, ok := ImageInspectArgv(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

// TestImageVerdictSkipsUnusedSandbox (audit finding FU7-A10): with
// supervisor_bin set the gateway never uses the sandbox runtime image, so
// row P8i checks the supervisor image alone.
func TestImageVerdictSkipsUnusedSandbox(t *testing.T) {
	t.Parallel()
	row, _ := testedRow(v016)
	facts := []ImageFact{
		{Role: ImageSupervisor, Ref: "s", Read: true, RepoDigests: []string{"r@" + row.Supervisor.Index}},
		{Role: ImageSandbox, Ref: "b", NotUsed: true},
	}
	if v, r := ImageVerdict(row, v016, "docker", facts); v != "" {
		t.Fatalf("got %q %q", v, r)
	}
	facts[0].RepoDigests = nil
	if v, _ := ImageVerdict(row, v016, "docker", facts); v != VerdictImageDigestMismatch {
		t.Fatalf("the supervisor image is still checked: %q", v)
	}
}

// TestImageTagNote (audit finding FU7-A4): one case per shape. The note
// names each tag reference with the digest reference to set; digest
// references need none; supervisor_bin is named as unchecked.
func TestImageTagNote(t *testing.T) {
	t.Parallel()
	row, _ := testedRow(v016)
	pinned, _ := PinnedRuntimeImages(v016)
	for _, tc := range []struct {
		name   string
		images RuntimeImages
		says   []string
		never  []string
	}{
		{"digest references (the managed config)", pinned, nil, nil},
		{"the default tags", DefaultRuntimeImages(v016), []string{
			`supervisor_image = "ghcr.io/nvidia/openshell/supervisor@` + row.Supervisor.Index + `"`,
			`sandbox_runtime_image = "ghcr.io/nvidia/openshell/sandbox@` + row.Sandbox.Index + `"`,
			"resolved to an image once at its own start",
		}, []string{"supervisor_bin"}},
		{"a mirror tag with a registry port", RuntimeImages{Supervisor: "mirror.example:5000/os/supervisor:0.1.6", Sandbox: pinned.Sandbox}, []string{
			`supervisor_image = "mirror.example:5000/os/supervisor@` + row.Supervisor.Index + `"`,
		}, []string{"sandbox_runtime_image"}},
		{"supervisor_bin set", RuntimeImages{Supervisor: pinned.Supervisor, Sandbox: "x:1", SandboxFromBin: true}, []string{
			"sets supervisor_bin",
		}, []string{"sandbox_runtime_image", "by tag"}},
	} {
		got := ImageTagNote(tc.images, row, "docker")
		if len(tc.says) == 0 && got != "" {
			t.Errorf("%s: a note %q", tc.name, got)
		}
		for _, w := range tc.says {
			if !strings.Contains(got, w) {
				t.Errorf("%s: %q lacks %q", tc.name, got, w)
			}
		}
		for _, w := range tc.never {
			if strings.Contains(got, w) {
				t.Errorf("%s: %q holds %q", tc.name, got, w)
			}
		}
	}
	if got := EffectiveRuntimeImages(RuntimeImages{SandboxFromBin: true}, v016); !got.SandboxFromBin {
		t.Fatal("EffectiveRuntimeImages drops SandboxFromBin")
	}
}

// TestImageMissingRemedy (lane FU9): a missing image's remedy names the
// pull of the gateway's reference by its driver's own engine (the Podman
// driver does not pull at the gateway's start), every engine for a driver
// the probe did not read, and never a gateway restart.
func TestImageMissingRemedy(t *testing.T) {
	t.Parallel()
	row, _ := testedRow(v016)
	const ref = "ghcr.io/nvidia/openshell/supervisor:0.1.6"
	for _, tc := range []struct {
		driver, ref string
		says, not   []string
	}{
		{"docker", ref, []string{"`docker pull " + ref + "`", row.Supervisor.Index}, []string{"podman pull", "restart"}},
		{"podman", ref, []string{"`podman pull " + ref + "`", row.Supervisor.Index, "the Podman driver does not"}, []string{"docker pull", "restart"}},
		{"", ref, []string{"`docker pull " + ref + "` (the docker driver) or `podman pull " + ref + "` (the podman driver)"}, []string{"restart"}},
		{"podman", "", []string{"by its pinned digest " + row.Supervisor.Index}, []string{"podman pull", "restart"}},
	} {
		facts := []ImageFact{{Role: ImageSupervisor, Ref: tc.ref, Read: true, Missing: true}}
		v, r := ImageVerdict(row, v016, tc.driver, facts)
		if v != VerdictImageMissing {
			t.Fatalf("%q: verdict %q", tc.driver, v)
		}
		for _, s := range tc.says {
			if !strings.Contains(r, s) {
				t.Errorf("%q %q: reason %q lacks %q", tc.driver, tc.ref, r, s)
			}
		}
		for _, s := range tc.not {
			if strings.Contains(r, s) {
				t.Errorf("%q %q: reason %q names %q", tc.driver, tc.ref, r, s)
			}
		}
	}
}

// TestImageRemediesNameTheDriverTable (audit FU9-A3): the digest-mismatch
// reason and the tag note name the config table of the driver in use, the
// Podman table under Podman, and every driver's table when the probe read
// none. One row per driver.
func TestImageRemediesNameTheDriverTable(t *testing.T) {
	t.Parallel()
	row, _ := testedRow(v016)
	mismatch := []ImageFact{
		{Role: ImageSupervisor, Ref: "s", Read: true},
		{Role: ImageSandbox, Ref: "b", Read: true, RepoDigests: []string{"ghcr.io/nvidia/openshell/sandbox@" + row.Sandbox.Index}},
	}
	for _, tc := range []struct {
		driver string
		says   []string
		never  []string
	}{
		{"docker", []string{"[openshell.drivers.docker]"}, []string{"podman"}},
		{"podman", []string{"[openshell.drivers.podman]"}, []string{"[openshell.drivers.docker]"}},
		{"", []string{"[openshell.drivers.docker] or [openshell.drivers.podman]", "the driver in use"}, nil},
	} {
		v, reason := ImageVerdict(row, v016, tc.driver, mismatch)
		if v != VerdictImageDigestMismatch {
			t.Fatalf("driver %q: verdict %q", tc.driver, v)
		}
		note := ImageTagNote(DefaultRuntimeImages(v016), row, tc.driver)
		for name, got := range map[string]string{"reason": reason, "note": note} {
			for _, w := range tc.says {
				if !strings.Contains(got, w) {
					t.Errorf("driver %q %s %q lacks %q", tc.driver, name, got, w)
				}
			}
			for _, w := range tc.never {
				if strings.Contains(got, w) {
					t.Errorf("driver %q %s %q holds %q", tc.driver, name, got, w)
				}
			}
		}
	}
}
