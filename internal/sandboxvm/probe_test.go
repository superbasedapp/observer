package sandboxvm

import (
	"errors"
	"strings"
	"testing"
)

// goodEnv is a host where every row passes; calls counts each func's calls.
func goodEnv(calls map[string]int) ProbeEnv {
	count := func(k string) { calls[k]++ }
	return ProbeEnv{
		GOOS: "linux", Active: true,
		KVM:  func() KVMFacts { count("kvm"); return KVMFacts{Exists: true, CharDevice: true} },
		InVM: func() bool { count("invm"); return false },
		LookVMM: func() (string, error) {
			count("lookvmm")
			return "/usr/local/bin/cloud-hypervisor", nil
		},
		LookVirtiofsd: func() (string, error) { count("lookfs"); return "/usr/libexec/virtiofsd", nil },
		StatProgram: func(string) (ProgramFacts, error) {
			count("stat")
			return ProgramFacts{Regular: true, OwnerOK: true, Perm: 0o755}, nil
		},
		VMMVersion: func(string) (string, error) { count("version"); return "cloud-hypervisor v54.0", nil },
		ImageSet: func() ImageSetFacts {
			count("imageset")
			return ImageSetFacts{Present: true, Verdict: pass(), Version: "1.0.0"}
		},
	}
}

// TestProbeAvailable: every row passes on a good host.
func TestProbeAvailable(t *testing.T) {
	r := Probe(goodEnv(map[string]int{}))
	if !r.Verdict.OK() || r.Version != "54" || r.Full != "54.0" || r.Beta || r.VMM == "" || r.Virtiofsd == "" || r.ImageSet.Version != "1.0.0" {
		t.Fatalf("result %+v", r)
	}
}

// TestProbeInactiveOpensNothing: off the active row nothing is called, so
// an existing install that never selected the driver opens no /dev/kvm,
// stats no binary and reads no content store.
func TestProbeInactiveOpensNothing(t *testing.T) {
	calls := map[string]int{}
	env := goodEnv(calls)
	env.Active = false
	r := Probe(env)
	if r.Verdict.Code != VerdictDisabledByConfig {
		t.Fatalf("verdict %+v", r.Verdict)
	}
	if len(calls) != 0 {
		t.Fatalf("an inactive probe called %v", calls)
	}
	calls = map[string]int{}
	env = goodEnv(calls)
	env.GOOS = "darwin"
	if r := Probe(env); r.Verdict.Code != VerdictUnsupportedPlatform || len(calls) != 0 {
		t.Fatalf("off Linux: %+v %v", r.Verdict, calls)
	}
}

// TestProbeVerdicts is one case per verdict the ladder gives.
func TestProbeVerdicts(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*ProbeEnv)
		code string
		says string
	}{
		{"no kvm on metal", func(e *ProbeEnv) { e.KVM = func() KVMFacts { return KVMFacts{} } }, VerdictNoHypervisor, "missing"},
		{"no kvm in a vm", func(e *ProbeEnv) {
			e.KVM = func() KVMFacts { return KVMFacts{} }
			e.InVM = func() bool { return true }
		}, VerdictNestedVirtUnavailable, "nested virtualisation"},
		{"kvm not a device", func(e *ProbeEnv) { e.KVM = func() KVMFacts { return KVMFacts{Exists: true} } }, VerdictNoHypervisor, "character device"},
		{"kvm permission", func(e *ProbeEnv) {
			e.KVM = func() KVMFacts {
				return KVMFacts{Exists: true, CharDevice: true, OpenErr: "permission denied", PermissionDenied: true}
			}
		}, VerdictNoHypervisor, "group"},
		{"kvm other error", func(e *ProbeEnv) {
			e.KVM = func() KVMFacts { return KVMFacts{Exists: true, CharDevice: true, OpenErr: "no such device"} }
		}, VerdictNoHypervisor, "no such device"},
		{"no vmm", func(e *ProbeEnv) { e.LookVMM = func() (string, error) { return "", errors.New("not found") } }, VerdictBackendMissing, "cloud-hypervisor is not installed"},
		{"vmm group-writable", func(e *ProbeEnv) {
			e.StatProgram = func(p string) (ProgramFacts, error) {
				return ProgramFacts{Regular: true, OwnerOK: true, Perm: 0o775}, nil
			}
		}, VerdictBackendUntrusted, "never run"},
		{"vmm foreign owner", func(e *ProbeEnv) {
			e.StatProgram = func(p string) (ProgramFacts, error) { return ProgramFacts{Regular: true, Perm: 0o755}, nil }
		}, VerdictBackendUntrusted, "owned by you or root"},
		{"version unreadable", func(e *ProbeEnv) { e.VMMVersion = func(string) (string, error) { return "garbage", nil } }, VerdictVersionUntested, "could not be read"},
		{"version too old", func(e *ProbeEnv) {
			e.VMMVersion = func(string) (string, error) { return "cloud-hypervisor v41.0", nil }
		}, VerdictVersionUntested, "below 54"},
		{"no virtiofsd", func(e *ProbeEnv) { e.LookVirtiofsd = func() (string, error) { return "", errors.New("nope") } }, VerdictBackendMissing, "virtiofsd is not installed"},
		{"no image set", func(e *ProbeEnv) { e.ImageSet = func() ImageSetFacts { return ImageSetFacts{} } }, VerdictImageMissing, "content import"},
		{"image set unverified", func(e *ProbeEnv) {
			e.ImageSet = func() ImageSetFacts {
				return ImageSetFacts{Present: true, Verdict: refuse(VerdictArtifactUnverified, "the manifest expired"), LastKnownGood: "1.0.0"}
			}
		}, VerdictArtifactUnverified, "last set that verified was 1.0.0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := goodEnv(map[string]int{})
			tc.mut(&env)
			r := Probe(env)
			if r.Verdict.Code != tc.code || !strings.Contains(r.Verdict.Reason, tc.says) {
				t.Fatalf("verdict %+v, want %s naming %q", r.Verdict, tc.code, tc.says)
			}
		})
	}
}

// TestProbeNewerVersionIsBeta: a version above the tested range is usable
// and marked beta (never refused).
func TestProbeNewerVersionIsBeta(t *testing.T) {
	env := goodEnv(map[string]int{})
	env.VMMVersion = func(string) (string, error) { return "cloud-hypervisor v55.1-3-gdeadbee", nil }
	r := Probe(env)
	if !r.Verdict.OK() || !r.Beta || r.Version != "55" || r.Full != "55.1" {
		t.Fatalf("result %+v", r)
	}
}

func TestParseVMMVersion(t *testing.T) {
	for raw, want := range map[string]string{
		"cloud-hypervisor v54.0":             "54.0",
		"cloud-hypervisor v54.0-7-g1234abcd": "54.0",
		"cloud-hypervisor 54.1.2":            "54.1.2",
		"cloud-hypervisor":                   "",
		"":                                   "",
		"cloud-hypervisor vX.0":              "",
		"cloud-hypervisor v54":               "",
		"cloud-hypervisor v54.0 extra v55.0": "54.0",
	} {
		if got := ParseVMMVersion(raw); got != want {
			t.Errorf("%q: %q, want %q", raw, got, want)
		}
	}
}
