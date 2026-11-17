//go:build !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/extrun/extruntest"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxopenshell"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

// openShellNotFoundText is v0.1.6's exact text for a missing box (live,
// o0-receipts.md CLI table "Get"), as miette prints it.
// openShellTestServer is the measured host's gateway server.
const openShellTestServer = "https://127.0.0.1:17670"

const openShellNotFoundText = "Error:   × code: 'Some requested entity was not found', message: \"sandbox not found\""

// openShellFake is a scripted openshell and docker: each answer keyed by
// the program's base name and its argv.
type openShellFake struct {
	cliMissing bool
	// cliDir is where the resolver finds the openshell CLI ("": /usr/bin).
	cliDir  string
	version string
	status  string
	info    string
	canary  extrun.ExecFacts
	// engineID is the ID `docker info` answers ("": openShellTestEngineID).
	engineID string
	// inspect answers `docker image inspect` of a runtime image (nil: the
	// pinned digests, openShellFakeImageInspect).
	inspect func(ref string) extrun.ExecFacts
	// settings and global answer row PS (lane FU8): the gateway's
	// settings listing and its global policy read.
	settings string
	global   extrun.ExecFacts
	// answer overrides any call (nil: the defaults above).
	answer func(prog string, args []string) (extrun.ExecFacts, bool)
}

// healthyOpenShell answers like the measured host: v0.1.6 both sides,
// connected and authenticated, the Docker driver, canary ABI 4.
func healthyOpenShell() *openShellFake {
	return &openShellFake{
		version:  "openshell 0.1.6\n",
		status:   `{"gateway":"openshell","server":"https://127.0.0.1:17670","status":"connected","version":"0.1.6","authentication":{"status":"authenticated"}}`,
		info:     `{"gateway":"openshell","compute_drivers":[{"name":"docker","capabilities":{"driver_name":"docker"}}]}`,
		canary:   extrun.ExecFacts{Stdout: []byte("O0:canary=4 0\n"), PeakChildren: -1},
		settings: `{"proposal_approval_mode":"manual","agent_policy_proposals_enabled":false}`,
		global:   extrun.ExecFacts{Stdout: []byte("null"), PeakChildren: -1},
	}
}

func (f *openShellFake) facts(p extrun.Plan) extrun.ExecFacts {
	prog := filepath.Base(p.Path)
	if f.answer != nil {
		if out, ok := f.answer(prog, p.Args); ok {
			return out
		}
	}
	ok := func(s string) extrun.ExecFacts { return extrun.ExecFacts{Stdout: []byte(s), PeakChildren: -1} }
	switch {
	case prog == "docker" && len(p.Args) > 0 && p.Args[0] == "info":
		if f.engineID != "" {
			return ok(`"` + f.engineID + `"` + "\n")
		}
		return ok(`"` + openShellTestEngineID + `"` + "\n")
	case prog == "docker" && len(p.Args) > 1 && p.Args[0] == "image" && p.Args[1] == "inspect":
		if f.inspect != nil {
			return f.inspect(p.Args[len(p.Args)-1])
		}
		return openShellFakeImageInspect(p.Args)
	case prog == "docker":
		return f.canary
	case slices.Equal(p.Args, []string{"--version"}):
		return ok(f.version)
	case slices.Contains(p.Args, "status"):
		return ok(f.status)
	case slices.Contains(p.Args, "info"):
		return ok(f.info)
	case slices.Contains(p.Args, "settings"):
		return ok(f.settings)
	case slices.Contains(p.Args, "policy") && slices.Contains(p.Args, "--global"):
		return f.global
	}
	return extrun.ExecFacts{ExitCode: 2, Stderr: []byte("unscripted"), PeakChildren: -1}
}

// runner returns an extruntest runner over the fake.
// The fake runners resolve the OpenShell programs to /usr/bin paths that
// do not exist on the test host: the trust rule (ledger row OSH-44) reads
// them as the package's root-owned files unless a test says otherwise.
func init() { openShellBinaryFactsFn = openShellFakeBinaryFacts }

// openShellFakeBinaryFacts reads every program as a root-owned 0755 file
// in /usr/bin, except one under /home, which is the user's.
func openShellFakeBinaryFacts(program, path string) sandboxopenshell.BinaryTrustFacts {
	uid := 0
	if strings.HasPrefix(path, "/home/") {
		uid = 1000
	}
	return sandboxopenshell.BinaryTrustFacts{
		Program: program, Path: path, Real: path, Read: true,
		File: sandboxopenshell.PathOwner{Path: path, UID: uid, Mode: 0o755},
		Dirs: []sandboxopenshell.PathOwner{{Path: filepath.Dir(path), UID: uid, Mode: 0o755}, {Path: "/", UID: 0, Mode: 0o755}},
	}
}

// openShellFakeImageInspect answers `docker image inspect` like an engine
// that pulled v0.1.6's runtime images (ledger row OSH-48): the RepoDigests
// list carries the pinned index digest of the image's repository (a digest
// reference keeps its own repository), and the {{.Id}} form answers an id.
func openShellFakeImageInspect(args []string) extrun.ExecFacts {
	ok := func(s string) extrun.ExecFacts { return extrun.ExecFacts{Stdout: []byte(s), PeakChildren: -1} }
	if !slices.Contains(args, "{{json .RepoDigests}}") {
		return ok("sha256:SENTINEL\n")
	}
	ref := args[len(args)-1]
	row := sandboxopenshell.TestedVersions()[0]
	repo, _, _ := strings.Cut(ref, "@")
	if i := strings.LastIndexByte(repo, ':'); i > strings.LastIndexByte(repo, '/') {
		repo = repo[:i]
	}
	digest := row.Sandbox.Index
	if strings.Contains(repo, "supervisor") {
		digest = row.Supervisor.Index
	}
	return ok(`["` + repo + "@" + digest + `"]` + "\n")
}

func (f *openShellFake) runner() (*extrun.Runner, *extruntest.Executor) {
	ex := &extruntest.Executor{Facts: f.facts}
	r := extruntest.NewRunner("linux", extruntest.Files{"/usr/bin/openshell": {}, "/usr/bin/docker": {}}, ex, nil)
	r.Resolve = func(s integration.BinaryResolveSpec) toolresolve.Resolution {
		name := s.Names.Unix[0]
		if name == sandboxopenshell.Program && f.cliMissing {
			return toolresolve.Resolution{Verdict: toolresolve.VerdictNotFound}
		}
		if name == sandboxopenshell.Program && f.cliDir != "" {
			return toolresolve.Resolution{Verdict: toolresolve.VerdictOK, Bin: f.cliDir + "/" + name}
		}
		return toolresolve.Resolution{Verdict: toolresolve.VerdictOK, Bin: "/usr/bin/" + name}
	}
	return r, ex
}

// healthyHost is the measured host's facts.
func healthyHost() openShellHostFactsT {
	return openShellHostFactsT{
		LandlockABI: func() int { return 4 },
		DockerGroup: func() bool { return true },
		BindMounts:  func(string) sandboxopenshell.Tri { return sandboxopenshell.TriYes },
		ObserverBin: "/usr/local/bin/observer",
		IDs:         func() (int, int) { return 1000, 1000 },
		// The engine the row first used is the one the fake docker
		// answers (row P8e).
		EngineRecord: func() (string, []byte, error) {
			return "/s/" + sandboxopenshell.EngineRecordFile, []byte(`{"engine_id":"` + openShellTestEngineID + `","first_seen":1}`), nil
		},
		SaveEngine: func([]byte) error { return errors.New("a recorded engine is never written again") },
	}
}

// openShellTestEngineID is the engine ID the fake docker answers.
const openShellTestEngineID = "ABCD:EFGH:IJKL:MNOP:QRST:UVWX:YZ23:4567:ABCD:EFGH:IJKL:MNOP"

// TestOpenShellProbeLadder (lane O1B M1): one case per verdict row of the
// probe table, driven through the fake exec seam. Each case also pins that
// gathering stops at the failing row: no program after it runs.
func TestOpenShellProbeLadder(t *testing.T) {
	cases := []struct {
		name    string
		cfg     config.TerminalSandboxOpenShellConfig
		host    sandboxbackend.HostKind
		mutF    func(*openShellFake)
		mutH    func(*openShellHostFactsT)
		verdict string
		rule    string
		// lastProg is the last program the ladder may start ("" none).
		lastProg string
	}{
		{name: "P0 an unknown mode", cfg: config.TerminalSandboxOpenShellConfig{GatewayMode: "remote"}, verdict: sandboxopenshell.VerdictGatewayModeNotBuilt, rule: "P0"},
		{name: "PG managed mode with no lifecycle pass", cfg: config.TerminalSandboxOpenShellConfig{GatewayMode: "managed"}, verdict: sandboxopenshell.VerdictGatewayNotReady, rule: "PG", lastProg: "openshell"},
		{name: "P1 WSL2", host: sandboxbackend.HostWSL2, verdict: sandboxopenshell.VerdictUnsupportedPlatform, rule: "P1"},
		{name: "P1 macOS", host: sandboxbackend.HostMacOS, verdict: sandboxopenshell.VerdictUnsupportedPlatform, rule: "P1"},
		{name: "P2 CLI missing", mutF: func(f *openShellFake) { f.cliMissing = true }, verdict: sandboxopenshell.VerdictMissing, rule: "P2"},
		// Ledger row OSH-44: a CLI found only in a dir the user can write
		// (a tool fallback dir another backend binds into a box) is never
		// run, not even for its version.
		{name: "P2 CLI only in a user-writable fallback dir", mutF: func(f *openShellFake) { f.cliDir = "/home/dev/.local/bin" }, verdict: sandboxopenshell.VerdictBinaryUntrusted, rule: "P2"},
		{name: "P3 gateway disconnected", mutF: func(f *openShellFake) {
			f.status = `{"gateway":"openshell","status":"disconnected","version":"0.1.6","authentication":{"status":"unverified"}}`
		}, verdict: sandboxopenshell.VerdictGatewayUnreachable, rule: "P3", lastProg: "openshell"},
		{name: "P3 status unreadable", mutF: func(f *openShellFake) { f.status = "not json" }, verdict: sandboxopenshell.VerdictGatewayUnreachable, rule: "P3", lastProg: "openshell"},
		{name: "P4 not authenticated", mutF: func(f *openShellFake) {
			f.status = `{"gateway":"openshell","status":"connected","version":"0.1.6","authentication":{"status":"failed"}}`
		}, verdict: sandboxopenshell.VerdictGatewayUnauthed, rule: "P4", lastProg: "openshell"},
		{name: "P4b a remote gateway", mutF: func(f *openShellFake) {
			f.status = strings.Replace(f.status, openShellTestServer, "https://gateway.example.com:17670", 1)
		}, verdict: sandboxopenshell.VerdictGatewayNotLocal, rule: "P4b", lastProg: "openshell"},
		{name: "P4b no server in the answer", mutF: func(f *openShellFake) {
			f.status = strings.Replace(f.status, `"server":"`+openShellTestServer+`",`, "", 1)
		}, verdict: sandboxopenshell.VerdictGatewayNotLocal, rule: "P4b", lastProg: "openshell"},
		{name: "P4b a loopback gateway on another port", mutF: func(f *openShellFake) {
			f.status = strings.Replace(f.status, openShellTestServer, "https://[::1]:9443", 1)
		}, verdict: sandboxopenshell.VerdictAvailable, rule: "P10", lastProg: "openshell"},
		{name: "P5 CLI and gateway differ", mutF: func(f *openShellFake) { f.version = "openshell 0.1.7\n" }, verdict: sandboxopenshell.VerdictVersionMismatch, rule: "P5", lastProg: "openshell"},
		{name: "P5 too old", mutF: func(f *openShellFake) {
			f.version = "openshell 0.1.5\n"
			f.status = strings.Replace(f.status, `"0.1.6"`, `"0.1.5"`, 1)
		}, verdict: sandboxopenshell.VerdictVersionTooOld, rule: "P5", lastProg: "openshell"},
		{name: "P5 untested", mutF: func(f *openShellFake) {
			f.version = "openshell 0.1.8\n"
			f.status = strings.Replace(f.status, `"0.1.6"`, `"0.1.8"`, 1)
		}, verdict: sandboxopenshell.VerdictVersionUntested, rule: "P5", lastProg: "openshell"},
		{name: "P5 pin mismatch", cfg: config.TerminalSandboxOpenShellConfig{Version: "0.1.7"}, verdict: sandboxopenshell.VerdictVersionPinMismatch, rule: "P5", lastProg: "openshell"},
		{name: "P5 CLI version unreadable", mutF: func(f *openShellFake) { f.version = "garbage" }, verdict: sandboxopenshell.VerdictVersionUnknown, rule: "P5", lastProg: "openshell"},
		// The P6 lift (lane FU7, F-033): the Podman driver is taken on
		// v0.1.6, whose row names its launch receipt; no `docker info` runs
		// for it (row P8e does not apply), the image checks and the canary
		// do.
		// FU7-A1: the shipped table names no Podman receipt yet (the
		// PENDING placeholder), so the Podman driver is refused at P6.
		{name: "P6 the Podman driver, receipt pending in the shipped table", mutF: func(f *openShellFake) {
			f.info = `{"compute_drivers":[{"name":"podman"}]}`
		}, verdict: sandboxopenshell.VerdictDriverUntested, rule: "P6", lastProg: "openshell"},
		{name: "P6 an unmeasured driver", mutF: func(f *openShellFake) {
			f.info = `{"compute_drivers":[{"name":"lxc"}]}`
		}, verdict: sandboxopenshell.VerdictDriverUntested, rule: "P6", lastProg: "openshell"},
		{name: "P6 driver unreadable", mutF: func(f *openShellFake) { f.info = "{}" }, verdict: sandboxopenshell.VerdictDriverUntested, rule: "P6", lastProg: "openshell"},
		{name: "P7 Landlock ABI 2", mutH: func(h *openShellHostFactsT) { h.LandlockABI = func() int { return 2 } }, verdict: sandboxopenshell.VerdictLandlockABITooOld, rule: "P7", lastProg: "openshell"},
		{name: "P8 the runtime answers ENOSYS", mutF: func(f *openShellFake) {
			f.canary = extrun.ExecFacts{Stdout: []byte("O0:canary=-1 38\n"), PeakChildren: -1}
		}, verdict: sandboxopenshell.VerdictRuntimeBlocksLandlock, rule: "P8", lastProg: "docker"},
		{name: "P8e another engine answers at the socket", mutF: func(f *openShellFake) {
			f.engineID = "5b1e3f0a-6c0d-4a8e-9f1a-2b3c4d5e6f70"
		}, verdict: sandboxopenshell.VerdictEngineChanged, rule: "P8e", lastProg: "docker"},
		{name: "P8e the engine's ID cannot be read", mutF: func(f *openShellFake) {
			f.answer = func(prog string, args []string) (extrun.ExecFacts, bool) {
				if prog == "docker" && len(args) > 0 && args[0] == "info" {
					return extrun.ExecFacts{ExitCode: 1, Stderr: []byte("Cannot connect to the Docker daemon\n"), PeakChildren: -1}, true
				}
				return extrun.ExecFacts{}, false
			}
		}, verdict: sandboxopenshell.VerdictEngineUnread, rule: "P8e", lastProg: "docker"},
		{name: "P8i the supervisor image was re-pushed under its tag", mutF: func(f *openShellFake) {
			f.inspect = func(ref string) extrun.ExecFacts {
				return extrun.ExecFacts{Stdout: []byte(`["` + strings.Split(ref, ":")[0] + `@sha256:` + strings.Repeat("0", 64) + `"]`), PeakChildren: -1}
			}
		}, verdict: sandboxopenshell.VerdictImageDigestMismatch, rule: "P8i", lastProg: "docker"},
		{name: "P8i the sandbox image is not on the host", mutF: func(f *openShellFake) {
			f.inspect = func(ref string) extrun.ExecFacts {
				if strings.Contains(ref, "/sandbox") {
					return extrun.ExecFacts{ExitCode: 1, Stderr: []byte("Error response from daemon: No such image: " + ref + "\n"), PeakChildren: -1}
				}
				return openShellFakeImageInspect([]string{"image", "inspect", "--format", "{{json .RepoDigests}}", ref})
			}
		}, verdict: sandboxopenshell.VerdictImageMissing, rule: "P8i", lastProg: "docker"},
		{name: "P8i a mirror named in the gateway's config keeps the digest", mutH: func(h *openShellHostFactsT) {
			h.GatewayImages = func(string) sandboxopenshell.RuntimeImages {
				return sandboxopenshell.RuntimeImages{Supervisor: "mirror.example:5000/os/supervisor:0.1.6"}
			}
		}, verdict: sandboxopenshell.VerdictAvailable, rule: "P10", lastProg: "openshell"},
		// FU7-A10: an external gateway whose config sets supervisor_bin
		// does not use the sandbox runtime image; P8i checks the
		// supervisor image alone and the probe hint names the gap.
		{name: "P8i supervisor_bin set: the sandbox image is not checked", mutF: func(f *openShellFake) {
			f.inspect = func(ref string) extrun.ExecFacts {
				if strings.Contains(ref, "/sandbox") {
					return extrun.ExecFacts{ExitCode: 1, Stderr: []byte("Error response from daemon: No such image: " + ref + "\n"), PeakChildren: -1}
				}
				return openShellFakeImageInspect([]string{"image", "inspect", "--format", "{{json .RepoDigests}}", ref})
			}
		}, mutH: func(h *openShellHostFactsT) {
			h.GatewayImages = func(string) sandboxopenshell.RuntimeImages {
				return sandboxopenshell.RuntimeImages{SandboxFromBin: true}
			}
		}, verdict: sandboxopenshell.VerdictAvailable, rule: "P10", lastProg: "openshell"},
		{name: "P8 the canary image is not on the host", mutF: func(f *openShellFake) {
			f.canary = extrun.ExecFacts{ExitCode: 125, Stderr: []byte("docker: Error response from daemon: No such image: ghcr.io/nvidia/openshell/supervisor:0.1.6\n"), PeakChildren: -1}
		}, verdict: sandboxopenshell.VerdictCanaryImageMissing, rule: "P8", lastProg: "docker"},
		{name: "P8 the canary call times out", mutF: func(f *openShellFake) {
			f.canary = extrun.ExecFacts{Signaled: true, Signal: "killed", KillReason: extrun.KillTimeout, PeakChildren: -1}
		}, verdict: sandboxopenshell.VerdictCanaryTimedOut, rule: "P8", lastProg: "docker"},
		{name: "P8 docker cannot execute the canary", mutF: func(f *openShellFake) {
			f.canary = extrun.ExecFacts{ExitCode: 126, Stderr: []byte("exec /observer-canary: permission denied\n"), PeakChildren: -1}
		}, verdict: sandboxopenshell.VerdictCanaryNotStarted, rule: "P8", lastProg: "docker"},
		{
			// The last program is row P8i's image inspect: the canary
			// itself never starts.
			name: "P8 Observer's own binary is not known", mutH: func(h *openShellHostFactsT) { h.ObserverBin = "" },
			verdict: sandboxopenshell.VerdictCanaryNotStarted, rule: "P8", lastProg: "docker",
		},
		{name: "P8 no marker", mutF: func(f *openShellFake) {
			f.canary = extrun.ExecFacts{Stdout: []byte("hello\n"), PeakChildren: -1}
		}, verdict: sandboxopenshell.VerdictCanaryFailed, rule: "P8", lastProg: "docker"},
		{name: "P9 bind mounts off", mutH: func(h *openShellHostFactsT) {
			h.BindMounts = func(string) sandboxopenshell.Tri { return sandboxopenshell.TriNo }
		}, verdict: sandboxopenshell.VerdictBindMountsDisabled, rule: "P9", lastProg: "docker"},
		{name: "P9 bind mounts unknown", mutH: func(h *openShellHostFactsT) {
			h.BindMounts = func(string) sandboxopenshell.Tri { return sandboxopenshell.TriUnknown }
		}, verdict: sandboxopenshell.VerdictBindMountsUnknown, rule: "P9", lastProg: "docker"},
		{name: "PS gateway auto approval", mutF: func(f *openShellFake) {
			f.settings = `{"proposal_approval_mode":"auto","agent_policy_proposals_enabled":false}`
		}, verdict: sandboxopenshell.VerdictGatewayAutoApproval, rule: "PS", lastProg: "openshell"},
		{name: "PS gateway proposals on", mutF: func(f *openShellFake) {
			f.settings = "proposal_approval_mode manual\nagent_policy_proposals_enabled true\n"
		}, verdict: sandboxopenshell.VerdictGatewayPolicyProposals, rule: "PS", lastProg: "openshell"},
		{name: "PS gateway global policy", mutF: func(f *openShellFake) {
			f.global = extrun.ExecFacts{Stdout: []byte(`{"policy":{"version":1,"network_policies":{}}}`), PeakChildren: -1}
		}, verdict: sandboxopenshell.VerdictGatewayGlobalPolicy, rule: "PS", lastProg: "openshell"},
		{
			name: "PS settings unreadable", mutF: func(f *openShellFake) { f.settings = "error: unknown subcommand" },
			verdict: sandboxopenshell.VerdictGatewaySettingsUnknown, rule: "PS", lastProg: "openshell",
		},
		{name: "PS no global policy (failed read naming none)", mutF: func(f *openShellFake) {
			f.global = extrun.ExecFacts{ExitCode: 1, Stderr: []byte("Error: no global policy is set\n"), PeakChildren: -1}
		}, verdict: sandboxopenshell.VerdictAvailable, rule: "P10", lastProg: "openshell"},
		{name: "PS global read fails otherwise", mutF: func(f *openShellFake) {
			f.global = extrun.ExecFacts{ExitCode: 1, Stderr: []byte("Error: transport error\n"), PeakChildren: -1}
		}, verdict: sandboxopenshell.VerdictGatewaySettingsUnknown, rule: "PS", lastProg: "openshell"},
		{name: "P10 available", verdict: sandboxopenshell.VerdictAvailable, rule: "P10", lastProg: "openshell"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := healthyOpenShell()
			if tc.mutF != nil {
				tc.mutF(f)
			}
			hf := healthyHost()
			if tc.mutH != nil {
				tc.mutH(&hf)
			}
			host := tc.host
			if host == "" {
				host = sandboxbackend.HostLinux
			}
			r, ex := f.runner()
			cfg := tc.cfg
			if cfg.GatewayMode == "" {
				cfg.GatewayMode = config.OpenShellGatewayExternal // the ladder's external rows; managed has its own cases
			}
			got := openShellGather(context.Background(), cfg, host, r, hf)
			if got.res.Verdict != tc.verdict || got.res.Rule != tc.rule {
				t.Fatalf("verdict %s at %s (%s), want %s at %s", got.res.Verdict, got.res.Rule, got.res.Reason, tc.verdict, tc.rule)
			}
			calls := ex.Calls()
			last := ""
			if len(calls) > 0 {
				last = filepath.Base(calls[len(calls)-1].Path)
			}
			if last != tc.lastProg {
				t.Fatalf("the last program started is %q, want %q (gathering must stop at the failing row)", last, tc.lastProg)
			}
			if tc.verdict == sandboxopenshell.VerdictAvailable {
				// The pin is the answer's name and the server it answered from.
				wantPrereq := openShellPrereqDockerGroup
				if strings.Contains(f.info, `"podman"`) {
					wantPrereq = openShellPrereqPodman
				}
				if got.pin.Target != (sandboxopenshell.Target{Gateway: "openshell"}) || got.pin.Server == "" || !strings.Contains(f.status, `"server":"`+got.pin.Server+`"`) || got.prereq != wantPrereq {
					t.Fatalf("pin %+v prereq %s", got.pin, got.prereq)
				}
			}
		})
	}
}

// TestOpenShellProbeRowsCovered keeps the ladder's cases in step with the
// verdict table: every probe row id appears in the gathering ladder.
func TestOpenShellProbeRowsCovered(t *testing.T) {
	var have []int
	for _, st := range openShellSteps {
		have = append(have, openShellRuleIndex(st.rule))
	}
	if !slices.IsSorted(have) {
		t.Fatalf("the gathering ladder is out of the verdict table's order: %v", have)
	}
	for _, want := range []string{"P0", "P1", "P2", "PG", "P5", "P6", "P7", "P8", "P9", "PS"} {
		if !slices.Contains(have, openShellRuleIndex(want)) {
			t.Errorf("no gathering step for %s", want)
		}
	}
}

// TestOpenShellCanaryOnTheLadder (live run O1B-L1, item 1): the probe's
// canary runs Observer's own binary in OpenShell's supervisor image of the
// gateway's version, never the default workload image a fresh install
// does not hold, and never pulls.
func TestOpenShellCanaryOnTheLadder(t *testing.T) {
	f := healthyOpenShell()
	r, ex := f.runner()
	got := openShellGather(context.Background(), config.TerminalSandboxOpenShellConfig{GatewayMode: config.OpenShellGatewayExternal}, sandboxbackend.HostLinux, r, healthyHost())
	if !got.res.Available() || got.facts.CanaryImage != "ghcr.io/nvidia/openshell/supervisor:0.1.6" {
		t.Fatalf("%+v image %q", got.res, got.facts.CanaryImage)
	}
	var docker []string
	for _, c := range ex.Calls() {
		if filepath.Base(c.Path) == "docker" {
			docker = c.Args
		}
	}
	want, err := sandboxopenshell.CanaryArgv(sandboxopenshell.CanaryInput{Image: got.facts.CanaryImage, ObserverBin: "/usr/local/bin/observer", UID: 1000, GID: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(docker, want) || !slices.Contains(docker, "never") || slices.Contains(docker, "nvcr.io/nvidia/base/ubuntu:24.04") {
		t.Fatalf("docker argv %q", docker)
	}
}

// TestOpenShellBoxSocketDir (live run O1B-L1, item 2): the relay clients
// in a box read the launch record from the run's real socket dir only when
// the init named it and the guest path is the init's link to exactly it.
func TestOpenShellBoxSocketDir(t *testing.T) {
	const guest, sockDir = "/tmp/.observer-sandbox-net", "/tmp/observer-sbx-RUN"
	link := func(to string, err error) func(string) (string, error) {
		return func(p string) (string, error) {
			if p != guest {
				t.Fatalf("readlink %s", p)
			}
			return to, err
		}
	}
	cases := []struct {
		name     string
		env      string
		readlink func(string) (string, error)
		want     string
	}{
		{"the init's link to the named dir", sockDir, link(sockDir, nil), sockDir},
		{"nothing named", "", link(sockDir, nil), ""},
		{"a relative dir", "tmp/observer-sbx-RUN", link("tmp/observer-sbx-RUN", nil), ""},
		{"an unclean dir", "/tmp/x/../observer-sbx-RUN", link("/tmp/x/../observer-sbx-RUN", nil), ""},
		{"the guest path itself", guest, link(guest, nil), ""},
		{"the link points elsewhere", sockDir, link("/tmp/observer-sbx-OTHER", nil), ""},
		{"no link (another row's box, or the host)", sockDir, link("", fs.ErrNotExist), ""},
	}
	for _, tc := range cases {
		got, ok := openShellBoxSocketDir(tc.env, guest, tc.readlink)
		if got != tc.want || ok != (tc.want != "") {
			t.Errorf("%s: %q %v, want %q", tc.name, got, ok, tc.want)
		}
	}
	env := openShellWithSockDirEnv([]string{"A=1", openShellEnvSocketDir + "=/tmp/planted", openShellSharedSockDirEnv + "=/tmp/shared", "B=2"}, sockDir)
	if !slices.Equal(env, []string{"A=1", "B=2", openShellEnvSocketDir + "=" + sockDir}) {
		t.Fatalf("env %q", env)
	}
}

// TestOpenShellProcessDeclaration: every program the driver starts goes
// through the runner under the component's id, and the component's catalog
// row declares it (the Surface.Processes rule,
// tests/invariant/process_declaration_test.go), on a full ladder, a reap
// and a pinned delete.
func TestOpenShellProcessDeclaration(t *testing.T) {
	f := healthyOpenShell()
	r, ex := f.runner()
	_ = openShellGather(context.Background(), config.TerminalSandboxOpenShellConfig{GatewayMode: config.OpenShellGatewayExternal}, sandboxbackend.HostLinux, r, healthyHost())
	pf := openShellPlanFile{Target: sandboxopenshell.Target{Gateway: "openshell"}, Server: openShellTestServer, Name: sandboxopenshell.SandboxName("run-0000-aaaa"), GatewayVersion: "0.1.6"}
	_ = openShellDeleteBox(context.Background(), r, pf)
	c, ok := components.Get(openShellComponentID)
	if !ok {
		t.Fatal("no catalog row")
	}
	calls := ex.Calls()
	if len(calls) < 6 {
		t.Fatalf("only %d programs ran", len(calls))
	}
	for _, p := range calls {
		if p.Component != openShellComponentID {
			t.Errorf("%s ran under component %q", p.Path, p.Component)
		}
		if !extrun.DeclaresProcess(c.Surface.Processes, p.Path) {
			t.Errorf("%s is not declared by %s", p.Path, openShellComponentID)
		}
		for _, kv := range p.Env {
			k, _, _ := strings.Cut(kv, "=")
			if strings.Contains(strings.ToUpper(k), "KEY") || strings.Contains(strings.ToUpper(k), "TOKEN") {
				t.Errorf("%s got the secret-shaped variable %s", p.Path, k)
			}
		}
	}
}

// TestOpenShellPrereqTable: one case per row of decision D4's table.
func TestOpenShellPrereqTable(t *testing.T) {
	cases := []struct {
		driver string
		group  bool
		want   openShellPrereq
	}{
		{"docker", true, openShellPrereqDockerGroup},
		{"docker", false, openShellPrereqDockerNoGroup},
		{"podman", false, openShellPrereqPodman},
		{"", true, openShellPrereqUnknown},
	}
	if len(cases) != len(openShellPrereqRows)+1 {
		t.Fatalf("%d cases for %d rows plus the fallback", len(cases), len(openShellPrereqRows))
	}
	for _, tc := range cases {
		if got := openShellPrereqFor(tc.driver, tc.group); got != tc.want {
			t.Errorf("%s/%v: %s, want %s", tc.driver, tc.group, got, tc.want)
		}
	}
	if !strings.Contains(openShellPrereqHint(openShellPrereqDockerGroup), "root-equivalent") {
		t.Error("the docker group is not said to be root-equivalent")
	}
}

// writeOpenShellRun writes a run dir with a plan pinned to target.
func writeOpenShellRun(t *testing.T, stateDir, runID string, target sandboxopenshell.Target, age time.Duration) openShellPlanFile {
	t.Helper()
	dir := openShellRunDir(stateDir, runID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	pf := openShellPlanFile{Version: openShellPlanVersion, RunID: runID, Target: target, Server: openShellTestServer, GatewayVersion: "0.1.6", Name: sandboxopenshell.SandboxName(runID)}
	if err := openShellWriteExcl(filepath.Join(dir, "plan.json"), openShellJSON(t, pf)); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-age)
	if err := os.Chtimes(filepath.Join(dir, "plan.json"), old, old); err != nil {
		t.Fatal(err)
	}
	return pf
}

// TestOpenShellReaperPinsTheGateway (audit finding O1A-A9): the user
// switched the CLI's active gateway after the create. The active gateway
// answers the exact not-found text for any box; the box still runs on the
// pinned one. Every reaper call names the pinned gateway, so the box is
// never read gone and its run dir stays.
func TestOpenShellReaperPinsTheGateway(t *testing.T) {
	if !openShellLinuxStateIO() {
		t.Skip("the row keeps state on Linux only")
	}
	stateDir := t.TempDir()
	pinned := sandboxopenshell.Target{Gateway: "gw-a"}
	pf := writeOpenShellRun(t, stateDir, "run-switched-0001", pinned, time.Hour)
	f := healthyOpenShell()
	f.answer = func(prog string, args []string) (extrun.ExecFacts, bool) {
		if !slices.Equal(args[:2], []string{"-g", "gw-a"}) {
			// The switched-to active gateway: every box is "not found".
			return extrun.ExecFacts{ExitCode: 1, Stderr: []byte(openShellNotFoundText), PeakChildren: -1}, true
		}
		if slices.Contains(args, "status") {
			return extrun.ExecFacts{Stdout: []byte(healthyOpenShell().status), PeakChildren: -1}, true
		}
		if slices.Contains(args, "get") {
			return extrun.ExecFacts{Stdout: []byte(`{"name":"` + pf.Name + `"}`), PeakChildren: -1}, true
		}
		if slices.Contains(args, "list") {
			return extrun.ExecFacts{Stdout: []byte(pf.Name + "\n"), PeakChildren: -1}, true
		}
		return extrun.ExecFacts{PeakChildren: -1}, true
	}
	r, ex := f.runner()
	res := openShellSweep(context.Background(), r, stateDir, "0123456789abcdef", func(string) bool { return false }, time.Now)
	if len(res.Reaped) != 0 || !slices.Contains(res.Kept, pf.Name) {
		t.Fatalf("reaped %v kept %v: a box on the pinned gateway was read gone", res.Reaped, res.Kept)
	}
	for _, p := range ex.Calls() {
		if !slices.Equal(p.Args[:2], []string{"-g", "gw-a"}) {
			t.Errorf("a reaper call does not name the pinned gateway: %v", p.Args)
		}
	}
	if _, err := os.Stat(openShellRunDir(stateDir, "run-switched-0001")); err != nil {
		t.Fatalf("the run dir went with the box still present: %v", err)
	}
}

// TestOpenShellReaperRows: one case per reaper row: a held run is left; a
// young unheld run is left (its helper may not have started); an abandoned
// run whose box the pinned gateway shows gone is reaped with its run dir;
// an unclear answer keeps it; an unclaimed box under the install label is
// deleted; a failed list knows nothing.
func TestOpenShellReaperRows(t *testing.T) {
	if !openShellLinuxStateIO() {
		t.Skip("the row keeps state on Linux only")
	}
	gw := sandboxopenshell.Target{Gateway: "openshell"}
	cases := []struct {
		name    string
		held    bool
		age     time.Duration
		get     extrun.ExecFacts
		list    extrun.ExecFacts
		live    bool
		reaped  []string
		kept    bool
		dirGone bool
	}{
		{name: "held by its helper", held: true, age: time.Hour, live: true},
		{name: "too young to judge", age: time.Second, live: true},
		{name: "abandoned and gone", age: time.Hour, get: extrun.ExecFacts{ExitCode: 1, Stderr: []byte(openShellNotFoundText)}, reaped: []string{"own"}, dirGone: true},
		{name: "abandoned, unclear answer", age: time.Hour, get: extrun.ExecFacts{ExitCode: 1, Stderr: []byte("permission denied")}, kept: true},
		{
			name: "an unclaimed box under the install label", age: time.Second, live: true,
			list: extrun.ExecFacts{Stdout: []byte("sbo-aaaaaaaaaaaaaaa\nnot-ours\n")},
			get:  extrun.ExecFacts{ExitCode: 1, Stderr: []byte(openShellNotFoundText)}, reaped: []string{"sbo-aaaaaaaaaaaaaaa"},
		},
		{name: "a failed list", age: time.Second, live: true, list: extrun.ExecFacts{ExitCode: 1, Stderr: []byte("unavailable")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stateDir := t.TempDir()
			pf := writeOpenShellRun(t, stateDir, "run-reaper-0001", gw, tc.age)
			f := healthyOpenShell()
			f.answer = func(prog string, args []string) (extrun.ExecFacts, bool) {
				switch {
				case slices.Contains(args, "status"):
					return extrun.ExecFacts{Stdout: []byte(f.status), PeakChildren: -1}, true
				case slices.Contains(args, "get"):
					out := tc.get
					out.PeakChildren = -1
					return out, true
				case slices.Contains(args, "list"):
					out := tc.list
					out.PeakChildren = -1
					return out, true
				}
				return extrun.ExecFacts{PeakChildren: -1}, true
			}
			r, _ := f.runner()
			res := openShellSweep(context.Background(), r, stateDir, "0123456789abcdef", func(string) bool { return tc.held }, time.Now)
			want := make([]string, 0, len(tc.reaped))
			for _, n := range tc.reaped {
				if n == "own" {
					n = pf.Name
				}
				want = append(want, n)
			}
			if !slices.Equal(res.Reaped, want) || slices.Contains(res.Live, pf.Name) != tc.live || slices.Contains(res.Kept, pf.Name) != tc.kept {
				t.Fatalf("live %v reaped %v kept %v", res.Live, res.Reaped, res.Kept)
			}
			_, err := os.Stat(openShellRunDir(stateDir, "run-reaper-0001"))
			if gone := errors.Is(err, fs.ErrNotExist); gone != tc.dirGone {
				t.Fatalf("run dir gone %v, want %v", gone, tc.dirGone)
			}
		})
	}
}

// openShellLinuxStateIO reports whether the row's state files are read on
// this OS (openShellReadOwned is Linux-only).
func openShellLinuxStateIO() bool { return runtime.GOOS == "linux" }

// openShellJSON marshals v or fails the test.
func openShellJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestOpenShellComponentIsOptIn (lane O1A, kept by lane O1B when the
// driver replaced the stand-in opt-in rule): the component is off on an
// install with no [components] block and in every distro's default, and on
// only when a block names it with the sandbox module active
// (sandboxDriverOptIn over the registered driver).
func TestOpenShellComponentIsOptIn(t *testing.T) {
	requireUnstampedBuild(t)
	if _, ok := sandboxDriverRegs[sandboxbackend.BackendOpenShell]; !ok {
		t.Fatal("the openshell driver is not registered")
	}
	cases := []struct {
		name string
		sec  config.ComponentsConfig
		want bool
	}{
		{"no block", config.ComponentsConfig{}, false},
		{"developer distro", config.ComponentsConfig{Distro: "developer"}, false},
		{"managed distro", config.ComponentsConfig{Distro: "managed"}, false},
		{"full distro", config.ComponentsConfig{Distro: "full"}, false},
		{"another component added", config.ComponentsConfig{Add: []string{"terminals.sandbox.oci"}}, false},
		{"added by name", config.ComponentsConfig{Add: []string{openShellComponentID}}, true},
		{"module and driver removed", config.ComponentsConfig{Remove: []string{sandboxComponent, openShellComponentID}}, false},
		{"terminals removed", config.ComponentsConfig{Remove: []string{"terminals", sandboxComponent}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snap := componentstate.Resolve(tc.sec, fullNodeIDs())
			if got := moduleRuleActive(snap, openShellComponentID); got != tc.want {
				t.Fatalf("active = %v, want %v (issues %v)", got, tc.want, snap.Issues)
			}
		})
	}
}

// TestOpenShellEnvCodec: the box environment rides in a file, not on the
// create argv; HOME and malformed entries never go through it; a value
// with a newline survives.
func TestOpenShellEnvCodec(t *testing.T) {
	in := []string{"TERM=xterm", "HOME=/root", "MULTI=a\nb", "NOEQ", "=x", "OBSERVER_SANDBOX=1"}
	got := openShellDecodeEnv(openShellEncodeEnv(in))
	want := []string{"TERM=xterm", "MULTI=a\nb", "OBSERVER_SANDBOX=1"}
	if !slices.Equal(got, want) {
		t.Fatalf("%q, want %q", got, want)
	}
	box := openShellBoxEnv([]string{"HOME=/home/dev", "XDG_RUNTIME_DIR=/run/user/1000", "TERM=xterm", sandboxEnvMarker + "=0"})
	if slices.Contains(box, "HOME=/home/dev") || slices.Contains(box, "XDG_RUNTIME_DIR=/run/user/1000") || !slices.Contains(box, sandboxEnvMarker+"=1") || slices.Contains(box, sandboxEnvMarker+"=0") {
		t.Fatalf("box env %q", box)
	}
}

// TestOpenShellLifecycleVerdicts: resize, signal and stop belong to the
// run's terminal (the CLI is the helper's child and forwards SIGWINCH; the
// helper forwards signals and deletes the box); copy and checkpoint are
// not offered.
func TestOpenShellLifecycleVerdicts(t *testing.T) {
	d := &openShellDriver{}
	ctx := context.Background()
	run := termsvc.SandboxRun{ID: "RUN"}
	check := func(name string, got termsvc.LifecycleResult, err error, want termsvc.LifecycleVerdict) {
		if err != nil || got.Verdict != want || got.Detail == "" {
			t.Errorf("%s: %+v %v, want %s", name, got, err, want)
		}
	}
	r, err := d.Resize(ctx, run, 40, 100)
	check("resize", r, err, termsvc.VerdictPTYOwned)
	r, err = d.Signal(ctx, run, "TERM")
	check("signal", r, err, termsvc.VerdictPTYOwned)
	r, err = d.Stop(ctx, run, time.Second)
	check("stop", r, err, termsvc.VerdictPTYOwned)
	r, err = d.Copy(ctx, termsvc.CopyRequest{Run: run})
	check("copy", r, err, termsvc.VerdictNotSupported)
	r, err = d.Checkpoint(ctx, run)
	check("checkpoint", r, err, termsvc.VerdictNotSupported)
}

// TestOpenShellExtraBindsRefused (audit finding O1B-A12): the row's mount
// scope has no root for extra binds, so a launch that sets any is refused
// naming the key (never run with them silently absent); one case per row
// of the table, plus none set.
func TestOpenShellExtraBindsRefused(t *testing.T) {
	cases := []struct {
		name string
		cfg  config.TerminalSandboxConfig
		org  []string
		want string
	}{
		{name: "none set"},
		{name: "an org write bind", cfg: config.TerminalSandboxConfig{ExtraRWBinds: []string{"/srv/shared"}}, org: []string{"/srv/shared"}, want: "organization's write binds"},
		{name: "a local write bind", cfg: config.TerminalSandboxConfig{ExtraRWBinds: []string{"/srv/mine"}}, want: "extra_rw_binds"},
		{name: "a read-only bind", cfg: config.TerminalSandboxConfig{ExtraROBinds: []string{"/opt/data"}}, want: "extra_ro_binds"},
	}
	if len(cases) != len(openShellExtraBindRows)+1 {
		t.Fatalf("%d cases for %d rows plus none", len(cases), len(openShellExtraBindRows))
	}
	for _, tc := range cases {
		err := openShellExtraBindsRefusal(tc.cfg, tc.org)
		if tc.want == "" {
			if err != nil {
				t.Errorf("%s: %v", tc.name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want a refusal naming %q", tc.name, err, tc.want)
		}
	}
}

// TestOpenShellWorkspaceSources (audit finding O1B-R3): the row launches
// the live workspace only; a managed source is refused by name before any
// workspace is prepared. One case per source, plus the empty default.
func TestOpenShellWorkspaceSources(t *testing.T) {
	cases := []struct {
		source  string
		refused bool
	}{
		{source: ""},
		{source: "live"},
		{source: "clone-local", refused: true},
		{source: "clone-remote", refused: true},
		{source: "worktree", refused: true},
	}
	for _, tc := range cases {
		err := openShellWorkspaceSourceRefusal(tc.source)
		if !tc.refused {
			if err != nil {
				t.Errorf("%q: %v", tc.source, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), "the "+tc.source+" source") || !strings.Contains(err.Error(), "live") {
			t.Errorf("%q: %v, want a refusal naming the source", tc.source, err)
		}
	}
}

// TestOpenShellMasksAreTheRuntimeMasks (audit finding O1B-R1): the mask
// rows the bind builder checks are exactly r.maskPaths(), so a mask source
// added there without a row here fails.
func TestOpenShellMasksAreTheRuntimeMasks(t *testing.T) {
	r := &sandboxRuntime{cfg: config.TerminalSandboxConfig{MaskPaths: []string{"/srv/secrets", " ", "/home/dev/src/app/.env"}}}
	foreign, err := foreignMountRoots()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, m := range openShellMasks(r.cfg, foreign) {
		got = append(got, m.path)
	}
	want, err := r.maskPaths()
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(slices.Compact(got), want) {
		t.Fatalf("openshell masks %v, runtime masks %v", got, want)
	}
}

// TestOpenShellHomeNote (audit finding O1B-A12): the note's home field
// follows the planner's rule for every home_mode.
func TestOpenShellHomeNote(t *testing.T) {
	for mode, want := range map[string]string{"": "shared_tmpfs", sandboxopenshell.HomeTmpfs: "shared_tmpfs", sandboxopenshell.HomeReadonly: "readonly_bind"} {
		if got := openShellHomeNote(mode); got != want {
			t.Errorf("home_mode %q: %s, want %s", mode, got, want)
		}
	}
}

// TestOpenShellDirectChild: the gateways file's temporary file is renamed
// only when it is a direct child of the state dir (gosec G703, tracker
// F-022). One case per shape.
func TestOpenShellDirectChild(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		dir, p string
		want   bool
	}{
		{"/s/openshell", "/s/openshell/.gateways-123", true},
		{"/s/openshell/", "/s/openshell/.gateways-123", true},
		{"/s/openshell", "/s/openshell/sub/.gateways-123", false},
		{"/s/openshell", "/s/other/.gateways-123", false},
		{"/s/openshell", "/s/openshell/../x", false},
		{"/s/openshell", "/s/openshell", false},
		{"/", "/", false},
	} {
		if got := openShellDirectChild(tc.dir, tc.p); got != tc.want {
			t.Errorf("openShellDirectChild(%q, %q) = %v", tc.dir, tc.p, got)
		}
	}
}

// TestOpenShellImagesFrom: row P8i's configured images come from the
// driver's own table of the gateway's config; anything unread is zero (the
// version's defaults apply). One case per shape.
func TestOpenShellImagesFrom(t *testing.T) {
	t.Parallel()
	both := "[openshell.drivers.docker]\nsupervisor_image = \"m/sup@sha256:aa\"\nsandbox_runtime_image = \"m/sbx:0.1.6\"\n"
	for _, tc := range []struct {
		name, body, driver string
		err                error
		want               sandboxopenshell.RuntimeImages
	}{
		{"both keys", both, "docker", nil, sandboxopenshell.RuntimeImages{Supervisor: "m/sup@sha256:aa", Sandbox: "m/sbx:0.1.6"}},
		{"another driver's table", both, "podman", nil, sandboxopenshell.RuntimeImages{}},
		{"no keys", "[openshell.drivers.docker]\nenable_bind_mounts = true\n", "docker", nil, sandboxopenshell.RuntimeImages{}},
		{"no file", "", "docker", fs.ErrNotExist, sandboxopenshell.RuntimeImages{}},
		{"not toml", "[[[", "docker", nil, sandboxopenshell.RuntimeImages{}},
		{"driver unknown", both, "", nil, sandboxopenshell.RuntimeImages{}},
		// FU7-A10: supervisor_bin replaces the sandbox runtime image.
		{"supervisor_bin set", "[openshell.drivers.docker]\nsupervisor_bin = \"/usr/lib/openshell/openshell-sandbox\"\n", "docker", nil, sandboxopenshell.RuntimeImages{SandboxFromBin: true}},
	} {
		if got := openShellImagesFrom([]byte(tc.body), tc.err, tc.driver); got != tc.want {
			t.Errorf("%s: got %+v", tc.name, got)
		}
	}
}

// TestOpenShellTrustedProgramNotFound (audit finding FU7-A5): a trusted
// program that does not resolve is refused as not found by the seam
// itself, resolved once, never handed to the runner by its spec (which
// would resolve it again, unchecked).
func TestOpenShellTrustedProgramNotFound(t *testing.T) {
	t.Parallel()
	f := healthyOpenShell()
	f.cliMissing = true
	r, ex := f.runner()
	inner := r.Resolve
	calls := 0
	r.Resolve = func(s integration.BinaryResolveSpec) toolresolve.Resolution {
		calls++
		return inner(s)
	}
	res := openShellRun(context.Background(), r, openShellCLISpec, []string{"--version"})
	if res.Outcome != extrun.OutcomeRefused || res.Reason != extrun.RefuseNotFound || !strings.Contains(res.Detail, "not installed") {
		t.Fatalf("got %+v", res)
	}
	if calls != 1 || len(ex.Calls()) != 0 {
		t.Fatalf("resolved %d times, ran %d programs", calls, len(ex.Calls()))
	}
	if _, why, found := openShellProgram(r, openShellCLISpec); found || why != "" {
		t.Fatalf("found %v why %q", found, why)
	}
}
