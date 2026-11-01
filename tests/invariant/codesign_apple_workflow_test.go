package invariant

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// codesign_apple_workflow_test.go pins the macOS half of the release
// pipeline's signing wiring (macsign lane, plan
// docs/plans/code-signing-phase-2-plan-2026-10-21.md sections 3.3 and 3.5):
// the switch comes only from vars; the Apple secrets reach only the macOS
// signing steps, only when the switch is on and the ref is a v* tag; rcodesign
// is pinned by version and sha256 and installed only when the switch is on;
// every darwin binary the release ships passes through the hook before
// upload.

const rcodesignInstallStep = "Install rcodesign (pinned, retried)"

// appleSecretNames are the only secrets the release's signing jobs read.
var appleSecretNames = []string{
	"APPLE_DEVELOPER_ID_P12_BASE64",
	"APPLE_DEVELOPER_ID_P12_PASSWORD",
	"APPLE_NOTARY_API_KEY_JSON",
	"APPLE_NOTARY_KEY_P8",
}

// appleSecretEnv is the one accepted spelling of an Apple secret in a step's
// env: empty unless the switch is on and the ref is a v* tag. It returns ""
// for a name that is not an Apple secret.
func appleSecretEnv(name string) string {
	if !contains(appleSecretNames, name) {
		return ""
	}
	return "${{ vars.OBSERVER_SIGN_APPLE == '1' && startsWith(github.ref, 'refs/tags/v') && secrets." + name + " || '' }}"
}

// appleStepEnv is the exact env of every macOS signing step.
func appleStepEnv() map[string]string {
	env := map[string]string{
		"OBSERVER_SIGN_APPLE":    "${{ vars.OBSERVER_SIGN_APPLE }}",
		"APPLE_TEAM_ID":          "${{ vars.APPLE_TEAM_ID }}",
		"APPLE_NOTARY_ISSUER_ID": "${{ vars.APPLE_NOTARY_ISSUER_ID }}",
		"APPLE_NOTARY_KEY_ID":    "${{ vars.APPLE_NOTARY_KEY_ID }}",
		"RCODESIGN":              "${{ runner.temp }}/rcodesign/rcodesign",
	}
	for _, n := range appleSecretNames {
		env[n] = appleSecretEnv(n)
	}
	return env
}

// isMacOSSigningStep reports whether a step runs the darwin hook.
func isMacOSSigningStep(s workflowStep) bool {
	return strings.Contains(s.Run, "scripts/codesign.sh darwin ")
}

// TestCodesignAppleInputsReachOnlyMacOSSteps: every macOS signing step runs
// in a signing job on the darwin legs, carries exactly the Apple env (switch
// and identifiers from vars, secrets gated), sources the inputs script before
// its first hook call; no other step anywhere names an Apple input; nothing
// writes an Apple input to a runner file.
func TestCodesignAppleInputsReachOnlyMacOSSteps(t *testing.T) {
	doc, raw := loadWorkflow(t)
	want := appleStepEnv()
	steps := 0
	for name, job := range doc.Jobs {
		for _, s := range job.Steps {
			if !isMacOSSigningStep(s) {
				for k, v := range s.Env {
					if strings.HasPrefix(k, "APPLE_") || strings.Contains(v, "APPLE_") {
						t.Errorf("job %s step %q is not a macOS signing step but receives %s", name, s.Name, k)
					}
				}
				if strings.Contains(s.Run, "codesign-apple-inputs.sh") {
					t.Errorf("job %s step %q sources the Apple inputs but signs no macOS binary", name, s.Name)
				}
				continue
			}
			steps++
			if !contains(codesignJobs, name) {
				t.Errorf("job %s signs a macOS binary but is not a signing job", name)
			}
			if s.If != "matrix.goos == 'darwin'" {
				t.Errorf("job %s step %q if = %q, want matrix.goos == 'darwin' (it must run when off too, as a logged no-op)", name, s.Name, s.If)
			}
			if len(s.Env) != len(want) {
				t.Errorf("job %s step %q env has %d keys, want exactly %d (%v)", name, s.Name, len(s.Env), len(want), s.Env)
			}
			for k, v := range want {
				if s.Env[k] != v {
					t.Errorf("job %s step %q env %s = %q, want %q", name, s.Name, k, s.Env[k], v)
				}
			}
			src := normalizeShell(s.Run)
			source := strings.Index(src, "\n. scripts/codesign-apple-inputs.sh\n")
			first := strings.Index(src, "scripts/codesign.sh darwin ")
			if !strings.HasPrefix(src, "set -euo pipefail\n") || source < 0 || source > first {
				t.Errorf("job %s step %q does not start with set -euo pipefail and source scripts/codesign-apple-inputs.sh before the hook:\n%s", name, s.Name, s.Run)
			}
			if strings.Contains(s.Run, "secrets.") || strings.Contains(s.Run, "${{ vars.") {
				t.Errorf("job %s step %q expands a secret or variable in its script; they come only through env", name, s.Name)
			}
		}
	}
	if steps < 2 {
		t.Errorf("found %d macOS signing steps, want at least 2 (build, edition_build)", steps)
	}
	for _, m := range regexp.MustCompile(`secrets\.([A-Z0-9_]+)`).FindAllStringSubmatch(raw, -1) {
		if strings.HasPrefix(m[1], "APPLE_") && !contains(appleSecretNames, m[1]) {
			t.Errorf("unknown Apple secret %s", m[0])
		}
	}
	for _, line := range strings.Split(raw, "\n") {
		if strings.Contains(line, "APPLE_") && (strings.Contains(line, "GITHUB_ENV") || strings.Contains(line, "GITHUB_OUTPUT") || strings.Contains(line, "GITHUB_STEP_SUMMARY")) {
			t.Errorf("an Apple input is written to a runner file: %s", strings.TrimSpace(line))
		}
	}
	if strings.Contains(raw, "vars.APPLE_DEVELOPER_ID") || strings.Contains(raw, "vars.APPLE_NOTARY_API_KEY_JSON") || strings.Contains(raw, "vars.APPLE_NOTARY_KEY_P8") {
		t.Error("an Apple secret is read from vars; the certificate, its password and the key are secrets")
	}
	if strings.Contains(raw, "secrets.APPLE_TEAM_ID") || strings.Contains(raw, "secrets.APPLE_NOTARY_ISSUER_ID") || strings.Contains(raw, "secrets.APPLE_NOTARY_KEY_ID") {
		t.Error("an Apple identifier is read from secrets; the runbook names it an environment variable")
	}
}

// TestCodesignEveryDarwinBinaryIsSigned: in the build job every binary built
// for the matrix's own OS goes through the darwin hook (with the matrix ext
// dropped, as on darwin it is empty), and in both jobs the rcodesign install
// precedes the macOS signing step, which precedes every upload.
func TestCodesignEveryDarwinBinaryIsSigned(t *testing.T) {
	doc, _ := loadWorkflow(t)
	outFlag := regexp.MustCompile(`(?m)-o (.+?)\s*\\?$`)
	var signed string
	built := map[string]bool{}
	for _, s := range doc.Jobs["build"].Steps {
		if isMacOSSigningStep(s) {
			signed += s.Run
		}
		if !strings.Contains(s.Run, "go build") || s.Env["GOOS"] != "${{ matrix.goos }}" {
			continue
		}
		for _, m := range outFlag.FindAllStringSubmatch(s.Run, -1) {
			built[strings.TrimSuffix(m[1], "${{ matrix.ext }}")] = true
		}
	}
	if len(built) < 2 {
		t.Fatalf("found %d matrix-OS binaries in build (%v), want observer and observer-org", len(built), built)
	}
	for path := range built {
		if !strings.Contains(signed, `scripts/codesign.sh darwin "`+path+`"`) {
			t.Errorf("build ships %s on the darwin legs but the darwin hook does not sign it", path)
		}
	}
	for _, name := range []string{"build", "edition_build"} {
		install, sign, upload := -1, -1, -1
		for i, s := range doc.Jobs[name].Steps {
			switch {
			case s.Name == rcodesignInstallStep:
				install = i
			case isMacOSSigningStep(s):
				sign = i
			case strings.HasPrefix(s.Uses, "actions/upload-artifact") && upload < 0:
				upload = i
			}
		}
		if install < 0 || sign < 0 || upload < 0 || !(install < sign && sign < upload) {
			t.Errorf("%s order: rcodesign install=%d macOS sign=%d first upload=%d, want install < sign < upload", name, install, sign, upload)
		}
	}
	if !strings.Contains(jobText(t, doc.Jobs["edition_build"]), `scripts/codesign.sh darwin "edition/observer-${{ matrix.distro }}-${{ matrix.goos }}-${{ matrix.goarch }}"`) {
		t.Error("edition_build does not sign the edition binary on the darwin legs")
	}
}

func rcodesignInstallSteps(t *testing.T, doc workflowDoc) map[string]workflowStep {
	t.Helper()
	steps := map[string]workflowStep{}
	for jobName, job := range doc.Jobs {
		for _, s := range job.Steps {
			if s.Name == rcodesignInstallStep {
				if _, dup := steps[jobName]; dup {
					t.Errorf("job %s carries two %q steps", jobName, rcodesignInstallStep)
				}
				steps[jobName] = s
			}
		}
	}
	return steps
}

// TestCodesignRcodesignIsPinned: rcodesign is pinned by version and sha256 in
// the top-level env, and every job that signs a macOS binary installs it with
// one identical, retried, checksum-verified script that runs only when the
// switch is on, on the darwin legs.
func TestCodesignRcodesignIsPinned(t *testing.T) {
	doc, raw := loadWorkflow(t)
	var env workflowEnvDoc
	if err := yaml.Unmarshal([]byte(raw), &env); err != nil {
		t.Fatalf("parse top-level env: %v", err)
	}
	if !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(env.Env["RCODESIGN_VERSION"]) {
		t.Errorf("env.RCODESIGN_VERSION = %q, want a pinned apple-codesign release", env.Env["RCODESIGN_VERSION"])
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(env.Env["RCODESIGN_SHA256"]) {
		t.Errorf("env.RCODESIGN_SHA256 = %q, want the 64-hex sha256 of the x86_64-unknown-linux-musl tarball", env.Env["RCODESIGN_SHA256"])
	}
	steps := rcodesignInstallSteps(t, doc)
	ref := steps["build"].Run
	for name, job := range doc.Jobs {
		signs := false
		for _, s := range job.Steps {
			signs = signs || isMacOSSigningStep(s)
		}
		s, ok := steps[name]
		if signs != ok {
			t.Errorf("job %s: signs a macOS binary = %v, installs rcodesign = %v", name, signs, ok)
		}
		if !ok {
			continue
		}
		if s.Run != ref {
			t.Errorf("%s's rcodesign install differs from build's; they must be byte-identical", name)
		}
		if s.If != "vars.OBSERVER_SIGN_APPLE == '1' && matrix.goos == 'darwin'" {
			t.Errorf("%s installs rcodesign with if %q, want only when the switch is on, on the darwin legs", name, s.If)
		}
		if len(s.Env) != 0 {
			t.Errorf("%s's rcodesign install receives env %v; it needs none", name, s.Env)
		}
	}
	for _, want := range []string{
		"set -euo pipefail",
		"--retry 8", "--retry-all-errors",
		"https://github.com/indygreg/apple-platform-rs/releases/download/apple-codesign%2F${RCODESIGN_VERSION}",
		`name="apple-codesign-${RCODESIGN_VERSION}-x86_64-unknown-linux-musl"`,
		`echo "${RCODESIGN_SHA256}  ${RUNNER_TEMP}/rcodesign/${name}.tar.gz" | sha256sum -c -`,
	} {
		if !strings.Contains(ref, want) {
			t.Errorf("the rcodesign install script lacks %q", want)
		}
	}
	// sha256sum -c must run before tar touches the download.
	if strings.Index(ref, "sha256sum -c") > strings.Index(ref, "tar -xzf") {
		t.Error("the rcodesign install unpacks the tarball before checking its sha256")
	}
}

// TestCodesignRcodesignInstallExecutes runs the install script against a
// file:// download base: a tarball matching the pinned sha256 leaves an
// executable rcodesign where the signing steps look for it; a mismatching
// one is refused and nothing is unpacked.
func TestCodesignRcodesignInstallExecutes(t *testing.T) {
	for _, tool := range []string{"bash", "curl", "sha256sum", "tar"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not available", tool)
		}
	}
	if help, _ := exec.Command("curl", "--help", "all").CombinedOutput(); !strings.Contains(string(help), "--retry-all-errors") {
		t.Skip("local curl predates --retry-all-errors; the script is executed on the release runner")
	}
	doc, _ := loadWorkflow(t)
	script := rcodesignInstallSteps(t, doc)["build"].Run
	if script == "" {
		t.Fatal("build has no rcodesign install script")
	}
	const version = "0.0.1"
	name := "apple-codesign-" + version + "-x86_64-unknown-linux-musl"
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range []struct{ path, body string }{
		{name + "/COPYING", "license\n"},
		{name + "/rcodesign", "#!/bin/sh\necho 'rcodesign 0.0.1'\n"},
	} {
		if err := tw.WriteHeader(&tar.Header{Name: f.path, Mode: 0o644, Size: int64(len(f.body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(f.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(buf.Bytes())
	run := func(t *testing.T, pinned string) (string, string, error) {
		t.Helper()
		dl := t.TempDir()
		if err := os.WriteFile(filepath.Join(dl, name+".tar.gz"), buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		tmp := t.TempDir()
		cmd := exec.Command("bash", "-c", script)
		cmd.Env = append(os.Environ(),
			"RUNNER_TEMP="+tmp,
			"RCODESIGN_VERSION="+version,
			"RCODESIGN_SHA256="+pinned,
			"RCODESIGN_DOWNLOAD_BASE=file://"+dl,
		)
		out, err := cmd.CombinedOutput()
		return string(out), filepath.Join(tmp, "rcodesign", "rcodesign"), err
	}
	t.Run("pinned sha matches", func(t *testing.T) {
		out, path, err := run(t, hex.EncodeToString(sum[:]))
		if err != nil {
			t.Fatalf("install failed: %v\n%s", err, out)
		}
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("rcodesign is not at %s: %v", path, err)
		}
		if fi.Mode().Perm()&0o111 == 0 {
			t.Errorf("rcodesign is not executable (%v)", fi.Mode())
		}
		if !strings.Contains(out, "rcodesign 0.0.1") {
			t.Errorf("the install did not run rcodesign --version:\n%s", out)
		}
		if _, err := os.Stat(filepath.Join(filepath.Dir(path), name+".tar.gz")); err == nil {
			t.Error("the tarball is left behind")
		}
	})
	t.Run("pinned sha mismatch is refused", func(t *testing.T) {
		out, path, err := run(t, strings.Repeat("0", 64))
		if err == nil {
			t.Fatalf("install succeeded with a wrong checksum:\n%s", out)
		}
		if _, err := os.Stat(path); err == nil {
			t.Error("rcodesign was unpacked despite the wrong checksum")
		}
	})
}
