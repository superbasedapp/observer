package invariant

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// codesign_test.go pins the Windows Authenticode wiring of the release
// pipeline (T-961, plan docs/plans/code-signing-phase-2-plan-2026-10-21.md
// sections 3.1, 3.3 and 3.5): signing is OFF unless the release-signing
// environment's OBSERVER_SIGN_AUTHENTICODE variable is 1; only the
// signing jobs run in that environment and hold id-token: write; the Azure
// login is GitHub OIDC (no stored secret); the Key Vault token never reaches
// a command line, an env map or the log; the timestamp is mandatory; and
// every signature is verified before upload. The hermetic test at the end
// runs scripts/codesign.sh against fake jsign / osslsigncode binaries. The
// macOS half is pinned in codesign_macos_test.go (hook) and
// codesign_apple_workflow_test.go (workflow).

// codesignJobs are the jobs that sign, and therefore the only ones that may
// run in the release-signing environment or log in to Azure.
// build_win32 and edition_build_win32 are the win32 legs of build and
// edition_build (the same steps through a YAML alias, split out so only they
// wait on the MXC files job, SBX-P6 audit item 7); they sign the Windows
// binaries.
var codesignJobs = []string{"build", "build_win32", "edition_build", "edition_build_win32", "windows_setup"}

const (
	codesignEnvironment = "release-signing"
	jsignInstallStep    = "Install jsign (pinned, retried)"
	// tokenFetch is the one way a signing step obtains the Key Vault token:
	// into a shell variable, masked before anything else runs, exported only
	// to that step's child processes (jsign reads it via --storepass env:).
	tokenFetch = `if [ "${OBSERVER_SIGN_AUTHENTICODE:-}" = "1" ]; then
  AZURE_SIGNING_TOKEN="$(az account get-access-token --resource https://vault.azure.net --query accessToken -o tsv)"
  echo "::add-mask::${AZURE_SIGNING_TOKEN}"
  export AZURE_SIGNING_TOKEN
fi`
)

// signingEnv is the env a Windows signing step must carry: the switch and
// the identifiers, all from environment variables, never from secrets.
var signingEnv = map[string]string{
	"OBSERVER_SIGN_AUTHENTICODE": "${{ vars.OBSERVER_SIGN_AUTHENTICODE }}",
	"AZURE_SIGNING_VAULT":        "${{ vars.AZURE_SIGNING_VAULT }}",
	"AZURE_SIGNING_CERT_NAME":    "${{ vars.AZURE_SIGNING_CERT_NAME }}",
	"JSIGN_JAR":                  "${{ runner.temp }}/jsign/jsign.jar",
}

// normalizeShell strips leading indentation so a snippet can be matched
// regardless of the if-block depth it sits at.
func normalizeShell(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSpace(l)
	}
	return strings.Join(lines, "\n")
}

// isWindowsSigningStep reports whether a step signs (not merely verifies)
// a Windows file through the hook, directly or through makensis.
func isWindowsSigningStep(s workflowStep) bool {
	return strings.Contains(s.Run, "scripts/codesign.sh windows ") || strings.Contains(s.Run, "-DSIGN_COMMAND=")
}

// TestCodesignSigningJobsUseTheReleaseSigningEnvironment: exactly the
// signing jobs run in release-signing, each with job-level permissions of
// contents: read and id-token: write and nothing else, and the workflow's
// top-level permissions grant no id-token to anyone.
func TestCodesignSigningJobsUseTheReleaseSigningEnvironment(t *testing.T) {
	doc, raw := loadWorkflow(t)
	var top struct {
		Permissions map[string]string `yaml:"permissions"`
	}
	if err := yaml.Unmarshal([]byte(raw), &top); err != nil {
		t.Fatalf("parse top-level permissions: %v", err)
	}
	if _, ok := top.Permissions["id-token"]; ok {
		t.Error("the top-level permissions grant id-token; it belongs only to the jobs that need it")
	}
	for name, job := range doc.Jobs {
		env := job.Environment.Value
		if job.Environment.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(job.Environment.Content); i += 2 {
				if job.Environment.Content[i].Value == "name" {
					env = job.Environment.Content[i+1].Value
				}
			}
		}
		signing := contains(codesignJobs, name)
		if signing && env != codesignEnvironment {
			t.Errorf("job %s signs but does not run in the %s environment (environment: %q)", name, codesignEnvironment, env)
		}
		if !signing && env == codesignEnvironment {
			t.Errorf("job %s runs in the %s environment but does not sign; only %v may", name, codesignEnvironment, codesignJobs)
		}
		if !signing {
			continue
		}
		want := map[string]string{"contents": "read", "id-token": "write"}
		if len(job.Permissions) != len(want) {
			t.Errorf("job %s permissions = %v, want exactly %v", name, job.Permissions, want)
		}
		for k, v := range want {
			if job.Permissions[k] != v {
				t.Errorf("job %s permission %s = %q, want %q", name, k, job.Permissions[k], v)
			}
		}
	}
}

// TestCodesignSwitchComesOnlyFromEnvironmentVariables: the switch defaults
// off (nothing in the repo turns it on), only the two known switches exist,
// every step env that carries one reads it from vars, and no signing job
// reads a secret.
func TestCodesignSwitchComesOnlyFromEnvironmentVariables(t *testing.T) {
	doc, raw := loadWorkflow(t)
	for _, m := range regexp.MustCompile(`OBSERVER_SIGN_([A-Z_]+)`).FindAllStringSubmatch(raw, -1) {
		if m[1] != "AUTHENTICODE" && m[1] != "APPLE" {
			t.Errorf("unknown signing switch %s in npm-release.yml", m[0])
		}
	}
	if regexp.MustCompile(`OBSERVER_SIGN_[A-Z_]+\s*[:=]\s*['"]?(1|true)\b`).MatchString(raw) {
		t.Error("npm-release.yml hard-codes a signing switch on; it must come only from the release-signing environment (default off)")
	}
	if strings.Contains(raw, "secrets.OBSERVER_SIGN_") || strings.Contains(raw, "secrets.AZURE_SIGNING_") {
		t.Error("a signing switch or Azure identifier is read from secrets; they are environment variables")
	}
	for name, job := range doc.Jobs {
		for _, s := range job.Steps {
			for k, v := range s.Env {
				if strings.HasPrefix(k, "OBSERVER_SIGN_") && v != "${{ vars."+k+" }}" {
					t.Errorf("job %s step %q sets %s = %q, want ${{ vars.%s }}", name, s.Name, k, v, k)
				}
			}
		}
	}
	// Windows signing logs in with OIDC and needs no secret; the only secrets
	// a signing job reads are the four Apple ones, in a macOS signing step's
	// env, gated on the switch and a v* tag (codesign_apple_workflow_test.go).
	for _, name := range codesignJobs {
		for _, s := range doc.Jobs[name].Steps {
			stepText := s.If + "\n" + s.Run + "\n" + s.Uses
			for _, v := range s.With {
				vs, _ := v.(string)
				stepText += "\n" + vs
			}
			if strings.Contains(stepText, "secrets.") {
				t.Errorf("signing job %s step %q reads a secret outside its env", name, s.Name)
			}
			for k, v := range s.Env {
				if !strings.Contains(v, "secrets.") {
					continue
				}
				if !isMacOSSigningStep(s) || appleSecretEnv(k) != v {
					t.Errorf("signing job %s step %q env %s = %q: only a macOS signing step may read a secret, and only %s", name, s.Name, k, v, strings.Join(appleSecretNames, ", "))
				}
			}
		}
	}
}

// TestCodesignAzureLoginIsOIDCAndScoped: the Azure login runs only in the
// signing jobs, pinned by commit SHA with a version comment, only when the
// switch is on and the ref is a v* tag, with identifiers from vars and no
// client secret; it precedes every Windows signing step, after the pinned
// jsign install.
func TestCodesignAzureLoginIsOIDCAndScoped(t *testing.T) {
	doc, raw := loadWorkflow(t)
	pin := regexp.MustCompile(`^azure/login@[0-9a-f]{40}$`)
	for name, job := range doc.Jobs {
		login, install := -1, -1
		for i, s := range job.Steps {
			if s.Name == jsignInstallStep && install < 0 {
				install = i
			}
			if !strings.HasPrefix(s.Uses, "azure/login") {
				if isWindowsSigningStep(s) && contains(codesignJobs, name) {
					if login < 0 || install < 0 || install > login {
						t.Errorf("job %s step %q signs before the jsign install and the Azure login", name, s.Name)
					}
				}
				continue
			}
			if !contains(codesignJobs, name) {
				t.Errorf("job %s logs in to Azure but is not a signing job", name)
			}
			login = i
			if !pin.MatchString(s.Uses) {
				t.Errorf("job %s: %q is not pinned by commit SHA", name, s.Uses)
			}
			if !regexp.MustCompile(regexp.QuoteMeta(s.Uses) + ` # v\d+\.\d+\.\d+`).MatchString(raw) {
				t.Errorf("job %s: %q has no version comment", name, s.Uses)
			}
			for _, w := range []string{"vars.OBSERVER_SIGN_AUTHENTICODE == '1'", "startsWith(github.ref, 'refs/tags/v')"} {
				if !strings.Contains(s.If, w) {
					t.Errorf("job %s: the Azure login's if %q lacks %s", name, s.If, w)
				}
			}
			for k, v := range s.With {
				vs, _ := v.(string)
				switch k {
				case "client-id", "tenant-id", "subscription-id":
					if !strings.HasPrefix(vs, "${{ vars.AZURE_SIGNING_") {
						t.Errorf("job %s: azure/login %s = %q, want a vars.AZURE_SIGNING_* value", name, k, vs)
					}
				default:
					t.Errorf("job %s: azure/login takes %s; only client-id, tenant-id and subscription-id (OIDC, no secret)", name, k)
				}
			}
		}
		if contains(codesignJobs, name) && login < 0 {
			t.Errorf("signing job %s has no Azure login step", name)
		}
	}
}

// TestCodesignTokenNeverLeaves: every Windows signing step fetches the token
// with the one masked snippet and carries the switch and identifiers from
// vars; no env map anywhere names the token; nothing writes it to
// GITHUB_ENV or GITHUB_OUTPUT; its value is expanded only in the add-mask
// line. Windows steps receive no Apple input and macOS steps no Azure one.
func TestCodesignTokenNeverLeaves(t *testing.T) {
	doc, raw := loadWorkflow(t)
	snippet := normalizeShell(tokenFetch)
	signing := 0
	for name, job := range doc.Jobs {
		for _, s := range job.Steps {
			if _, ok := s.Env["AZURE_SIGNING_TOKEN"]; ok {
				t.Errorf("job %s step %q puts AZURE_SIGNING_TOKEN in an env map", name, s.Name)
			}
			if isWindowsSigningStep(s) {
				signing++
				if !strings.Contains(normalizeShell(s.Run), snippet) {
					t.Errorf("job %s step %q does not fetch the Key Vault token with the masked snippet", name, s.Name)
				}
				for k, v := range signingEnv {
					if s.Env[k] != v {
						t.Errorf("job %s step %q env %s = %q, want %q", name, s.Name, k, s.Env[k], v)
					}
				}
				for k := range s.Env {
					if strings.Contains(k, "APPLE") {
						t.Errorf("Windows signing step %q receives %s", s.Name, k)
					}
				}
			}
			if strings.Contains(s.Run, "scripts/codesign.sh darwin ") {
				for k := range s.Env {
					if strings.HasPrefix(k, "AZURE_") {
						t.Errorf("macOS signing step %q receives %s", s.Name, k)
					}
				}
			}
		}
	}
	if signing < 4 {
		t.Errorf("found %d Windows signing steps, want at least 4 (build, edition_build, observerw.exe, makensis)", signing)
	}
	for _, line := range strings.Split(raw, "\n") {
		if !strings.Contains(line, "AZURE_SIGNING_TOKEN") {
			continue
		}
		if strings.Contains(line, "GITHUB_ENV") || strings.Contains(line, "GITHUB_OUTPUT") || strings.Contains(line, "GITHUB_STEP_SUMMARY") {
			t.Errorf("the token is written to a runner file: %s", strings.TrimSpace(line))
		}
		if strings.Contains(line, "$AZURE_SIGNING_TOKEN") || (strings.Contains(line, "${AZURE_SIGNING_TOKEN") && !strings.Contains(line, `echo "::add-mask::${AZURE_SIGNING_TOKEN}"`)) {
			t.Errorf("the token's value is expanded outside the add-mask line: %s", strings.TrimSpace(line))
		}
	}
}

// TestCodesignSetupProgramIsVerifiedBeforeUpload: windows_setup checks the
// finished setup program's signature after makensis and before upload.
func TestCodesignSetupProgramIsVerifiedBeforeUpload(t *testing.T) {
	doc, _ := loadWorkflow(t)
	makensis, verify, upload := -1, -1, -1
	for i, s := range doc.Jobs["windows_setup"].Steps {
		switch {
		case strings.Contains(s.Run, "makensis -V2 -WX"):
			makensis = i
		case strings.Contains(s.Run, "scripts/codesign.sh windows-verify "):
			verify = i
			if s.Env["OBSERVER_SIGN_AUTHENTICODE"] != "${{ vars.OBSERVER_SIGN_AUTHENTICODE }}" {
				t.Errorf("the setup check does not read the switch from vars (env %v)", s.Env)
			}
		case s.Uses != "" && strings.HasPrefix(s.Uses, "actions/upload-artifact"):
			upload = i
		}
	}
	if makensis < 0 || verify < 0 || upload < 0 || !(makensis < verify && verify < upload) {
		t.Errorf("windows_setup order: makensis=%d verify=%d upload=%d, want makensis < verify < upload", makensis, verify, upload)
	}
}

// TestCodesignJsignIsPinned: jsign is pinned by version and sha256 in the
// top-level env, and every signing job installs it with one identical,
// retried, checksum-verified script that runs only when the switch is on.
func TestCodesignJsignIsPinned(t *testing.T) {
	doc, raw := loadWorkflow(t)
	var env workflowEnvDoc
	if err := yaml.Unmarshal([]byte(raw), &env); err != nil {
		t.Fatalf("parse top-level env: %v", err)
	}
	if !regexp.MustCompile(`^\d+\.\d+(\.\d+)?$`).MatchString(env.Env["JSIGN_VERSION"]) {
		t.Errorf("env.JSIGN_VERSION = %q, want a pinned jsign release", env.Env["JSIGN_VERSION"])
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(env.Env["JSIGN_SHA256"]) {
		t.Errorf("env.JSIGN_SHA256 = %q, want the 64-hex sha256 of jsign-<version>.jar", env.Env["JSIGN_SHA256"])
	}
	steps := jsignInstallSteps(t, doc)
	ref := steps["build"].Run
	for _, name := range codesignJobs {
		s, ok := steps[name]
		if !ok {
			t.Errorf("signing job %s has no %q step", name, jsignInstallStep)
			continue
		}
		if s.Run != ref {
			t.Errorf("%s's jsign install differs from build's; they must be byte-identical", name)
		}
		if !strings.Contains(s.If, "vars.OBSERVER_SIGN_AUTHENTICODE == '1'") {
			t.Errorf("%s installs jsign without the switch on (if %q)", name, s.If)
		}
	}
	if len(steps) != len(codesignJobs) {
		t.Errorf("%d jobs install jsign, want exactly %d", len(steps), len(codesignJobs))
	}
	for _, want := range []string{
		"set -euo pipefail",
		"--retry 8", "--retry-all-errors",
		`"${base}/jsign-${JSIGN_VERSION}.jar"`,
		`echo "${JSIGN_SHA256}  ${RUNNER_TEMP}/jsign/jsign.jar" | sha256sum -c -`,
	} {
		if !strings.Contains(ref, want) {
			t.Errorf("the jsign install script lacks %q", want)
		}
	}
}

func jsignInstallSteps(t *testing.T, doc workflowDoc) map[string]workflowStep {
	t.Helper()
	steps := map[string]workflowStep{}
	for jobName, job := range doc.Jobs {
		for _, s := range job.Steps {
			if s.Name == jsignInstallStep {
				if _, dup := steps[jobName]; dup {
					t.Errorf("job %s carries two %q steps", jobName, jsignInstallStep)
				}
				steps[jobName] = s
			}
		}
	}
	return steps
}

// TestCodesignJsignInstallExecutes runs the install script against a file://
// download base: a jar matching the pinned sha256 lands where the signing
// steps look for it; a mismatching one is refused.
func TestCodesignJsignInstallExecutes(t *testing.T) {
	for _, tool := range []string{"bash", "curl", "sha256sum"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not available", tool)
		}
	}
	if help, _ := exec.Command("curl", "--help", "all").CombinedOutput(); !strings.Contains(string(help), "--retry-all-errors") {
		t.Skip("local curl predates --retry-all-errors; the script is executed on the release runner")
	}
	doc, _ := loadWorkflow(t)
	script := jsignInstallSteps(t, doc)["build"].Run
	if script == "" {
		t.Fatal("build has no jsign install script")
	}
	jar := []byte("not really a jar")
	sum := sha256.Sum256(jar)
	run := func(t *testing.T, pinned string) (string, string, error) {
		t.Helper()
		dl := t.TempDir()
		if err := os.WriteFile(filepath.Join(dl, "jsign-0.0.jar"), jar, 0o644); err != nil {
			t.Fatal(err)
		}
		tmp := t.TempDir()
		cmd := exec.Command("bash", "-c", script)
		cmd.Env = append(os.Environ(),
			"RUNNER_TEMP="+tmp,
			"JSIGN_VERSION=0.0",
			"JSIGN_SHA256="+pinned,
			"JSIGN_DOWNLOAD_BASE=file://"+dl,
		)
		out, err := cmd.CombinedOutput()
		return string(out), filepath.Join(tmp, "jsign", "jsign.jar"), err
	}
	t.Run("pinned sha matches", func(t *testing.T) {
		out, path, err := run(t, hex.EncodeToString(sum[:]))
		if err != nil {
			t.Fatalf("install failed: %v\n%s", err, out)
		}
		if _, err := os.Stat(path); err != nil {
			t.Errorf("the jar is not at %s: %v", path, err)
		}
	})
	t.Run("pinned sha mismatch is refused", func(t *testing.T) {
		if out, _, err := run(t, strings.Repeat("0", 64)); err == nil {
			t.Fatalf("install succeeded with a wrong checksum:\n%s", out)
		}
	})
}

// TestCodesignScriptStaticRules: the hook never traces, never reads a
// secret, never expands the token, always timestamps (RFC 3161) and passes
// the token to jsign only through env:, and its expected publisher is the
// setup program's PUBLISHER.
func TestCodesignScriptStaticRules(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(repoRoot(t), "scripts", "codesign.sh"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	if regexp.MustCompile(`(?m)^\s*set\s+(-[a-wyz]*x|-o\s+xtrace)`).MatchString(src) {
		t.Error("scripts/codesign.sh enables command tracing; the token would be at risk")
	}
	if strings.Contains(src, "secrets.") {
		t.Error("scripts/codesign.sh references a secret")
	}
	if strings.Contains(src, "$AZURE_SIGNING_TOKEN") || strings.Contains(src, "${AZURE_SIGNING_TOKEN") {
		t.Error("scripts/codesign.sh expands the Key Vault token; it must only name it (env:AZURE_SIGNING_TOKEN)")
	}
	for _, want := range []string{
		"--storetype AZUREKEYVAULT",
		"--storepass env:AZURE_SIGNING_TOKEN",
		`--tsaurl "$TSA_URLS"`,
		"--tsmode RFC3161",
		`TSA_URLS="http://timestamp.sectigo.com,http://timestamp.digicert.com"`,
		"--replace",
		"--alg SHA-256",
		"env -u AZURE_SIGNING_TOKEN osslsigncode verify",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("scripts/codesign.sh lacks %q", want)
		}
	}
	m := regexp.MustCompile(`(?m)^EXPECTED_PUBLISHER="([^"]+)"$`).FindStringSubmatch(src)
	if m == nil {
		t.Fatal("scripts/codesign.sh has no EXPECTED_PUBLISHER")
	}
	nsi, err := os.ReadFile(filepath.Join(repoRoot(t), "installer", "windows", "superbased-setup.nsi"))
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^!define PUBLISHER\s+"` + regexp.QuoteMeta(m[1]) + `"`).Match(nsi) {
		t.Errorf("the setup program's PUBLISHER differs from codesign.sh's EXPECTED_PUBLISHER %q", m[1])
	}
}

// fakeTool writes an executable shell script into dir.
func fakeTool(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/usr/bin/env bash\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
}

const (
	codesignSentinelToken = "SENTINEL-KV-TOKEN-9f8e7d"
	osslGood              = "Signer's certificate:\n\tSigner #0:\n\t\tSubject: /C=IN/ST=Maharashtra/L=Mumbai/O=Gaja AI Private Limited/CN=Gaja AI Private Limited\n\t\tIssuer : /C=LV/O=EnVers Group SIA/CN=GoGetSSL G4 CS RSA4096 SHA256 2022 CA-1\n\nThe signature is timestamped: Oct 23 13:15:20 2026 GMT\nTimestamp Server Signature verification: ok\nSignature verification: ok\n\nNumber of verified signatures: 1\nSucceeded\n"
	osslWrongSubject      = "Signer's certificate:\n\tSigner #0:\n\t\tSubject: /C=US/O=Someone Else/CN=Someone Else\n\nThe signature is timestamped: Oct 23 13:15:20 2026 GMT\nSignature verification: ok\nSucceeded\n"
	osslNoTimestamp       = "Signer's certificate:\n\tSigner #0:\n\t\tSubject: /C=IN/O=Gaja AI Private Limited/CN=Gaja AI Private Limited\n\nSignature verification: ok\nSucceeded\n"
)

// TestCodesignScriptFailsClosed runs scripts/codesign.sh hermetically (fake
// java and osslsigncode on PATH, no network, no key): off is a logged no-op,
// a typo in the switch fails, every missing input fails before jsign runs, a
// jsign or osslsigncode failure fails, a wrong publisher or a missing
// timestamp fails, and the token never appears in the output, on jsign's
// command line or in the checker's environment.
func TestCodesignScriptFailsClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the hook runs on the Linux release runner")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not available")
	}
	script := filepath.Join(repoRoot(t), "scripts", "codesign.sh")

	type tc struct {
		name      string
		kind      string
		env       map[string]string // overrides on top of the "on, complete" base
		unset     []string
		java      string // exit code of the fake jsign
		ossl      string // output of the fake osslsigncode
		osslExit  string
		chain     bool
		noOssl    bool
		wantExit  int
		wantOut   string
		wantJava  bool
		wantOsslV bool
	}
	off := map[string]string{"OBSERVER_SIGN_AUTHENTICODE": ""}
	cases := []tc{
		{name: "off when unset", kind: "windows", unset: []string{"OBSERVER_SIGN_AUTHENTICODE"}, wantExit: 0, wantOut: "ships unsigned"},
		{name: "off when empty", kind: "windows", env: off, wantExit: 0, wantOut: "ships unsigned"},
		{name: "off when 0", kind: "windows", env: map[string]string{"OBSERVER_SIGN_AUTHENTICODE": "0"}, wantExit: 0, wantOut: "ships unsigned"},
		{name: "typo in the switch fails", kind: "windows", env: map[string]string{"OBSERVER_SIGN_AUTHENTICODE": "true"}, wantExit: 1, wantOut: "must be 1"},
		{name: "missing vault", kind: "windows", unset: []string{"AZURE_SIGNING_VAULT"}, wantExit: 1, wantOut: "AZURE_SIGNING_VAULT is not set"},
		{name: "missing cert name", kind: "windows", unset: []string{"AZURE_SIGNING_CERT_NAME"}, wantExit: 1, wantOut: "AZURE_SIGNING_CERT_NAME is not set"},
		{name: "missing token", kind: "windows", unset: []string{"AZURE_SIGNING_TOKEN"}, wantExit: 1, wantOut: "AZURE_SIGNING_TOKEN is not set"},
		{name: "empty token", kind: "windows", env: map[string]string{"AZURE_SIGNING_TOKEN": ""}, wantExit: 1, wantOut: "AZURE_SIGNING_TOKEN is not set"},
		{name: "missing jsign jar input", kind: "windows", unset: []string{"JSIGN_JAR"}, wantExit: 1, wantOut: "JSIGN_JAR is not set"},
		{name: "jsign jar not on disk", kind: "windows", env: map[string]string{"JSIGN_JAR": "/nonexistent/jsign.jar"}, wantExit: 1, wantOut: "JSIGN_JAR does not exist"},
		{name: "osslsigncode not installed", kind: "windows", noOssl: true, wantExit: 1, wantOut: "osslsigncode is not installed"},
		{name: "missing trust anchors", kind: "windows", env: map[string]string{"CODESIGN_CAFILE": "/nonexistent/ca.pem"}, wantExit: 1, wantOut: "trust anchors not found", wantJava: true},
		{name: "jsign fails", kind: "windows", java: "1", wantExit: 1, wantOut: "jsign could not sign", wantJava: true},
		{name: "verify rejects", kind: "windows", osslExit: "1", wantExit: 1, wantOut: "osslsigncode verify rejected", wantJava: true, wantOsslV: true},
		{name: "wrong publisher", kind: "windows", ossl: osslWrongSubject, wantExit: 1, wantOut: "does not name Gaja AI Private Limited", wantJava: true, wantOsslV: true},
		{name: "no timestamp", kind: "windows", ossl: osslNoTimestamp, wantExit: 1, wantOut: "carries no timestamp", wantJava: true, wantOsslV: true},
		{name: "signs and verifies", kind: "windows", wantExit: 0, wantOut: "timestamped and verified", wantJava: true, wantOsslV: true},
		{name: "signs with the chain file", kind: "windows", chain: true, wantExit: 0, wantOut: "timestamped and verified", wantJava: true, wantOsslV: true},
		{name: "verify-only off", kind: "windows-verify", env: off, wantExit: 0, wantOut: "not checking"},
		{name: "verify-only on", kind: "windows-verify", wantExit: 0, wantOut: "timestamped and verified", wantOsslV: true},
		{name: "verify-only wrong publisher", kind: "windows-verify", ossl: osslWrongSubject, wantExit: 1, wantOut: "does not name", wantOsslV: true},
		{name: "darwin off", kind: "darwin", wantExit: 0, wantOut: "ad-hoc signature only"},
		// The darwin branch on is covered by TestCodesignDarwinFailsClosed
		// (codesign_macos_test.go); here only: on without its inputs fails.
		{name: "darwin on without inputs fails", kind: "darwin", env: map[string]string{"OBSERVER_SIGN_APPLE": "1"}, wantExit: 1, wantOut: "OBSERVER_SIGN_APPLE=1 but APPLE_P12_FILE is not set"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "bin")
			logs := filepath.Join(dir, "logs")
			for _, d := range []string{bin, logs} {
				if err := os.MkdirAll(d, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			target := filepath.Join(dir, "observer.exe")
			if err := os.WriteFile(target, []byte("MZ fake pe"), 0o644); err != nil {
				t.Fatal(err)
			}
			jar := filepath.Join(dir, "jsign.jar")
			if err := os.WriteFile(jar, []byte("jar"), 0o644); err != nil {
				t.Fatal(err)
			}
			ca := filepath.Join(dir, "ca.pem")
			if err := os.WriteFile(ca, []byte("system anchors\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			chain := filepath.Join(dir, "codesign-chain.pem")
			if c.chain {
				if err := os.WriteFile(chain, []byte("chain\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			osslOut := filepath.Join(dir, "ossl.out")
			out := c.ossl
			if out == "" {
				out = osslGood
			}
			if err := os.WriteFile(osslOut, []byte(out), 0o644); err != nil {
				t.Fatal(err)
			}
			fakeTool(t, bin, "java", `printf '%s\n' "$@" > "$FAKE_LOGS/java.args"
if [ -n "${AZURE_SIGNING_TOKEN:-}" ]; then echo yes > "$FAKE_LOGS/java.token"; fi
exit "${FAKE_JAVA_EXIT:-0}"
`)
			if !c.noOssl {
				fakeTool(t, bin, "osslsigncode", `printf '%s\n' "$@" > "$FAKE_LOGS/ossl.args"
if [ -n "${AZURE_SIGNING_TOKEN:-}" ]; then echo yes > "$FAKE_LOGS/ossl.token"; fi
cat "$FAKE_OSSL_OUT"
exit "${FAKE_OSSL_EXIT:-0}"
`)
			} else if p, err := exec.LookPath("osslsigncode"); err == nil {
				t.Skipf("a real osslsigncode is installed at %s; cannot hide it", p)
			}
			env := map[string]string{
				"PATH":                       bin + ":/usr/bin:/bin",
				"HOME":                       dir,
				"FAKE_LOGS":                  logs,
				"FAKE_OSSL_OUT":              osslOut,
				"FAKE_JAVA_EXIT":             c.java,
				"FAKE_OSSL_EXIT":             c.osslExit,
				"OBSERVER_SIGN_AUTHENTICODE": "1",
				"AZURE_SIGNING_VAULT":        "superbased-codesigning",
				"AZURE_SIGNING_CERT_NAME":    "superbased-ov-codesigning",
				"AZURE_SIGNING_TOKEN":        codesignSentinelToken,
				"JSIGN_JAR":                  jar,
				"CODESIGN_CAFILE":            ca,
				"CODESIGN_CHAIN_FILE":        chain,
			}
			if c.kind == "darwin" {
				delete(env, "OBSERVER_SIGN_AUTHENTICODE")
			}
			for k, v := range c.env {
				env[k] = v
			}
			for _, k := range c.unset {
				delete(env, k)
			}
			cmd := exec.Command("bash", script, c.kind, target)
			cmd.Env = nil
			for k, v := range env {
				cmd.Env = append(cmd.Env, k+"="+v)
			}
			got, err := cmd.CombinedOutput()
			code := 0
			if err != nil {
				var ee *exec.ExitError
				if !errors.As(err, &ee) {
					t.Fatalf("run: %v", err)
				}
				code = ee.ExitCode()
			}
			if code != c.wantExit {
				t.Errorf("exit %d, want %d\n%s", code, c.wantExit, got)
			}
			if !strings.Contains(string(got), c.wantOut) {
				t.Errorf("output lacks %q:\n%s", c.wantOut, got)
			}
			if strings.Contains(string(got), codesignSentinelToken) {
				t.Errorf("the token appears in the output:\n%s", got)
			}
			javaArgs, javaErr := os.ReadFile(filepath.Join(logs, "java.args"))
			if ran := javaErr == nil; ran != c.wantJava {
				t.Errorf("jsign ran = %v, want %v", ran, c.wantJava)
			}
			osslArgs, osslErr := os.ReadFile(filepath.Join(logs, "ossl.args"))
			if ran := osslErr == nil; ran != c.wantOsslV {
				t.Errorf("osslsigncode ran = %v, want %v", ran, c.wantOsslV)
			}
			if strings.Contains(string(javaArgs), codesignSentinelToken) || strings.Contains(string(osslArgs), codesignSentinelToken) {
				t.Error("the token is on a command line")
			}
			if _, err := os.Stat(filepath.Join(logs, "ossl.token")); err == nil {
				t.Error("the token reached osslsigncode's environment")
			}
			if c.wantJava {
				if _, err := os.Stat(filepath.Join(logs, "java.token")); err != nil {
					t.Error("jsign did not receive the token in its environment (--storepass env: needs it)")
				}
				args := "\n" + string(javaArgs)
				for _, w := range []string{
					"\n-jar\n" + jar + "\n",
					"\n--storetype\nAZUREKEYVAULT\n",
					"\n--keystore\nsuperbased-codesigning\n",
					"\n--alias\nsuperbased-ov-codesigning\n",
					"\n--storepass\nenv:AZURE_SIGNING_TOKEN\n",
					"\n--alg\nSHA-256\n",
					"\n--tsaurl\nhttp://timestamp.sectigo.com,http://timestamp.digicert.com\n",
					"\n--tsmode\nRFC3161\n",
					"\n--replace\n",
					"\n--name\nSuperBased Observer\n",
					"\n--url\nhttps://superbased.app\n",
					"\n" + target + "\n",
				} {
					if !strings.Contains(args, w) {
						t.Errorf("jsign argv lacks %q:\n%s", strings.TrimSpace(w), javaArgs)
					}
				}
				if hasChain := strings.Contains(args, "\n--certfile\n"+chain+"\n"); hasChain != c.chain {
					t.Errorf("jsign --certfile present = %v, want %v:\n%s", hasChain, c.chain, javaArgs)
				}
			}
			if c.wantOsslV && osslErr == nil {
				oargs := "\n" + string(osslArgs)
				if !strings.Contains(oargs, "\nverify\n-in\n"+target+"\n-CAfile\n") {
					t.Errorf("osslsigncode argv is not `verify -in <file> -CAfile <anchors>`:\n%s", osslArgs)
				}
				if usesSystem := strings.Contains(oargs, "\n-CAfile\n"+ca+"\n"); usesSystem == c.chain {
					t.Errorf("-CAfile = system anchors %v with chain file %v; the chain file must be added to the anchors:\n%s", usesSystem, c.chain, osslArgs)
				}
			}
		})
	}
}
