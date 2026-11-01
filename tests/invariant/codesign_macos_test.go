package invariant

import (
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// codesign_macos_test.go runs the macOS half of the signing hook (macsign
// lane, plan docs/plans/code-signing-phase-2-plan-2026-10-21.md sections 3.2
// and 3.5) hermetically: scripts/codesign-apple-inputs.sh is sourced and
// scripts/codesign.sh darwin runs against a fake rcodesign and a fake zip on
// PATH. No network, no key, no Apple account.

const (
	appleTeam             = "ABCDE12345"
	appleSentinelP12Bytes = "SENTINEL-P12-BYTES-4c1d"
	appleSentinelPassword = "SENTINEL-P12-PASSWORD-7a2b"
	appleSentinelJSONKey  = "SENTINEL-JSON-PRIVATE-KEY-3e9f"
	appleSentinelP8       = "SENTINEL-P8-PRIVATE-KEY-5d6c"
	appleDerivedKey       = "SENTINEL-DERIVED-KEY-8b0a"
	appleIssuer           = "69a6de70-1234-47e3-e053-5b8c7c11a4d1"
	appleKeyID            = "ZXCV123456"
	appleSubmission       = "11111111-2222-3333-4444-555555555555"
)

// tracing matches a `set -x` / `set -o xtrace` that would print secrets.
var tracing = regexp.MustCompile(`(?m)^\s*set\s+(-[a-wyz]*x|-o\s+xtrace)`)

var appleSentinelP12 = base64.StdEncoding.EncodeToString([]byte(appleSentinelP12Bytes))

// appleSecrets are the secret values that must never reach the output (other
// than an ::add-mask:: line), a command line or a child's environment.
var appleSecrets = []string{appleSentinelP12, appleSentinelP12Bytes, appleSentinelPassword, appleSentinelJSONKey, appleSentinelP8, appleDerivedKey}

const signatureInfoGood = `- path: observer
  entity:
    mach_o:
      code_directory:
        version: '0x20500'
        flags: CodeSignatureFlags(RUNTIME)
        identifier: app.superbased.observer
        team_name: ABCDE12345
        executable_segment_flags: ExecutableSegmentFlags(MAIN_BINARY)
      cms:
        certificates:
        - subject: 'CN="Developer ID Application: Gaja AI Private Limited (ABCDE12345)", OU=ABCDE12345, O=Gaja AI Private Limited, C=IN'
          chains_to_apple_root_ca: true
          apple_certificate_profile: developer-id-application
          apple_team_id: ABCDE12345
        - subject: CN=Developer ID Certification Authority, OU=G2, O=Apple Inc., C=US
          is_apple_intermediate_ca: true
`

var (
	signatureInfoNoRuntime = strings.Replace(signatureInfoGood, "flags: CodeSignatureFlags(RUNTIME)", "flags: CodeSignatureFlags(0x0)", 1)
	signatureInfoNotDevID  = strings.Replace(signatureInfoGood, "apple_certificate_profile: developer-id-application", "apple_certificate_profile: apple-development", 1)
	signatureInfoWrongTeam = strings.Replace(signatureInfoGood, "apple_team_id: ABCDE12345", "apple_team_id: QWERTY9876", 1)
)

const (
	notaryAccepted = "created submission ID: " + appleSubmission + "\npoll state after 14s: Accepted\nNotary API Server has finished processing the uploaded asset\nnotary log> {\"status\": \"Accepted\"}\n"
	notaryInvalid  = "created submission ID: " + appleSubmission + "\npoll state after 30s: Invalid\nNotary API Server has finished processing the uploaded asset\nnotary log> {\"status\": \"Invalid\"}\nError: notarization Invalid\n"
	notaryTimeout  = "created submission ID: " + appleSubmission + "\npoll state after 1801s: InProgress\nreached wait limit after 1801s\n"
)

// fakeRcodesign stands in for rcodesign: it logs each call, the modes of the
// files it is handed and whether a secret reached its environment, and
// answers from the FAKE_* knobs. Like rcodesign 0.29 it refuses to run with
// any RCODESIGN_<KEY> variable in its environment: the real one reads each as
// a configuration key and stops with "configuration file error" (the v1.37.0
// failure, caused by the workflow's RCODESIGN_VERSION / RCODESIGN_SHA256).
const fakeRcodesign = `sub="$1"
printf '%s\n' "$sub" >> "$FAKE_LOGS/calls"
printf '%s\n' "$@" > "$FAKE_LOGS/$sub.args"
if env | grep -q '^RCODESIGN_'; then
  echo "configuration file error" >&2
  echo "$sub" >> "$FAKE_LOGS/rcodesign-env"
  exit 1
fi
if env | grep -Eq '^APPLE_(DEVELOPER_ID_P12_BASE64|DEVELOPER_ID_P12_PASSWORD|NOTARY_API_KEY_JSON|NOTARY_KEY_P8)='; then
  echo "$sub" >> "$FAKE_LOGS/secret-env"
fi
mode() { stat -c '%a' "$1" 2>/dev/null || echo missing; }
case "$sub" in
  encode-app-store-connect-api-key)
    out="$3"; p8="$6"
    mode "$p8" > "$FAKE_LOGS/p8.mode"
    mode "$(dirname "$p8")" > "$FAKE_LOGS/dir.mode"
    if grep -q "$FAKE_P8_WANT" "$p8"; then echo yes > "$FAKE_LOGS/p8.content"; fi
    [ "${FAKE_ENCODE_EXIT:-0}" = 0 ] || exit "$FAKE_ENCODE_EXIT"
    printf '{\n  "issuer_id": "%s",\n  "key_id": "%s",\n  "private_key": "%s"\n}\n' "$4" "$5" "$FAKE_DERIVED" > "$out"
    echo "writing unified key JSON to $out" >&2
    ;;
  sign)
    while [ $# -gt 0 ]; do
      case "$1" in
        --p12-file) mode "$2" > "$FAKE_LOGS/p12.mode"; mode "$(dirname "$2")" > "$FAKE_LOGS/dir.mode"
          if grep -q "$FAKE_P12_WANT" "$2"; then echo yes > "$FAKE_LOGS/p12.content"; fi; shift ;;
        --p12-password-file) mode "$2" > "$FAKE_LOGS/password.mode"
          if grep -q "$FAKE_PASSWORD_WANT" "$2"; then echo yes > "$FAKE_LOGS/password.content"; fi; shift ;;
      esac
      shift
    done
    exit "${FAKE_SIGN_EXIT:-0}"
    ;;
  verify) exit "${FAKE_VERIFY_EXIT:-0}" ;;
  print-signature-info) cat "$FAKE_INFO" ;;
  notary-submit)
    while [ $# -gt 0 ]; do
      case "$1" in
        --api-key-file) mode "$2" > "$FAKE_LOGS/key.mode"
          if grep -q "$FAKE_KEY_WANT" "$2"; then echo yes > "$FAKE_LOGS/key.content"; fi; shift ;;
        *.zip) [ -s "$1" ] && echo yes > "$FAKE_LOGS/zip.present" ;;
      esac
      shift
    done
    cat "$FAKE_NOTARY_OUT" >&2
    exit "${FAKE_NOTARY_EXIT:-0}"
    ;;
  notary-log) echo "notary log for $4: the binary is not signed with a valid Developer ID" ;;
  *) echo "fake rcodesign: unexpected $sub" >&2; exit 9 ;;
esac
`

// fakeZip writes a non-empty archive at the first *.zip argument.
const fakeZip = `for a in "$@"; do case "$a" in *.zip) printf 'PK fake' > "$a" ;; esac; done
printf '%s\n' "$@" > "$FAKE_LOGS/zip.args"
`

type darwinRun struct {
	out    string
	code   int
	logs   string
	runner string
	target string
	bin    string
}

func (r darwinRun) log(t *testing.T, name string) (string, bool) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(r.logs, name))
	return string(b), err == nil
}

// runDarwinSign prepares a fake toolbox and runs script (bash -c) with env,
// returning what it printed and left behind.
func runDarwinSign(t *testing.T, script string, env map[string]string, unset []string, extra map[string]string) darwinRun {
	t.Helper()
	dir := t.TempDir()
	r := darwinRun{
		logs:   filepath.Join(dir, "logs"),
		runner: filepath.Join(dir, "runner-temp"),
		bin:    filepath.Join(dir, "bin"),
		target: filepath.Join(dir, "observer"),
	}
	for _, d := range []string{r.logs, r.runner, r.bin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(r.target, []byte("\xcf\xfa\xed\xfe fake mach-o"), 0o755); err != nil {
		t.Fatal(err)
	}
	fakeTool(t, r.bin, "rcodesign", fakeRcodesign)
	fakeTool(t, r.bin, "zip", fakeZip)
	info := filepath.Join(dir, "info.yaml")
	notary := filepath.Join(dir, "notary.out")
	infoBody, notaryBody := signatureInfoGood, notaryAccepted
	if v, ok := extra["info"]; ok {
		infoBody = v
	}
	if v, ok := extra["notary"]; ok {
		notaryBody = v
	}
	if err := os.WriteFile(info, []byte(infoBody), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(notary, []byte(notaryBody), 0o644); err != nil {
		t.Fatal(err)
	}
	base := map[string]string{
		"PATH":                       r.bin + ":/usr/bin:/bin",
		"HOME":                       dir,
		"RUNNER_TEMP":                r.runner,
		"FAKE_LOGS":                  r.logs,
		"FAKE_INFO":                  info,
		"FAKE_NOTARY_OUT":            notary,
		"FAKE_DERIVED":               appleDerivedKey,
		"FAKE_P8_WANT":               appleSentinelP8,
		"FAKE_P12_WANT":              appleSentinelP12Bytes,
		"FAKE_PASSWORD_WANT":         appleSentinelPassword,
		"FAKE_KEY_WANT":              "private_key",
		"CODESIGN_ENTITLEMENTS_FILE": filepath.Join(dir, "no-entitlements"),
		"TARGET":                     r.target,
		"OBSERVER_SIGN_APPLE":        "1",
		"APPLE_TEAM_ID":              appleTeam,
		"RCODESIGN":                  filepath.Join(r.bin, "rcodesign"),
		// The release workflow's top-level env, and the install step's test
		// seam: none may reach rcodesign (the fake fails if one does).
		"RCODESIGN_VERSION":               "0.29.0",
		"RCODESIGN_SHA256":                strings.Repeat("0", 64),
		"RCODESIGN_DOWNLOAD_BASE":         "file:///nonexistent",
		"APPLE_DEVELOPER_ID_P12_BASE64":   appleSentinelP12,
		"APPLE_DEVELOPER_ID_P12_PASSWORD": appleSentinelPassword,
		"APPLE_NOTARY_API_KEY_JSON":       `{"issuer_id":"` + appleIssuer + `","key_id":"` + appleKeyID + `","private_key":"` + appleSentinelJSONKey + `"}`,
	}
	for k, v := range env {
		base[k] = v
	}
	for _, k := range unset {
		delete(base, k)
	}
	if v, ok := extra["entitlements"]; ok {
		if err := os.WriteFile(base["CODESIGN_ENTITLEMENTS_FILE"], []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	root := repoRoot(t)
	cmd := exec.Command("bash", "-c", script, "_",
		filepath.Join(root, "scripts", "codesign-apple-inputs.sh"),
		filepath.Join(root, "scripts", "codesign.sh"))
	for k, v := range base {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	got, err := cmd.CombinedOutput()
	r.out = string(got)
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("run: %v", err)
		}
		r.code = ee.ExitCode()
	}
	return r
}

// darwinStep is what a macOS signing step runs: source the inputs, then the
// hook once per binary.
const darwinStep = `set -euo pipefail
. "$1"
"$2" darwin "$TARGET"
`

// assertNoAppleLeak: no secret in the output (outside an ::add-mask:: line),
// on any fake's command line or in any fake's environment, and nothing left
// in RUNNER_TEMP.
func assertNoAppleLeak(t *testing.T, r darwinRun) {
	t.Helper()
	var visible []string
	for _, l := range strings.Split(r.out, "\n") {
		if !strings.HasPrefix(l, "::add-mask::") {
			visible = append(visible, l)
		}
	}
	shown := strings.Join(visible, "\n")
	entries, _ := os.ReadDir(r.logs)
	for _, s := range appleSecrets {
		if strings.Contains(shown, s) {
			t.Errorf("a secret value appears in the output:\n%s", r.out)
		}
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".args") {
				if b, _ := os.ReadFile(filepath.Join(r.logs, e.Name())); strings.Contains(string(b), s) {
					t.Errorf("a secret value is on a command line (%s)", e.Name())
				}
			}
		}
	}
	if who, ok := r.log(t, "secret-env"); ok {
		t.Errorf("a secret variable reached rcodesign's environment (%s)", strings.TrimSpace(who))
	}
	left, err := os.ReadDir(r.runner)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range left {
		t.Errorf("left behind in RUNNER_TEMP: %s", e.Name())
	}
}

// TestCodesignDarwinFailsClosed: the macOS signing step, end to end through
// the sourced inputs and the hook.
func TestCodesignDarwinFailsClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the hook runs on the Linux release runner")
	}
	for _, tool := range []string{"bash", "base64", "stat", "mktemp"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not available", tool)
		}
	}
	raw := map[string]string{
		"APPLE_NOTARY_API_KEY_JSON": "",
		"APPLE_NOTARY_ISSUER_ID":    appleIssuer,
		"APPLE_NOTARY_KEY_ID":       appleKeyID,
		"APPLE_NOTARY_KEY_P8":       "-----BEGIN PRIVATE KEY-----\n" + appleSentinelP8 + "\n-----END PRIVATE KEY-----",
	}
	with := func(over map[string]string, more map[string]string) map[string]string {
		m := map[string]string{}
		for k, v := range over {
			m[k] = v
		}
		for k, v := range more {
			m[k] = v
		}
		return m
	}
	type tc struct {
		name     string
		env      map[string]string
		unset    []string
		extra    map[string]string
		wantExit int
		wantOut  string
		// calls is the exact rcodesign subcommand sequence, one per line.
		calls        string
		wantEncode   bool
		wantNotaryOK bool
	}
	cases := []tc{
		{name: "off when unset", unset: []string{"OBSERVER_SIGN_APPLE"}, wantOut: "ad-hoc signature only"},
		{name: "off when empty", env: map[string]string{"OBSERVER_SIGN_APPLE": ""}, wantOut: "no Apple signing input is read"},
		{name: "off when 0", env: map[string]string{"OBSERVER_SIGN_APPLE": "0"}, wantOut: "ad-hoc signature only"},
		{name: "off reads no input", env: map[string]string{"OBSERVER_SIGN_APPLE": "0"}, unset: []string{"APPLE_DEVELOPER_ID_P12_BASE64", "APPLE_NOTARY_API_KEY_JSON", "RCODESIGN", "RUNNER_TEMP"}, wantOut: "ships with Go's ad-hoc signature only"},
		{name: "typo in the switch fails", env: map[string]string{"OBSERVER_SIGN_APPLE": "true"}, wantExit: 1, wantOut: "must be 1 (on) or unset"},
		{name: "missing p12", unset: []string{"APPLE_DEVELOPER_ID_P12_BASE64"}, wantExit: 1, wantOut: "APPLE_DEVELOPER_ID_P12_BASE64 is not set"},
		{name: "missing p12 password", unset: []string{"APPLE_DEVELOPER_ID_P12_PASSWORD"}, wantExit: 1, wantOut: "APPLE_DEVELOPER_ID_P12_PASSWORD is not set"},
		{name: "missing team id", env: map[string]string{"APPLE_TEAM_ID": ""}, wantExit: 1, wantOut: "APPLE_TEAM_ID is not set"},
		{name: "missing rcodesign", unset: []string{"RCODESIGN"}, wantExit: 1, wantOut: "RCODESIGN is not set"},
		{name: "rcodesign not on disk", env: map[string]string{"RCODESIGN": "/nonexistent/rcodesign"}, wantExit: 1, wantOut: "RCODESIGN is not an executable file"},
		{name: "missing runner temp", unset: []string{"RUNNER_TEMP"}, wantExit: 1, wantOut: "RUNNER_TEMP is not set"},
		{name: "neither key form", env: map[string]string{"APPLE_NOTARY_API_KEY_JSON": ""}, wantExit: 1, wantOut: "no notarization key is set"},
		{name: "both key forms", env: with(raw, map[string]string{"APPLE_NOTARY_API_KEY_JSON": `{"private_key":"` + appleSentinelJSONKey + `"}`}), wantExit: 1, wantOut: "both forms of the notarization key are set"},
		{name: "json beside a raw part", env: map[string]string{"APPLE_NOTARY_KEY_ID": appleKeyID}, wantExit: 1, wantOut: "both forms of the notarization key are set"},
		{name: "raw form without the p8", env: with(raw, map[string]string{"APPLE_NOTARY_KEY_P8": ""}), wantExit: 1, wantOut: "APPLE_NOTARY_KEY_P8 is not set"},
		{name: "raw form without the issuer", env: with(raw, map[string]string{"APPLE_NOTARY_ISSUER_ID": ""}), wantExit: 1, wantOut: "APPLE_NOTARY_ISSUER_ID is not set"},
		{name: "raw form with a malformed key id", env: with(raw, map[string]string{"APPLE_NOTARY_KEY_ID": "short"}), wantExit: 1, wantOut: "10-character Key ID"},
		{name: "p12 not base64", env: map[string]string{"APPLE_DEVELOPER_ID_P12_BASE64": "%%% not base64 %%%"}, wantExit: 1, wantOut: "is not valid base64"},
		{name: "malformed team id", env: map[string]string{"APPLE_TEAM_ID": "abc"}, wantExit: 1, wantOut: "10-character Team ID"},
		{name: "encode fails", env: with(raw, map[string]string{"FAKE_ENCODE_EXIT": "1"}), wantExit: 1, wantOut: "could not encode the notarization key", calls: "encode-app-store-connect-api-key", wantEncode: true},
		{name: "sign fails", env: map[string]string{"FAKE_SIGN_EXIT": "1"}, wantExit: 1, wantOut: "rcodesign could not sign observer", calls: "sign"},
		{name: "verify fails", env: map[string]string{"FAKE_VERIFY_EXIT": "1"}, wantExit: 1, wantOut: "rcodesign verify rejected", calls: "sign\nverify"},
		{name: "no hardened runtime", extra: map[string]string{"info": signatureInfoNoRuntime}, wantExit: 1, wantOut: "lacks the hardened runtime flag", calls: "sign\nverify\nprint-signature-info"},
		{name: "not a Developer ID certificate", extra: map[string]string{"info": signatureInfoNotDevID}, wantExit: 1, wantOut: "not made with a Developer ID Application certificate", calls: "sign\nverify\nprint-signature-info"},
		{name: "wrong team", extra: map[string]string{"info": signatureInfoWrongTeam}, wantExit: 1, wantOut: "does not name team ABCDE12345", calls: "sign\nverify\nprint-signature-info"},
		{name: "notarization Invalid", env: map[string]string{"FAKE_NOTARY_EXIT": "1"}, extra: map[string]string{"notary": notaryInvalid}, wantExit: 1, wantOut: "notarization of observer was not Accepted", calls: "sign\nverify\nprint-signature-info\nnotary-submit\nnotary-log"},
		{name: "notarization times out", env: map[string]string{"FAKE_NOTARY_EXIT": "1"}, extra: map[string]string{"notary": notaryTimeout}, wantExit: 1, wantOut: "notary log for " + appleSubmission, calls: "sign\nverify\nprint-signature-info\nnotary-submit\nnotary-log"},
		{name: "exit 0 without Accepted still fails", extra: map[string]string{"notary": notaryTimeout}, wantExit: 1, wantOut: "was not Accepted", calls: "sign\nverify\nprint-signature-info\nnotary-submit\nnotary-log"},
		{name: "json key form signs and notarizes", wantOut: "observer signed with the Developer ID of team ABCDE12345, notarization Accepted", calls: "sign\nverify\nprint-signature-info\nnotary-submit", wantNotaryOK: true},
		{name: "raw key form encodes, signs and notarizes", env: raw, wantOut: "notarization Accepted", calls: "encode-app-store-connect-api-key\nsign\nverify\nprint-signature-info\nnotary-submit", wantEncode: true, wantNotaryOK: true},
		{name: "entitlements file is passed when present", extra: map[string]string{"entitlements": "<plist/>"}, wantOut: "notarization Accepted", calls: "sign\nverify\nprint-signature-info\nnotary-submit", wantNotaryOK: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := runDarwinSign(t, darwinStep, c.env, c.unset, c.extra)
			if r.code != c.wantExit {
				t.Errorf("exit %d, want %d\n%s", r.code, c.wantExit, r.out)
			}
			if !strings.Contains(r.out, c.wantOut) {
				t.Errorf("output lacks %q:\n%s", c.wantOut, r.out)
			}
			calls, _ := r.log(t, "calls")
			if strings.TrimSpace(calls) != c.calls {
				t.Errorf("rcodesign calls = %q, want %q\n%s", strings.TrimSpace(calls), c.calls, r.out)
			}
			assertNoAppleLeak(t, r)
			if _, ran := r.log(t, "encode-app-store-connect-api-key.args"); ran != c.wantEncode {
				t.Errorf("the encode step ran = %v, want %v", ran, c.wantEncode)
			}
			if c.wantEncode {
				args, _ := r.log(t, "encode-app-store-connect-api-key.args")
				for _, w := range []string{"\n-o\n", "\n" + appleIssuer + "\n", "\n" + appleKeyID + "\n"} {
					if !strings.Contains("\n"+args, w) {
						t.Errorf("encode argv lacks %q:\n%s", strings.TrimSpace(w), args)
					}
				}
				if m, _ := r.log(t, "p8.mode"); strings.TrimSpace(m) != "600" {
					t.Errorf("the .p8 file mode = %q, want 600", strings.TrimSpace(m))
				}
				if _, ok := r.log(t, "p8.content"); !ok {
					t.Error("the .p8 file the encode step read does not hold APPLE_NOTARY_KEY_P8")
				}
			}
			if signRan := strings.HasPrefix(c.calls, "sign") || strings.Contains(c.calls, "\nsign"); signRan {
				for _, f := range []string{"p12.mode", "password.mode"} {
					if m, _ := r.log(t, f); strings.TrimSpace(m) != "600" {
						t.Errorf("%s = %q, want 600", f, strings.TrimSpace(m))
					}
				}
				if m, _ := r.log(t, "dir.mode"); strings.TrimSpace(m) != "700" {
					t.Errorf("the inputs directory mode = %q, want 700", strings.TrimSpace(m))
				}
				for _, f := range []string{"p12.content", "password.content"} {
					if _, ok := r.log(t, f); !ok {
						t.Errorf("%s: the file rcodesign read does not hold the secret's value", f)
					}
				}
				args, _ := r.log(t, "sign.args")
				args = "\n" + args
				for _, w := range []string{
					"\n--code-signature-flags\nruntime\n",
					"\n--for-notarization\n",
					"\n--binary-identifier\napp.superbased.observer\n",
					"\n" + r.target + "\n",
				} {
					if !strings.Contains(args, w) {
						t.Errorf("sign argv lacks %q:\n%s", strings.TrimSpace(w), args)
					}
				}
				_, hasEnt := c.extra["entitlements"]
				if got := strings.Contains(args, "\n--entitlements-xml-file\n"); got != hasEnt {
					t.Errorf("--entitlements-xml-file passed = %v, want %v", got, hasEnt)
				}
			}
			if strings.Contains(c.calls, "notary-submit") {
				args, _ := r.log(t, "notary-submit.args")
				args = "\n" + args
				for _, w := range []string{"\n--api-key-file\n", "\n--wait\n", "\n--max-wait-seconds\n1800\n"} {
					if !strings.Contains(args, w) {
						t.Errorf("notary-submit argv lacks %q:\n%s", strings.TrimSpace(w), args)
					}
				}
				if strings.Contains(args, "--staple") {
					t.Error("notary-submit staples; a bare binary cannot hold a ticket")
				}
				if _, ok := r.log(t, "zip.present"); !ok {
					t.Error("notary-submit was not handed a non-empty zip")
				}
				if m, _ := r.log(t, "key.mode"); strings.TrimSpace(m) != "600" {
					t.Errorf("the notary key file mode = %q, want 600", strings.TrimSpace(m))
				}
				if _, ok := r.log(t, "key.content"); !ok {
					t.Error("the notary key file holds no key")
				}
			}
			if c.wantNotaryOK && !strings.Contains(r.out, "::add-mask::") {
				t.Error("the encoded key's private key was not masked")
			}
		})
	}
}

// TestCodesignDarwinHookRequiresItsInputs runs scripts/codesign.sh darwin
// directly (no sourced inputs): each missing or empty input fails before
// rcodesign runs.
func TestCodesignDarwinHookRequiresItsInputs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the hook runs on the Linux release runner")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not available")
	}
	files := t.TempDir()
	p12 := filepath.Join(files, "p12")
	pw := filepath.Join(files, "pw")
	key := filepath.Join(files, "key.json")
	empty := filepath.Join(files, "empty")
	for path, body := range map[string]string{p12: "p12", pw: "pw\n", key: `{"private_key":"k"}`, empty: ""} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	direct := `set -euo pipefail
"$2" darwin "$TARGET"
`
	inputs := map[string]string{"APPLE_P12_FILE": p12, "APPLE_P12_PASSWORD_FILE": pw, "APPLE_NOTARY_KEY_FILE": key}
	type tc struct {
		name, unset, emptyFile, wantOut string
		noZip                           bool
	}
	cases := []tc{
		{name: "missing p12 file input", unset: "APPLE_P12_FILE", wantOut: "OBSERVER_SIGN_APPLE=1 but APPLE_P12_FILE is not set"},
		{name: "missing password file input", unset: "APPLE_P12_PASSWORD_FILE", wantOut: "APPLE_P12_PASSWORD_FILE is not set"},
		{name: "missing notary key input", unset: "APPLE_NOTARY_KEY_FILE", wantOut: "APPLE_NOTARY_KEY_FILE is not set"},
		{name: "missing team", unset: "APPLE_TEAM_ID", wantOut: "APPLE_TEAM_ID is not set"},
		{name: "missing rcodesign", unset: "RCODESIGN", wantOut: "RCODESIGN is not set"},
		{name: "empty p12 file", emptyFile: "APPLE_P12_FILE", wantOut: "APPLE_P12_FILE does not point at a non-empty file"},
		{name: "empty notary key file", emptyFile: "APPLE_NOTARY_KEY_FILE", wantOut: "APPLE_NOTARY_KEY_FILE does not point at a non-empty file"},
		{name: "zip not installed", noZip: true, wantOut: "zip is not installed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := map[string]string{}
			for k, v := range inputs {
				env[k] = v
			}
			if c.emptyFile != "" {
				env[c.emptyFile] = empty
			}
			var unset []string
			if c.unset != "" {
				unset = append(unset, c.unset)
			}
			script := direct
			if c.noZip {
				for _, d := range []string{"/usr/bin", "/bin"} {
					if _, err := os.Stat(filepath.Join(d, "zip")); err == nil {
						t.Skipf("a real zip is installed in %s; cannot hide it", d)
					}
				}
				script = `rm -f "$(dirname "$RCODESIGN")/zip"
` + direct
			}
			r := runDarwinSign(t, script, env, unset, nil)
			if r.code != 1 {
				t.Errorf("exit %d, want 1\n%s", r.code, r.out)
			}
			if !strings.Contains(r.out, c.wantOut) {
				t.Errorf("output lacks %q:\n%s", c.wantOut, r.out)
			}
			if calls, ok := r.log(t, "calls"); ok {
				t.Errorf("rcodesign ran (%q) before the inputs were complete", strings.TrimSpace(calls))
			}
		})
	}
}

// TestCodesignAppleInputsMustBeSourced: running the inputs script instead of
// sourcing it would export nothing into the step, so it refuses.
func TestCodesignAppleInputsMustBeSourced(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the hook runs on the Linux release runner")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not available")
	}
	r := runDarwinSign(t, `bash "$1"`, nil, nil, nil)
	if r.code != 2 || !strings.Contains(r.out, "do not run it") {
		t.Errorf("running the inputs script: exit %d, output:\n%s", r.code, r.out)
	}
	assertNoAppleLeak(t, r)
}

// TestCodesignAppleScriptsStaticRules: neither script traces, reads a
// GitHub secret expression, or expands a secret value anywhere but the
// printf that writes its file; the hook never staples and pins the
// notarization flags.
func TestCodesignAppleScriptsStaticRules(t *testing.T) {
	root := repoRoot(t)
	hook, err := os.ReadFile(filepath.Join(root, "scripts", "codesign.sh"))
	if err != nil {
		t.Fatal(err)
	}
	inputs, err := os.ReadFile(filepath.Join(root, "scripts", "codesign-apple-inputs.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for name, src := range map[string]string{"codesign.sh": string(hook), "codesign-apple-inputs.sh": string(inputs)} {
		if tracing.MatchString(src) {
			t.Errorf("scripts/%s enables command tracing", name)
		}
		if strings.Contains(src, "secrets.") {
			t.Errorf("scripts/%s references a GitHub secret expression", name)
		}
		for _, line := range strings.Split(src, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			for _, secret := range []string{"APPLE_DEVELOPER_ID_P12_BASE64", "APPLE_DEVELOPER_ID_P12_PASSWORD", "APPLE_NOTARY_API_KEY_JSON", "APPLE_NOTARY_KEY_P8"} {
				if !strings.Contains(line, "$"+secret) && !strings.Contains(line, "${"+secret) {
					continue
				}
				if name == "codesign.sh" {
					t.Errorf("scripts/codesign.sh expands %s; only the inputs script reads the secrets", secret)
				} else if !strings.HasPrefix(trimmed, "if ! printf '%s' \"$"+secret+"\" |") && !strings.HasPrefix(trimmed, "printf '%s\\n' \"$"+secret+"\" >") {
					t.Errorf("scripts/%s expands %s outside the printf that writes its file: %s", name, secret, trimmed)
				}
			}
		}
	}
	src := string(hook)
	for _, want := range []string{
		"--code-signature-flags runtime",
		"--for-notarization",
		`--binary-identifier "$APPLE_BINARY_IDENTIFIER"`,
		`APPLE_BINARY_IDENTIFIER="app.superbased.observer"`,
		"notary-submit --api-key-file \"$APPLE_NOTARY_KEY_FILE\" --wait --max-wait-seconds \"$NOTARY_WAIT_SECONDS\"",
		"NOTARY_WAIT_SECONDS=1800",
		`"$RCODESIGN" verify "$f"`,
		`"$RCODESIGN" print-signature-info "$f"`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("scripts/codesign.sh lacks %q", want)
		}
	}
	for _, banned := range []string{"--staple", "rcodesign staple", `"$RCODESIGN" staple`} {
		if strings.Contains(src, banned) {
			t.Errorf("scripts/codesign.sh staples (%q); a bare binary cannot hold a ticket", banned)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "installer", "macos", "observer.entitlements")); err == nil {
		t.Log("installer/macos/observer.entitlements exists: the hook passes it to rcodesign (ledger CODESIGN-2 must name it)")
	}
}
