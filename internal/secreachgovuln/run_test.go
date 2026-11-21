//go:build !sbo_omit_security_reach_go && !sbo_omit_security

package secreachgovuln

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/module"
	modzip "golang.org/x/mod/zip"

	"github.com/marmutapp/superbased-observer/internal/secreach"
	"github.com/marmutapp/superbased-observer/internal/secreachgo"
)

// run_test.go is 3b-bin end to end, as RG-0 measured it: a dependency
// module served from a local file:// proxy (no network), a program that
// calls one listed function of it and links another package of it without
// the listed one, built by the local toolchain for linux, windows and
// darwin, plain and stripped, and govulncheck's binary mode over each,
// against the records written as a flat <id>.json directory.

const libMod = "example.com/observer-reach-lib"

var libFiles = map[string]string{
	"go.mod":     "module " + libMod + "\n\ngo 1.21\n",
	"jwt/jwt.go": "package jwt\n\n// Claims are claims.\ntype Claims map[string]any\n\n//go:noinline\nfunc (c Claims) VerifyAudience(s string) bool { return c[\"aud\"] == s }\n\n//go:noinline\nfunc Sign(s string) string { return s + \".sig\" }\n",
	"text/t.go":  "package text\n\n//go:noinline\nfunc Parse(s string) string { return \"p:\" + s }\n\n//go:noinline\nfunc MatchStrings(s string) bool { return s == \"m\" }\n",
}

const appMain = `package main

import (
	"fmt"
	"os"

	"example.com/observer-reach-lib/jwt"
	"example.com/observer-reach-lib/text"
)

func main() {
	c := jwt.Claims{"aud": os.Args[0]}
	fmt.Println(c.VerifyAudience("x"), text.Parse(os.Args[0]))
}
`

// records: GO-2099-0001 lists the called VerifyAudience (called);
// GO-2099-0002 lists MatchStrings of a linked package (not called);
// GO-2099-0003 lists the jwt package with no symbols (package only, no
// claim); GHSA-aaaa-bbbb-cccc is 0001's alias with no imports (rides 0001).
var records = map[string]string{
	"GO-2099-0001":        rec("GO-2099-0001", []string{"GHSA-aaaa-bbbb-cccc"}, `{"path":"`+libMod+`/jwt","symbols":["Claims.VerifyAudience"]}`),
	"GO-2099-0002":        rec("GO-2099-0002", nil, `{"path":"`+libMod+`/text","symbols":["MatchStrings"]}`),
	"GO-2099-0003":        rec("GO-2099-0003", nil, `{"path":"`+libMod+`/jwt"}`),
	"GHSA-aaaa-bbbb-cccc": rec("GHSA-aaaa-bbbb-cccc", []string{"GO-2099-0001"}, ""),
}

func rec(id string, aliases []string, imports string) string {
	al := `[]`
	if len(aliases) > 0 {
		al = `["` + strings.Join(aliases, `","`) + `"]`
	}
	es := ""
	if imports != "" {
		es = `,"ecosystem_specific":{"imports":[` + imports + `]}`
	}
	return `{"schema_version":"1.3.1","id":"` + id + `","modified":"2026-01-01T00:00:00Z","aliases":` + al + `,"summary":"fixture",` +
		`"affected":[{"package":{"ecosystem":"Go","name":"` + libMod + `"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.1"}]}]` + es + `}]}`
}

func toolchainOrSkip(t *testing.T) string {
	t.Helper()
	if testing.Short() || os.Getenv("SBO_SKIP_TOOLCHAIN_TESTS") != "" {
		t.Skip("execs the Go toolchain")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no Go toolchain on PATH")
	}
	return goBin
}

func write(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// proxyDir lays out a GOPROXY=file:// tree serving libMod v1.0.0.
func proxyDir(t *testing.T) string {
	t.Helper()
	src := t.TempDir()
	write(t, src, libFiles)
	proxy := t.TempDir()
	at := filepath.Join(proxy, filepath.FromSlash(libMod), "@v")
	if err := os.MkdirAll(at, 0o700); err != nil {
		t.Fatal(err)
	}
	var zb bytes.Buffer
	if err := modzip.CreateFromDir(&zb, module.Version{Path: libMod, Version: "v1.0.0"}, src); err != nil {
		t.Fatal(err)
	}
	if _, err := zip.NewReader(bytes.NewReader(zb.Bytes()), int64(zb.Len())); err != nil {
		t.Fatal(err)
	}
	write(t, at, map[string]string{
		"list":        "v1.0.0\n",
		"v1.0.0.info": `{"Version":"v1.0.0","Time":"2026-01-01T00:00:00Z"}`,
		"v1.0.0.mod":  libFiles["go.mod"],
	})
	if err := os.WriteFile(filepath.Join(at, "v1.0.0.zip"), zb.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return proxy
}

// build builds the app for goos; ldflags "-s -w" strips it.
func build(t *testing.T, goBin, proxy, goos, ldflags string) string {
	t.Helper()
	app := t.TempDir()
	write(t, app, map[string]string{
		"go.mod":  "module example.com/observer-reach-app\n\ngo 1.21\n\nrequire " + libMod + " v1.0.0\n",
		"main.go": appMain,
	})
	out := filepath.Join(t.TempDir(), "app-"+goos)
	cache := t.TempDir()
	args := []string{"build", "-o", out}
	if ldflags != "" {
		args = append(args, "-ldflags="+ldflags)
	}
	args = append(args, ".")
	proxyURL := filepath.ToSlash(proxy)
	if !strings.HasPrefix(proxyURL, "/") {
		proxyURL = "/" + proxyURL
	}
	cmd := exec.Command(goBin, args...)
	cmd.Dir = app
	cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH=amd64", "CGO_ENABLED=0", "GOFLAGS=-mod=mod -modcacherw", "GOWORK=off",
		"GOPROXY=file://"+proxyURL, "GOSUMDB=off", "GOTOOLCHAIN=local", "GOMODCACHE="+filepath.Join(cache, "mod"))
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build (%s %q): %v\n%s", goos, ldflags, err, b)
	}
	return out
}

func inspect(t *testing.T, bin string) secreachgo.Inspection {
	t.Helper()
	f, err := os.Open(bin)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	return secreachgo.Inspect(f)
}

func dbDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	for id, body := range records {
		if err := os.WriteFile(filepath.Join(d, id+".json"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func verdicts(t *testing.T, bin string) map[string]secreach.SymbolRecord {
	t.Helper()
	var out, errOut bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := Run(ctx, dbDir(t), bin, &out, &errOut); err != nil {
		t.Fatalf("Run: %v\n%s", err, errOut.String())
	}
	traces, err := secreachgo.ParseStream(&out)
	if err != nil {
		t.Fatal(err)
	}
	parsed := map[string]secreachgo.RecordImports{}
	for id, body := range records {
		r, err := secreachgo.ParseRecord([]byte(body))
		if err != nil {
			t.Fatal(err)
		}
		parsed[id] = r
	}
	var advs []secreachgo.Advisory
	for id, r := range parsed {
		advs = append(advs, secreachgo.Advisory{ID: id, Aliases: r.Aliases, Module: libMod, Version: "1.0.0"})
	}
	got := map[string]secreach.SymbolRecord{}
	for _, r := range secreachgo.Verdicts(secreachgo.Input{Advisories: advs, Records: parsed, Traces: traces}) {
		got[r.ID] = r
	}
	return got
}

// TestBinaryModeEndToEnd: an unstripped binary of every format answers
// called and not called exactly as the fixture says; a stripped one is
// refused by Inspect (and would have read every listed function as called).
func TestBinaryModeEndToEnd(t *testing.T) {
	goBin := toolchainOrSkip(t)
	proxy := proxyDir(t)
	want := map[string]secreach.SymbolVerdict{
		"GO-2099-0001":        secreach.VerdictCalled,
		"GHSA-aaaa-bbbb-cccc": secreach.VerdictCalled,
		"GO-2099-0002":        secreach.VerdictNotCalled,
	}
	formats := map[string]secreachgo.Format{"linux": secreachgo.FormatELF, "windows": secreachgo.FormatPE, "darwin": secreachgo.FormatMachO}
	for goos, format := range formats {
		bin := build(t, goBin, proxy, goos, "")
		if in := inspect(t, bin); !in.Checkable || in.Format != format {
			t.Fatalf("%s plain: %+v", goos, in)
		}
		got := verdicts(t, bin)
		if len(got) != len(want) {
			t.Errorf("%s: verdicts %+v, want %v", goos, got, want)
		}
		for id, v := range want {
			if got[id].Verdict != v {
				t.Errorf("%s: %s = %+v, want %q", goos, id, got[id], v)
			}
		}
		if s := got["GO-2099-0001"].Symbol; s != "jwt.Claims.VerifyAudience" {
			t.Errorf("%s: called symbol %q", goos, s)
		}

		stripped := build(t, goBin, proxy, goos, "-s -w")
		if in := inspect(t, stripped); in.Checkable || in.Reason != secreach.ReasonStripped || in.Format != format {
			t.Fatalf("%s stripped: %+v", goos, in)
		}
		// What Inspect protects against: govulncheck itself reads the
		// stripped binary's not-called record as called.
		if goos == "linux" {
			if v := verdicts(t, stripped)["GO-2099-0002"].Verdict; v != secreach.VerdictCalled {
				t.Logf("note: govulncheck on a stripped binary gave %q for the not-called record (RG-0 saw called)", v)
			}
		}
	}
}

func TestArgsAndURL(t *testing.T) {
	abs := filepath.Join(t.TempDir(), "db")
	u, err := DBURL(abs)
	if err != nil || !strings.HasPrefix(u, "file:///") {
		t.Fatalf("DBURL = %q, %v", u, err)
	}
	args, err := Args(u, filepath.Join(abs, "bin"))
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, must := range []string{"-mode binary", "-format json", "-scan symbol", "-db file:///"} {
		if !strings.Contains(joined, must) {
			t.Errorf("args %q lack %q", joined, must)
		}
	}
	for _, never := range []string{"source", "-test", "http"} {
		if strings.Contains(joined, never) {
			t.Errorf("args %q carry %q", joined, never)
		}
	}
	for _, bad := range []string{"https://vuln.go.dev", "file://host/x", "relative/dir", ""} {
		if _, err := Args(bad, "/bin/x"); err == nil {
			t.Errorf("Args accepted database %q", bad)
		}
	}
	if _, err := DBURL("relative"); err == nil {
		t.Error("DBURL accepted a relative directory")
	}
	if _, err := Args(u, "relative"); err == nil {
		t.Error("Args accepted a relative binary")
	}
	if err := Run(context.Background(), "relative", "/bin/x", nil, nil); err == nil {
		t.Error("Run accepted a relative database")
	}
}
