package policy

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// SDK quickstart plan section 5, ledger SDKQS-8: the SDK's `setup` command
// is not an R-165 verb, because its consent is out of band (the browser
// approval, or a y/N the person answers). That holds only while setup never
// does what R-165 keeps for the person: it never calls an R-165 dashboard
// route (the machine's /api/sdk/credential* among them) and never runs an
// R-165 command (`observer sdk sign-in`, `observer sdk use-key` among them),
// so it cannot be used to route around R-165. This test reads the setup
// modules for those names, taken from the R-165 tables themselves.
//
// The modules are written by the SDK lanes (Python `_setup/`, TypeScript
// `src/setup/`); before they exist the test has nothing to read and says so.

// sdkSetupModuleDirs are the setup modules, from the repository root.
var sdkSetupModuleDirs = []string{
	"sdk/python/superbased_sdk/_setup",
	"sdk/typescript/src/setup",
}

// sdkSetupSourceExts are the source files read in those directories.
var sdkSetupSourceExts = []string{".py", ".ts", ".mts", ".cts", ".js", ".mjs", ".cjs"}

// r165Finding is one R-165 name a setup source carries.
type r165Finding struct {
	what string // the route or the command
	how  string // route | argv | command
}

// r165Scanner holds the patterns built from the R-165 tables.
type r165Scanner struct {
	// literals are setup-cases.json no_r165.forbidden_in_source (lane L0's
	// contract): plain strings no setup source may carry at all.
	literals []string
	routes   []string
	argv     []*regexp.Regexp
	commands []*regexp.Regexp
	names    []string // the command for each argv/commands index
}

// newR165Scanner builds the scanner from selfApprovalVerbs, consentAskVerbs
// and guardGrantRoutes, so a new R-165 row is covered without editing this
// test.
func newR165Scanner() r165Scanner {
	var sc r165Scanner
	for _, r := range guardGrantRoutes {
		sc.routes = append(sc.routes, r.path)
	}
	launchers := []string{`observer`}
	for pkg := range observerPackages {
		launchers = append(launchers, regexp.QuoteMeta(pkg))
	}
	slices.Sort(launchers)
	runner := `(?:(?:npx|pnpx|bunx|uvx|pnpm\s+dlx|yarn\s+dlx|npm\s+exec|pipx\s+run)\s+)?`
	for _, v := range append(append([]selfApprovalVerb{}, selfApprovalVerbs...), consentAskVerbs...) {
		quoted := make([]string, len(v.path))
		words := make([]string, len(v.path))
		for i, w := range v.path {
			quoted[i] = `["']` + regexp.QuoteMeta(w) + `["']`
			words[i] = regexp.QuoteMeta(w)
		}
		// An argument list: "sdk", "sign-in" (Python lists, Node spawn and
		// execFile arrays). A one-word command ("uninstall") is too common a
		// word alone, so its list must start with the launcher.
		if len(quoted) == 1 {
			quoted = append([]string{`["'](?:` + strings.Join(launchers, `|`) + `)["']`}, quoted...)
		}
		sc.argv = append(sc.argv, regexp.MustCompile(strings.Join(quoted, `\s*,\s*`)+`(?:\s*[,\]\)]|\s*$)`))
		// A command line in a string: a literal that starts with the command
		// (optionally through a package runner), or a template literal passed
		// straight to a call. Prose that names the command mid-sentence (for
		// a person to run on a machine with Observer) is not a call.
		cmd := runner + `(?:` + strings.Join(launchers, `|`) + `)\s+` + strings.Join(words, `\s+`) + `(?:\s|["'` + "`" + `]|$)`
		sc.commands = append(sc.commands, regexp.MustCompile(`(?:["']|\(\s*`+"`"+`)`+cmd))
		sc.names = append(sc.names, "observer "+strings.Join(v.path, " "))
	}
	return sc
}

// scan returns every R-165 name src carries.
func (sc r165Scanner) scan(src string) []r165Finding {
	var out []r165Finding
	for _, l := range sc.literals {
		if strings.Contains(src, l) {
			out = append(out, r165Finding{what: l, how: "contract string"})
		}
	}
	for _, r := range sc.routes {
		if strings.Contains(src, r) {
			out = append(out, r165Finding{what: r, how: "route"})
		}
	}
	for i, re := range sc.argv {
		if re.MatchString(src) {
			out = append(out, r165Finding{what: sc.names[i], how: "argv"})
		}
	}
	for i, re := range sc.commands {
		if re.MatchString(src) {
			out = append(out, r165Finding{what: sc.names[i], how: "command"})
		}
	}
	return out
}

// TestR165ScannerRows proves the scanner on the shapes a setup module could
// take, so the module test below is not vacuous.
func TestR165ScannerRows(t *testing.T) {
	t.Parallel()
	sc := newR165Scanner()
	cases := []struct {
		name string
		src  string
		want string // "" for no finding; else the how of one finding
	}{
		{"python argv", `subprocess.run(["observer", "sdk", "sign-in"], check=True)`, "argv"},
		{"python argv, single quotes", `subprocess.run(['observer', 'sdk', 'use-key', '--gateway-url', url])`, "argv"},
		{"node execFile array", `execFileSync("observer", ["sdk", "use-key"], { input: key })`, "argv"},
		{"shell string", `os.system("observer sdk sign-in")`, "command"},
		{"package runner string", `execSync('npx @superbased/observer sdk use-key --gateway-url ' + gw)`, "command"},
		{"template literal command", "execSync(`observer sdk sign-in`)", "command"},
		{"sign-in route", `fetch(node + "/api/sdk/credential", { method: "POST" })`, "route"},
		{"use-key route", `urllib.request.Request(base + "/api/sdk/credential/key", data=body)`, "route"},
		{"another R-165 command", `subprocess.run(["observer", "guard", "disable"])`, "argv"},
		{"another R-165 route", `fetch(base + "/api/guard/approvals")`, "route"},
		// What setup may do.
		{"discovery", `fetch(node + "/api/sdk/destination")`, ""},
		{"apps status", `urlopen(node + "/api/apps/status")`, ""},
		{"apps enable", `post(node + "/api/apps/enable", {"source": "sdk-setup"})`, ""},
		{"trace read", `get(node + "/api/obs/trace/" + trace_id)`, ""},
		{"observer on PATH", `shutil.which("observer")`, ""},
		// Advice prose that names the command is not a call, but lane L0's
		// contract (setup-cases.json no_r165) forbids the string itself.
		{"advice for the person names a contract string", `print("Self-hosted: give the app an admin key in SUPERBASED_API_KEY, or run ` + "`observer sdk sign-in`" + ` on a machine with Observer.")`, "contract string"},
		{"advice worded without the command", `print("Self-hosted: give the app an admin key in SUPERBASED_API_KEY, or sign Observer in on a machine that runs it.")`, ""},
		{"a contract string alone", `const KEY_ROUTE = "/api/agent/sdk-credential/key"`, "contract string"},
		{"sdk status is a read", `subprocess.run(["observer", "sdk", "status"])`, ""},
		{"apps on is not R-165", `subprocess.run(["observer", "apps", "on"])`, ""},
		{"one-word command through the launcher", `subprocess.run(["observer", "uninstall"])`, "argv"},
		{"one-word command name alone", `MANAGERS = {"pip": ["install", "uninstall"]}`, ""},
	}
	sc.literals = []string{"sdk sign-in", "sdk-credential/key"}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := sc.scan(tc.src)
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("want no finding, got %+v", got)
				}
				return
			}
			if !slices.ContainsFunc(got, func(f r165Finding) bool { return f.how == tc.want }) {
				t.Fatalf("want a %s finding, got %+v", tc.want, got)
			}
		})
	}
}

// contractForbiddenInSource reads setup-cases.json no_r165 (lane L0): the
// strings each SDK's own test greps its setup module for. None when the
// contract file is not in the tree.
func contractForbiddenInSource(t *testing.T, root string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "sdk", "contract", "setup-cases.json"))
	if err != nil {
		t.Logf("sdk/contract/setup-cases.json: %v; only the R-165 tables are read", err)
		return nil
	}
	var doc struct {
		NoR165 struct {
			Forbidden []string `json:"forbidden_in_source"`
		} `json:"no_r165"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("setup-cases.json: %v", err)
	}
	return doc.NoR165.Forbidden
}

// TestSDKSetupModulesNameNoR165Verb is the SDKQS-8 check: no SDK setup
// source calls an R-165 route or runs an R-165 command, or carries a string
// the contract forbids.
func TestSDKSetupModulesNameNoR165Verb(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..")
	sc := newR165Scanner()
	sc.literals = contractForbiddenInSource(t, root)
	read := 0
	for _, dir := range sdkSetupModuleDirs {
		abs := filepath.Join(root, filepath.FromSlash(dir))
		if _, err := os.Stat(abs); err != nil {
			t.Logf("%s: not built yet (%v); nothing to read", dir, err)
			continue
		}
		err := filepath.WalkDir(abs, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "node_modules" || d.Name() == "__pycache__" {
					return filepath.SkipDir
				}
				return nil
			}
			if !slices.Contains(sdkSetupSourceExts, filepath.Ext(p)) {
				return nil
			}
			raw, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			read++
			for _, f := range sc.scan(string(raw)) {
				rel, _ := filepath.Rel(root, p)
				t.Errorf("%s names the R-165 %s %q: setup must not call what R-165 keeps for the person (ledger SDKQS-8)", filepath.ToSlash(rel), f.how, f.what)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
	}
	t.Logf("read %d setup source files", read)
}
