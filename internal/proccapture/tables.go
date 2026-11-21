package proccapture

import "strings"

// NormalizeExe folds an executable basename for table matching: lowercase,
// with a trailing ".exe" removed, so "Docker Desktop.exe", "docker desktop"
// and "DOCKER DESKTOP.EXE" are one entry. A path is reduced to its last
// element first (either slash).
func NormalizeExe(name string) string {
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	name = strings.ToLower(strings.TrimSpace(name))
	return strings.TrimSuffix(name, ".exe")
}

// DefaultServiceBasenames is the built-in service table (plan §4.2): programs
// that start long-lived services or GUI apps. A run of one of them is a
// service root (R4); its later subtree is the service's, tracked under a cap
// (R5). Language servers (gopls, tsserver) are deliberately absent: the agent
// drives them, so their children are the agent's work (plan §7). Keys are
// NormalizeExe forms. Extended by [observer.process.capture.services]
// extra_basenames.
var DefaultServiceBasenames = map[string]bool{
	"docker desktop":     true,
	"com.docker.backend": true,
	"code":               true,
	"explorer":           true,
	"devenv":             true,
	"idea64":             true,
}

// foldRule is one row of the fold table (plan §4.3): a run matching it folds
// into its parent (R6). Every row is a test case in tables_test.go.
type foldRule struct {
	// name documents the row (and names its test case).
	name string
	// match reports whether a run with this normalized executable, argv and
	// normalized parent executable folds.
	match func(exe, argv, parentExe string) bool
}

// foldTable is the built-in fold table, walked top-down. Data, not a ladder.
var foldTable = []foldRule{
	{
		name:  "conhost: any",
		match: func(exe, _, _ string) bool { return exe == "conhost" },
	},
	{
		name: "docker cli plugin metadata probe",
		match: func(exe, argv, _ string) bool {
			return strings.HasPrefix(exe, "docker-") && strings.Contains(argv, "docker-cli-plugin-metadata")
		},
	},
	{
		name:  "git credential helper",
		match: func(exe, _, _ string) bool { return strings.HasPrefix(exe, "git-credential-") },
	},
	{
		name:  "docker credential helper",
		match: func(exe, _, _ string) bool { return strings.HasPrefix(exe, "docker-credential-") },
	},
	{
		name:  "wslhost under a captured wsl",
		match: func(exe, _, parentExe string) bool { return exe == "wslhost" && parentExe == "wsl" },
	},
}

// tables is the compiled service and fold tables of one Policy (built-ins
// plus the config extensions).
type tables struct {
	services  map[string]bool
	extraFold map[string]bool
}

func compileTables(cfg Config) tables {
	t := tables{services: make(map[string]bool, len(DefaultServiceBasenames)+len(cfg.ExtraServiceBasenames))}
	for k := range DefaultServiceBasenames {
		t.services[k] = true
	}
	for _, b := range cfg.ExtraServiceBasenames {
		if n := NormalizeExe(b); n != "" {
			t.services[n] = true
		}
	}
	if len(cfg.ExtraFoldBasenames) > 0 {
		t.extraFold = make(map[string]bool, len(cfg.ExtraFoldBasenames))
		for _, b := range cfg.ExtraFoldBasenames {
			if n := NormalizeExe(b); n != "" {
				t.extraFold[n] = true
			}
		}
	}
	return t
}

// isService reports whether exe is in the service table.
func (t tables) isService(exe string) bool {
	return t.services[NormalizeExe(exe)]
}

// foldMatch reports whether a run folds into its parent, and the matching
// row's name.
func (t tables) foldMatch(exe, argv, parentExe string) (string, bool) {
	e, p := NormalizeExe(exe), NormalizeExe(parentExe)
	for _, r := range foldTable {
		if r.match(e, argv, p) {
			return r.name, true
		}
	}
	if t.extraFold[e] {
		return "configured fold basename", true
	}
	return "", false
}
