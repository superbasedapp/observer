package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// launcherInject is one launcher's `--continue-from` seed, read from source.
type launcherInject struct {
	kind string // the promptInjectKind identifier
	flag string
	file string
}

// launcherInjectsFromSource parses every non-test file of this package and
// returns, per tool, the promptInjection literal of its continueFromParams
// (tool must be a string literal there).
func launcherInjectsFromSource(t *testing.T) map[string]launcherInject {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]launcherInject{}
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(src), "continueFromParams{") {
			continue
		}
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			if id, ok := lit.Type.(*ast.Ident); !ok || id.Name != "continueFromParams" {
				return true
			}
			var tool string
			var inj launcherInject
			for _, el := range lit.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, _ := kv.Key.(*ast.Ident)
				if key == nil {
					continue
				}
				switch key.Name {
				case "tool":
					if bl, ok := kv.Value.(*ast.BasicLit); ok && bl.Kind == token.STRING {
						tool, _ = strconv.Unquote(bl.Value)
					}
				case "inject":
					if il, ok := kv.Value.(*ast.CompositeLit); ok {
						inj = injectFromLiteral(il)
					}
				}
			}
			if tool != "" && inj.kind != "" {
				inj.file = name
				out[tool] = inj
			}
			return true
		})
	}
	return out
}

// injectFromLiteral reads Kind and Flag from a promptInjection literal.
func injectFromLiteral(lit *ast.CompositeLit) launcherInject {
	var inj launcherInject
	for _, el := range lit.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, _ := kv.Key.(*ast.Ident)
		if key == nil {
			continue
		}
		switch key.Name {
		case "Kind":
			if id, ok := kv.Value.(*ast.Ident); ok {
				inj.kind = id.Name
			}
		case "Flag":
			if bl, ok := kv.Value.(*ast.BasicLit); ok && bl.Kind == token.STRING {
				inj.flag, _ = strconv.Unquote(bl.Value)
			}
		}
	}
	return inj
}

// injectKindSeed maps a launcher's injection kind to the task-seed kind it
// grounds (the after-dash-dash kind grounds none: see integration taskSeeds).
var injectKindSeed = map[string]integration.TaskSeedKind{
	"injectLeadingPositional":               integration.TaskSeedLeadingPositional,
	"injectTrailingPositional":              integration.TaskSeedTrailingPositional,
	"injectFlagValue":                       integration.TaskSeedFlag,
	"injectTrailingPositionalAfterDashDash": integration.TaskSeedNone,
}

// TestTaskSeedMatchesLauncherInjection pins integration.TaskSeedFor to the
// launchers: a tool's task seed is the shape its own `--continue-from` path
// injects a handover with, unless the row carries a Note saying why a fresh
// launch cannot use it. Every launcher literal is covered, and every seeded
// table row has a launcher literal behind it.
func TestTaskSeedMatchesLauncherInjection(t *testing.T) {
	injects := launcherInjectsFromSource(t)
	if len(injects) < 20 {
		t.Fatalf("found %d continueFromParams literals; the source scan is broken", len(injects))
	}
	for tool, inj := range injects {
		want, known := injectKindSeed[inj.kind]
		if !known {
			t.Errorf("%s (%s): unknown injection kind %s; add it to injectKindSeed", tool, inj.file, inj.kind)
			continue
		}
		seed := integration.TaskSeedFor(tool)
		if !seed.Seeds() {
			if seed.Note == "" && want != integration.TaskSeedNone {
				t.Errorf("%s (%s): launcher seeds %s but the task seed table has no seed and no Note", tool, inj.file, inj.kind)
			}
			continue
		}
		if seed.Kind != want || seed.Flag != inj.flag {
			t.Errorf("%s (%s): task seed %q %q, launcher injects %s %q", tool, inj.file, seed.Kind, seed.Flag, inj.kind, inj.flag)
		}
	}
	for _, c := range integration.Capabilities() {
		seed := integration.TaskSeedFor(c.Tool)
		if !seed.Seeds() {
			continue
		}
		if _, ok := injects[c.Tool]; !ok {
			t.Errorf("%s: task seed %q with no launcher continueFromParams literal behind it", c.Tool, seed.Kind)
		}
	}
}

// TestTaskSeedSurvivesLauncherArgSplit proves the argv the daemon composes
// for a seeded fresh launch (`observer <x> <tool args> <seed>`) reaches the
// tool unchanged through the launcher's own flag split: the seed flag is not
// one the launcher reserves, and the prompt is forwarded intact.
func TestTaskSeedSurvivesLauncherArgSplit(t *testing.T) {
	prompt := "Fix these Code security findings.\nRead the facts below."
	for _, c := range integration.Capabilities() {
		seed := integration.TaskSeedFor(c.Tool)
		if !seed.Seeds() || !c.Handoff.Launchable() {
			continue
		}
		t.Run(c.Tool, func(t *testing.T) {
			root := newRootCmd()
			sub, _, err := root.Find([]string{c.Handoff.Launch.Subcommand})
			if err != nil || sub == root {
				t.Fatalf("launcher %q not found: %v", c.Handoff.Launch.Subcommand, err)
			}
			args, err := integration.TaskSeedArgs(seed, []string{"--sbo-unreserved-test-flag"}, prompt)
			if err != nil {
				t.Fatal(err)
			}
			got, err := splitLauncherArgs(sub, args)
			if err != nil {
				t.Fatalf("split: %v", err)
			}
			if !reflect.DeepEqual(got, args) {
				t.Fatalf("launcher forwarded %q, want %q (a seed token is reserved by observer %s)", got, args, c.Handoff.Launch.Subcommand)
			}
		})
	}
}
