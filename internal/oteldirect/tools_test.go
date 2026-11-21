package oteldirect

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/otlpvendor"
)

// TestToolRowsHaveVendorRows: every tool row reads turns and content through
// an otlpvendor row of the same tool that claims the same service names.
func TestToolRowsHaveVendorRows(t *testing.T) {
	for _, r := range toolRows {
		var found *otlpvendor.Vendor
		for _, v := range otlpvendor.Vendors() {
			if v.Tool == r.Tool {
				v := v
				found = &v
				break
			}
		}
		if found == nil {
			t.Fatalf("tool %q has no otlpvendor row", r.Tool)
		}
		for _, svc := range r.ServiceNames {
			ok := false
			for _, n := range found.ServiceNames {
				ok = ok || n == svc
			}
			if !ok {
				t.Errorf("tool %q: service.name %q is not claimed by its otlpvendor row", r.Tool, svc)
			}
		}
		if len(r.Events) == 0 || len(r.Attrs.Session) == 0 {
			t.Errorf("tool %q: empty vocabulary", r.Tool)
		}
		for ev, kind := range r.Events {
			if _, ok := kindMappers[kind]; !ok {
				t.Errorf("tool %q: event %q has kind %d with no kindMappers row", r.Tool, ev, kind)
			}
		}
		for et, rule := range r.Targets {
			if len(rule.Keys) == 0 {
				t.Errorf("tool %q: target rule %q has no keys", r.Tool, et)
			}
		}
		if got := SourceFileFor(r.Tool); got != "otel:"+r.Tool {
			t.Errorf("SourceFileFor(%q) = %q", r.Tool, got)
		}
	}
}

func TestToolForService(t *testing.T) {
	cases := []struct {
		svc  string
		ok   bool
		tool string
	}{
		{"claude-code", true, "claude-code"},
		{"claude-code-x", false, ""},
		{"codex_exec", false, ""},
		{"", false, ""},
	}
	for _, c := range cases {
		r, ok := ToolForService(c.svc)
		if ok != c.ok || r.Tool != c.tool {
			t.Errorf("ToolForService(%q) = %q %v", c.svc, r.Tool, ok)
		}
	}
	if got := SupportedTools(); len(got) != 1 || got[0] != "claude-code" {
		t.Fatalf("SupportedTools = %v", got)
	}
}

func TestClaudeCodeSurface(t *testing.T) {
	row, _ := ToolForService("claude-code")
	cases := []struct {
		entry      string
		kind, host string
		ok         bool
	}{
		{"cli", models.SurfaceCLI, "claude", true},
		{"claude-vscode", models.SurfaceIDE, "vscode", true},
		{"claude-jetbrains", models.SurfaceIDE, "jetbrains", true},
		{"claude-desktop", models.SurfaceDesktop, "claude-desktop", true},
		{"remote_desktop", models.SurfaceDesktop, "claude-desktop", true},
		{"remote", models.SurfaceWeb, "claude-remote", true},
		{"remote_mobile", models.SurfaceMobile, "claude-mobile", true},
		{"sdk-ts", models.SurfaceSDK, "ts", true},
		{"sdk-", models.SurfaceSDK, "sdk", true},
		{"sdk", models.SurfaceSDK, "sdk", true},
		{"something-new", "", "", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		s, ok := row.surface(c.entry)
		if ok != c.ok || s.Kind != c.kind || s.Host != c.host {
			t.Errorf("surface(%q) = %+v %v, want %s/%s %v", c.entry, s, ok, c.kind, c.host, c.ok)
		}
	}
}

// TestClaudeCodeSurfacesMatchAdapter parses the node adapter's entrypoint
// table (internal/adapter/claudecode/surface.go claudeEntrypointSurface, the
// source of truth this row copies) and fails on any drift.
func TestClaudeCodeSurfacesMatchAdapter(t *testing.T) {
	path := filepath.Join("..", "adapter", "claudecode", "surface.go")
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	surfaceConst := map[string]string{
		"SurfaceCLI": models.SurfaceCLI, "SurfaceIDE": models.SurfaceIDE, "SurfaceDesktop": models.SurfaceDesktop,
		"SurfaceSDK": models.SurfaceSDK, "SurfaceWeb": models.SurfaceWeb, "SurfaceMobile": models.SurfaceMobile,
	}
	adapter := map[string]Surface{}
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok || len(vs.Names) != 1 || vs.Names[0].Name != "claudeEntrypointSurface" || len(vs.Values) != 1 {
			return true
		}
		lit := vs.Values[0].(*ast.CompositeLit)
		for _, el := range lit.Elts {
			kv := el.(*ast.KeyValueExpr)
			key, _ := strconv.Unquote(kv.Key.(*ast.BasicLit).Value)
			var s Surface
			for _, fe := range kv.Value.(*ast.CompositeLit).Elts {
				fkv := fe.(*ast.KeyValueExpr)
				switch fkv.Key.(*ast.Ident).Name {
				case "kind":
					name := fkv.Value.(*ast.SelectorExpr).Sel.Name
					v, known := surfaceConst[name]
					if !known {
						t.Fatalf("adapter uses models.%s, unknown to this test", name)
					}
					s.Kind = v
				case "host":
					s.Host, _ = strconv.Unquote(fkv.Value.(*ast.BasicLit).Value)
				}
			}
			adapter[key] = s
		}
		return false
	})
	if len(adapter) == 0 {
		t.Fatal("claudeEntrypointSurface not found in the adapter")
	}
	row, _ := ToolForService("claude-code")
	if len(adapter) != len(row.Surfaces) {
		t.Errorf("adapter has %d entrypoints, the tool row %d", len(adapter), len(row.Surfaces))
	}
	for k, want := range adapter {
		if got, ok := row.Surfaces[k]; !ok || got != want {
			t.Errorf("entrypoint %q: tool row %+v, adapter %+v", k, got, want)
		}
	}
}
