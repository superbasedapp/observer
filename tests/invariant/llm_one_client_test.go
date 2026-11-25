package invariant

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// chatPathLiteral is the OpenAI chat-completions path whose appearance in a
// string literal marks code that builds (or routes) such a request.
const chatPathLiteral = "/chat/completions"

// oneClientAllow is the explicit allow-list of non-test Go files outside
// internal/llmwire whose string literals mention the chat-completions path.
// Each row carries its reason; "debt" rows are second OpenAI-compatible
// clients owned by other lanes, listed so they cannot multiply unnoticed.
var oneClientAllow = []struct {
	file   string // slash path relative to the repository root
	reason string
}{
	{"internal/proxy/provider.go", "path matcher: classifies inbound requests, builds none"},
	{"internal/proxy/proxy.go", "path matcher: classifies inbound requests, builds none"},
	{"internal/aigateway/gwhttp/errdialect.go", "path matcher: picks the caller's error dialect from the inbound path, builds no request"},
	{"internal/orgserver/aigwpooled/refusal.go", "path matcher: the pooled front's copy of gwhttp's error-dialect table (the L2 seam ask to export gwhttp's renderer), picks the dialect of a refusal written before the data plane runs, builds no request"},
	{"internal/aigateway/includeusage.go", "path matcher: decides whether a relayed chat-completions stream body gets stream_options.include_usage, builds no request (the pure root cannot import llmwire, which imports net/http)"},
	{"internal/aigateway/appendpoint.go", "path matcher: the one table of provider endpoints the gateway forwards to, their request shapes and the default path for a bare base URL (findings H1 and F-02), builds no request (the pure root cannot import llmwire, which imports net/http)"},
	{"internal/proxy/unknownlane.go", "error text showing an example path to the user"},
	{"internal/agentconfig/catalog_codebuddy.go", "settings catalog description of a foreign tool's config"},
	{"internal/intelligence/dashboard/guard_cloud.go", "validation message showing an example URL"},
	{"internal/orgserver/chat/admin_w5.go", "assistant tool help text"},
	{"internal/cloudserver/foundry/foundry.go", "debt: Azure Foundry deployment URL (Azure dialect, not yet in llmwire)"},
}

// TestOneOpenAICompatibleClient fails when a package outside internal/llmwire
// gains a string literal naming the chat-completions path without an
// allow-list row, and when an allow-list row goes stale.
func TestOneOpenAICompatibleClient(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	allowed := map[string]bool{}
	for _, a := range oneClientAllow {
		allowed[a.file] = false
	}
	for _, top := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if n := d.Name(); n == "node_modules" || n == "testdata" || n == "llmwire" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			src, rerr := os.ReadFile(path)
			if rerr != nil || !bytes.Contains(src, []byte(chatPathLiteral)) {
				return nil // cheap prefilter: parse only files that mention the path
			}
			f, perr := parser.ParseFile(token.NewFileSet(), path, src, parser.SkipObjectResolution)
			if perr != nil {
				return nil
			}
			found := false
			ast.Inspect(f, func(n ast.Node) bool {
				if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING && strings.Contains(lit.Value, chatPathLiteral) {
					found = true
				}
				return !found
			})
			if !found {
				return nil
			}
			if _, ok := allowed[rel]; !ok {
				t.Errorf("%s names %s outside internal/llmwire; use llmwire or add a justified allow-list row", rel, chatPathLiteral)
				return nil
			}
			allowed[rel] = true
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", top, err)
		}
	}
	for file, seen := range allowed {
		if !seen && inPublicTree(root) {
			// The public tree drops the private org server and AI gateway, so
			// their rows have no file to hold the literal there.
			if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(file))); err != nil {
				continue
			}
		}
		if !seen {
			t.Errorf("stale allow-list row %s: no longer contains a %s string literal", file, chatPathLiteral)
		}
	}
}
