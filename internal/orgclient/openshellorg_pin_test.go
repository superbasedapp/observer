package orgclient

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	osorg "github.com/marmutapp/superbased-observer/internal/openshellorg"
)

// TestOpenShellTypesMatchTheServer (fix round 1, A12): every answer and
// request type this client mirrors from lane G2's handlers carries the same
// JSON keys as the server's own struct, read from the server's source (the
// node never imports the server package).
func TestOpenShellTypesMatchTheServer(t *testing.T) {
	server := serverJSONKeys(t, filepath.Join("..", "orgserver", "openshellctl"))
	pairs := []struct {
		server string
		node   any
	}{
		{"MintResponse", OpenShellMint{}},
		{"LoginResponse", OpenShellLogin{}},
		{"PollResponse", OpenShellGrant{}},
		{"endedRequest", OpenShellEnded{}},
		{"endedResponse", OpenShellEndedAnswer{}},
		{"heldBox", OpenShellHeldBox{}},
	}
	for _, p := range pairs {
		want, ok := server[p.server]
		if !ok {
			t.Errorf("the server has no struct %s", p.server)
			continue
		}
		got := nodeJSONKeys(reflect.TypeOf(p.node))
		if !slices.Equal(got, want) {
			t.Errorf("%s: node keys %v, server keys %v", p.server, got, want)
		}
	}
}

func nodeJSONKeys(t reflect.Type) []string {
	var out []string
	for i := 0; i < t.NumField(); i++ {
		if k := jsonKey(t.Field(i).Tag.Get("json"), t.Field(i).Name); k != "" {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

func jsonKey(tag, name string) string {
	if tag == "-" {
		return ""
	}
	if k, _, _ := strings.Cut(tag, ","); k != "" {
		return k
	}
	return name
}

// serverJSONKeys parses every non-test Go file of dir and returns each
// struct type's sorted JSON keys.
func serverJSONKeys(t *testing.T, dir string) map[string][]string {
	t.Helper()
	fset := token.NewFileSet()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no server source in %s: %v", dir, err)
	}
	out := map[string][]string{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(af, func(n ast.Node) bool {
			ts, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				return true
			}
			var keys []string
			for _, fl := range st.Fields.List {
				tag := ""
				if fl.Tag != nil {
					raw, _ := strconv.Unquote(fl.Tag.Value)
					tag = reflect.StructTag(raw).Get("json")
				}
				for _, nm := range fl.Names {
					if k := jsonKey(tag, nm.Name); k != "" {
						keys = append(keys, k)
					}
				}
			}
			slices.Sort(keys)
			out[ts.Name.Name] = keys
			return true
		})
	}
	return out
}

// TestOpenShellMintRequestCarriesNoNodeCIDRs (fix round 1, the 11.4 row "a
// node egress_allow_cidrs that must not reach the compile"): the mint
// request has the core's keys exactly, and none of them can carry a range,
// so the org compile's AllowCIDRs come from the org body only (design 6.1,
// G1-A3) whatever the node's own terminal.sandbox.egress_allow_cidrs says.
func TestOpenShellMintRequestCarriesNoNodeCIDRs(t *testing.T) {
	got := nodeJSONKeys(reflect.TypeOf(OpenShellMintRequest{}))
	want := nodeJSONKeys(reflect.TypeOf(osorg.MintRequest{}))
	if !slices.Equal(got, want) {
		t.Errorf("node keys %v, core keys %v", got, want)
	}
	for _, k := range got {
		if strings.Contains(strings.ToLower(k), "cidr") {
			t.Errorf("the mint request carries %q", k)
		}
	}
}
