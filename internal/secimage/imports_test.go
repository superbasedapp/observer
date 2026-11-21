package secimage

import (
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// TestPure pins the package free of databases, the network, process
// execution, file watching and SCALIBR: its I/O is the reader and the sink
// it is handed (DirSink's os.Root is the one confined writer).
func TestPure(t *testing.T) {
	forbidden := []string{"database/sql", "net", "net/http", "os/exec", "syscall", "github.com/fsnotify/fsnotify"}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), n, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range forbidden {
				if p == bad || strings.HasPrefix(p, bad+"/") && bad != "net" {
					t.Errorf("%s imports %s; secimage is pure apart from its injected reader and sink", n, p)
				}
			}
			if strings.HasPrefix(p, "github.com/google/osv-scalibr") {
				t.Errorf("%s imports %s; only internal/secscan/scalibrfacade may import SCALIBR", n, p)
			}
			if p == "net" || strings.HasPrefix(p, "net/") {
				t.Errorf("%s imports %s; secimage opens no connection", n, p)
			}
		}
	}
}
