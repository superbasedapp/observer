package treesitter

import (
	"context"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/codeintel/parse"
)

// TestParseHonoursDeadlineOnPathologicalInput is the SR27-A1 regression
// (security review 2026-09-27). A repository file of repeated "(" drives
// tree-sitter's error recovery super-linearly (64 KiB measured ~15 s, 2 MiB
// still running after 8.5 min at 1.8 GB), and the wazero runtime used to
// ignore the caller's deadline, so one hostile file wedged the daemon's
// indexer. A Parse whose context ends must now return promptly with an error,
// and the backend must keep serving afterwards (the aborted instance is
// discarded, not re-pooled).
func TestParseHonoursDeadlineOnPathologicalInput(t *testing.T) {
	if testing.Short() {
		t.Skip("parses a pathological input")
	}
	p, warnings := New()
	if len(warnings) != 0 {
		t.Fatalf("New warnings: %v", warnings)
	}
	hostile := []byte(strings.Repeat("(", 64<<10))

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := p.Parse(ctx, hostile, parse.LangPython, "x.py")
	elapsed := time.Since(start)
	if elapsed > 5*time.Second {
		t.Fatalf("Parse ignored its 500ms deadline: took %s", elapsed)
	}
	if err == nil {
		t.Fatalf("Parse returned no error after its deadline (took %s)", elapsed)
	}

	// The backend still serves a normal file after the aborted call.
	res, err := p.Parse(context.Background(), []byte("def ok():\n    return 1\n"), parse.LangPython, "ok.py")
	if err != nil {
		t.Fatalf("Parse after an aborted call: %v", err)
	}
	if len(res.Nodes) == 0 {
		t.Fatal("Parse after an aborted call produced no nodes")
	}
}

// TestInstancesAreReusedAcrossGC is the SR27-A2 regression. The instance pool
// was a sync.Pool, which drops entries at GC without closing them; wazero keeps
// every instance (and its linear memory) linked in the runtime, so each GC
// leaked one instance per language and memory grew without bound over an
// index pass. The bounded free-list keeps a healthy instance across GC, so a
// sequential parse -> GC -> parse mints exactly one instance.
func TestInstancesAreReusedAcrossGC(t *testing.T) {
	p, warnings := New()
	if len(warnings) != 0 {
		t.Fatalf("New warnings: %v", warnings)
	}
	b := p.(*backend)
	lm := b.modules[parse.LangPython]
	var minted atomic.Int64
	orig := lm.newInst
	lm.newInst = func() *instance {
		minted.Add(1)
		return orig()
	}
	src := []byte("def f():\n    return 2\n")
	for i := 0; i < 5; i++ {
		if _, err := p.Parse(context.Background(), src, parse.LangPython, "f.py"); err != nil {
			t.Fatalf("Parse %d: %v", i, err)
		}
		runtime.GC()
		runtime.GC()
	}
	if n := minted.Load(); n != 1 {
		t.Fatalf("minted %d instances for 5 sequential parses across GC, want 1 (instances dropped at GC leak in the wazero runtime)", n)
	}
}
