package extruntest

import (
	"context"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/extrun"
)

// Executor records every plan it is handed and answers with Facts.
type Executor struct {
	// Plat is returned by Platform. The zero value enforces every cap.
	Plat *extrun.Platform
	// Facts answers one plan; nil answers a clean exit 0.
	Facts func(extrun.Plan) extrun.ExecFacts

	mu    sync.Mutex
	calls []extrun.Plan
}

// Platform returns Plat, or a platform that enforces every cap.
func (e *Executor) Platform() extrun.Platform {
	if e.Plat != nil {
		return *e.Plat
	}
	return extrun.Platform{GOOS: "linux", Caps: map[extrun.Cap]extrun.CapState{
		extrun.CapWall: extrun.CapEnforced, extrun.CapStdout: extrun.CapEnforced, extrun.CapStderr: extrun.CapEnforced,
		extrun.CapMemory: extrun.CapEnforced, extrun.CapChildren: extrun.CapEnforced,
		extrun.CapCPU: extrun.CapEnforced, extrun.CapFileSize: extrun.CapEnforced,
	}}
}

// Exec records p and returns the scripted facts.
func (e *Executor) Exec(_ context.Context, p extrun.Plan) extrun.ExecFacts {
	e.mu.Lock()
	e.calls = append(e.calls, p)
	e.mu.Unlock()
	if e.Facts != nil {
		return e.Facts(p)
	}
	return extrun.ExecFacts{PeakChildren: -1}
}

// Calls returns a copy of every plan handed to Exec, in order.
func (e *Executor) Calls() []extrun.Plan {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]extrun.Plan(nil), e.calls...)
}

// File is one entry of the in-memory file table.
type File struct {
	// LinkTo makes the entry a symlink to another entry.
	LinkTo string
	// Dir marks a directory.
	Dir bool
	// Digest is what Hash returns; empty means "sha256-of:" + path.
	Digest string
}

// Files is an in-memory file table keyed by absolute path.
type Files map[string]File

// Inspect reports what is at path, following LinkTo chains (up to 8 hops).
func (fs Files) Inspect(path string) (extrun.FileFacts, error) {
	f, ok := fs[path]
	if !ok {
		return extrun.FileFacts{}, nil
	}
	facts := extrun.FileFacts{Exists: true, Symlink: f.LinkTo != ""}
	real := path
	for hops := 0; f.LinkTo != "" && hops < 8; hops++ {
		real = f.LinkTo
		if f, ok = fs[real]; !ok {
			return facts, nil
		}
	}
	if f.LinkTo != "" {
		return facts, nil
	}
	facts.Real = real
	facts.Regular = !f.Dir
	return facts, nil
}

// Hash returns the entry's Digest, or "sha256-of:" + path.
func (fs Files) Hash(path string) (string, error) {
	if f, ok := fs[path]; ok && f.Digest != "" {
		return f.Digest, nil
	}
	return "sha256-of:" + path, nil
}

// NewRunner returns a Runner over the file table and executor, for goos,
// reading the daemon environment from env.
func NewRunner(goos string, files Files, ex *Executor, env map[string]string) *extrun.Runner {
	return &extrun.Runner{
		GOOS:    goos,
		Inspect: files.Inspect,
		Hash:    files.Hash,
		Getenv: func(name string) (string, bool) {
			v, ok := env[name]
			return v, ok
		},
		Exec: ex,
	}
}
