package sandboxhcs

import (
	"errors"
	"sort"
	"sync"
)

// loader.go is the OS-independent half of the lazy computecore.dll loader:
// which functions must resolve, and the once-only load with its error
// paths. The real library comes from loader_windows.go; off Windows every
// load fails.

// RequiredProcs are the HCS functions a run needs.
var RequiredProcs = []string{
	"HcsCreateOperation", "HcsCloseOperation", "HcsWaitForOperationResult",
	"HcsCreateComputeSystem", "HcsStartComputeSystem", "HcsTerminateComputeSystem",
	"HcsCloseComputeSystem", "HcsEnumerateComputeSystems",
}

// Library is a loaded DLL: Has reports whether a function resolves.
type Library interface {
	Has(name string) bool
}

// LoaderFacts are a load's outcome for the probe.
type LoaderFacts struct {
	Loaded  bool     `json:"loaded"`
	Err     string   `json:"err,omitempty"`
	Missing []string `json:"missing,omitempty"`
}

// Loader loads the library once and checks the required functions.
type Loader struct {
	open func() (Library, error)
	once sync.Once
	lib  Library
	err  error
}

// NewLoader builds a loader over open (a test passes a fake).
func NewLoader(open func() (Library, error)) *Loader { return &Loader{open: open} }

// ErrNotWindows is the off-Windows load error.
var ErrNotWindows = errors.New("sandboxhcs: computecore.dll exists only on Windows")

// Facts loads the library (once) and reports what resolved.
func (l *Loader) Facts() LoaderFacts {
	l.once.Do(func() {
		if l.open == nil {
			l.err = ErrNotWindows
			return
		}
		l.lib, l.err = l.open()
		if l.err == nil && l.lib == nil {
			l.err = errors.New("sandboxhcs: the loader returned no library")
		}
	})
	if l.err != nil {
		return LoaderFacts{Err: l.err.Error()}
	}
	f := LoaderFacts{Loaded: true}
	for _, p := range RequiredProcs {
		if !l.lib.Has(p) {
			f.Missing = append(f.Missing, p)
		}
	}
	sort.Strings(f.Missing)
	return f
}
