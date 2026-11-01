package host

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
	trhost "github.com/marmutapp/superbased-observer/internal/toolresolve/host"
)

// Options tunes NewRunner. The zero value is the production runner.
type Options struct {
	// Isolation is handed to the runner as is (nil runs programs directly).
	Isolation extrun.IsolationProvider
	// Executor overrides the default executor.
	Executor *Executor
	// ResolveEnv overrides the toolresolve environment. nil builds one with
	// toolresolve/host.NewEnv on first use (shim exclusion on).
	ResolveEnv func() toolresolve.Env
}

// NewRunner builds the production runner.
func NewRunner(opts Options) *extrun.Runner {
	envFn := opts.ResolveEnv
	if envFn == nil {
		envFn = sync.OnceValue(func() toolresolve.Env { return trhost.NewEnv(trhost.Options{}) })
	}
	ex := opts.Executor
	if ex == nil {
		ex = NewExecutor()
	}
	return &extrun.Runner{
		GOOS: runtime.GOOS,
		Resolve: func(spec integration.BinaryResolveSpec) toolresolve.Resolution {
			return toolresolve.Resolve(spec, envFn())
		},
		Inspect:   Inspect,
		Hash:      HashFile,
		Getenv:    os.LookupEnv,
		Exec:      ex,
		Isolation: opts.Isolation,
	}
}

// Inspect reports what is at path: whether anything is there, whether the
// last component is a symlink, the path with every symlink resolved, and
// whether that is a regular file. A missing path is not an error.
func Inspect(path string) (extrun.FileFacts, error) {
	li, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return extrun.FileFacts{}, nil
	}
	if err != nil {
		return extrun.FileFacts{}, fmt.Errorf("extrun/host.Inspect: %w", err)
	}
	facts := extrun.FileFacts{Exists: true, Symlink: li.Mode()&fs.ModeSymlink != 0}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		// A dangling link: it exists, but resolves to nothing runnable.
		return facts, nil
	}
	fi, err := os.Stat(real)
	if err != nil {
		return facts, nil
	}
	facts.Real = real
	facts.Regular = fi.Mode().IsRegular()
	return facts, nil
}

// HashFile returns the lowercase hex SHA-256 of the file at path.
func HashFile(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the path is a checked absolute program or companion path
	if err != nil {
		return "", fmt.Errorf("extrun/host.HashFile: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("extrun/host.HashFile: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
