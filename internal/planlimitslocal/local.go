package planlimitslocal

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	_ "modernc.org/sqlite" // read-only SQLite driver (pure Go)

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/planlimits"
)

// maxRead caps one local read.
const maxRead = 1 << 20

// Reader resolves and reads vendor-local files.
type Reader struct {
	// Getenv reads the environment (tests). Defaults to os.Getenv.
	Getenv func(string) string
	// Home returns the home directory (tests). Defaults to os.UserHomeDir.
	Home func() (string, error)
	// ConfigDir returns the per-OS config directory (tests). Defaults to
	// os.UserConfigDir.
	ConfigDir func() (string, error)
}

func (r Reader) getenv(k string) string {
	if r.Getenv != nil {
		return r.Getenv(k)
	}
	return os.Getenv(k)
}

func (r Reader) home() (string, error) {
	if r.Home != nil {
		return r.Home()
	}
	return os.UserHomeDir()
}

func (r Reader) config() (string, error) {
	if r.ConfigDir != nil {
		return r.ConfigDir()
	}
	return os.UserConfigDir()
}

// base resolves a LocalSpec base to a directory.
func (r Reader) base(b string) (string, error) {
	switch b {
	case planlimits.BaseHome:
		return r.home()
	case planlimits.BaseConfig:
		return r.config()
	case planlimits.BaseCodexHome:
		if v := strings.TrimSpace(r.getenv("CODEX_HOME")); v != "" {
			return v, nil
		}
		h, err := r.home()
		return filepath.Join(h, ".codex"), err
	case planlimits.BaseClaudeHome:
		// The one Claude config directory resolver (FU-131, FU-138):
		// CLAUDE_CONFIG_DIR, then ANTHROPIC_CONFIG_DIR, then ~/.claude; a
		// relative value names no directory.
		h, herr := r.home()
		if herr != nil {
			h = ""
		}
		dir, refused := agentconfig.ClaudeConfigDir(agentconfig.PathEnv{GOOS: runtime.GOOS, Home: h, Getenv: r.getenv})
		if refused != "" {
			return "", fmt.Errorf("%w: %s is set to a relative path", planlimits.ErrUnavailable, refused)
		}
		if dir == "" {
			return "", herr
		}
		return dir, nil
	}
	return "", fmt.Errorf("planlimitslocal: unknown base %q", b)
}

// Path resolves a spec to an absolute path. The relative part must stay
// inside its base.
func (r Reader) Path(s planlimits.LocalSpec) (string, error) {
	dir, err := r.base(s.Base)
	if err != nil || dir == "" {
		return "", fmt.Errorf("%w: no %s directory", planlimits.ErrUnavailable, s.Base)
	}
	rel := filepath.FromSlash(s.Rel)
	if rel == "" || filepath.IsAbs(rel) || strings.HasPrefix(filepath.Clean(rel), "..") {
		return "", fmt.Errorf("planlimitslocal: bad relative path %q", s.Rel)
	}
	segs := strings.Split(s.Rel, "/")
	star := -1
	for i, seg := range segs {
		switch {
		case seg == "*" && star < 0:
			star = i
		case seg == ".." || strings.ContainsAny(seg, "*?["):
			// One whole-segment wildcard at most; no partial patterns.
			return "", fmt.Errorf("planlimitslocal: bad relative path %q", s.Rel)
		}
	}
	if star < 0 {
		return filepath.Join(dir, rel), nil
	}
	return newestMatch(dir, segs[:star], segs[star+1:])
}

// newestMatch resolves one "*" path segment (a vendor's per-product,
// per-version folder such as JetBrains/IntelliJIdea2026.2) to the match
// whose file was modified most recently. No match is ErrUnavailable.
func newestMatch(dir string, before, after []string) (string, error) {
	parent := filepath.Join(append([]string{dir}, before...)...)
	entries, err := os.ReadDir(parent)
	if err != nil {
		return "", fmt.Errorf("%w: file not found", planlimits.ErrUnavailable)
	}
	best, bestAt := "", int64(0)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		p := filepath.Join(append([]string{parent, e.Name()}, after...)...)
		fi, err := os.Stat(p)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		if t := fi.ModTime().UnixNano(); best == "" || t > bestAt {
			best, bestAt = p, t
		}
	}
	if best == "" {
		return "", fmt.Errorf("%w: file not found", planlimits.ErrUnavailable)
	}
	return best, nil
}

// Read performs every spec of a source and returns the bytes by key. The
// first failure is returned (ErrUnavailable when the vendor app is not here).
func (r Reader) Read(ctx context.Context, specs []planlimits.LocalSpec) (map[string][]byte, error) {
	out := map[string][]byte{}
	for _, s := range specs {
		p, err := r.Path(s)
		if err != nil {
			return out, err
		}
		var b []byte
		switch s.Kind {
		case planlimits.LocalFile:
			b, err = readFile(p)
		case planlimits.LocalSQLiteKV:
			b, err = readItem(ctx, p, s.Item)
		default:
			err = fmt.Errorf("planlimitslocal: unknown kind %q", s.Kind)
		}
		if err != nil {
			return out, err
		}
		out[s.Key] = b
	}
	return out, nil
}

// readFile reads a regular file, read-only, capped.
func readFile(p string) ([]byte, error) {
	fi, err := os.Stat(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: file not found", planlimits.ErrUnavailable)
	}
	if err != nil || !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: file not readable", planlimits.ErrUnavailable)
	}
	f, err := os.Open(p) //nolint:gosec // G304: a registry-defined vendor path under a resolved base, read-only
	if err != nil {
		return nil, fmt.Errorf("%w: file not readable", planlimits.ErrUnavailable)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxRead+1))
	if err != nil || len(b) > maxRead {
		return nil, fmt.Errorf("%w: file not readable", planlimits.ErrUnavailable)
	}
	return b, nil
}

// readItem reads one ItemTable value from a VS Code style state.vscdb,
// opened read-only.
func readItem(ctx context.Context, p, key string) ([]byte, error) {
	if _, err := os.Stat(p); err != nil {
		return nil, fmt.Errorf("%w: app state not found", planlimits.ErrUnavailable)
	}
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(p), RawQuery: "mode=ro&_pragma=busy_timeout(2000)"}
	dsn := u.String()
	if !strings.HasPrefix(filepath.ToSlash(p), "/") { // a Windows drive path
		dsn = "file:" + filepath.ToSlash(p) + "?" + u.RawQuery
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("%w: app state not readable", planlimits.ErrUnavailable)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var v any
	err = db.QueryRowContext(ctx, `SELECT value FROM ItemTable WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: the app has no saved sign-in", planlimits.ErrAuth)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: app state not readable", planlimits.ErrUnavailable)
	}
	var b []byte
	switch t := v.(type) {
	case []byte:
		b = t
	case string:
		b = []byte(t)
	default:
		return nil, fmt.Errorf("%w: app state value", planlimits.ErrShape)
	}
	if len(b) > maxRead {
		return nil, fmt.Errorf("%w: app state value too large", planlimits.ErrShape)
	}
	return b, nil
}
