package hook

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/hookctx"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/testsupport/jsoncompat"
)

// hookContextEnvKeys are the environment variables the hook path reads
// through the seam (internal/hookctx): the max-runtime and worktree-root
// knobs of cmd/observer, the sandbox marker, the shape log, and the
// account-snapshot override keys.
var hookContextEnvKeys = []string{
	"OBSERVER_HOOK_MAX_RUNTIME", "OBSERVER_CLAUDE_WORKTREE_ROOT", "OBSERVER_SANDBOX", HookShapeLogEnv,
	"OPENAI_API_KEY", "CODEX_API_KEY", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
	"CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY",
}

// fileFact is what one payload-named path yields through each file call.
type fileFact struct {
	ReadErr, ReadSum   string
	StatErr            string
	StatSize           int64
	StatMode           fs.FileMode
	OpenErr, OpenSum   string
	OpenSize, OpenSeek int64
}

// contextFacts is the filled context a hook handler can read: the process
// facts, the environment and every payload-named file.
type contextFacts struct {
	ParentPID int
	Env       map[string]string
	Files     map[string]fileFact
}

func errKind(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, fs.ErrNotExist):
		return "not-exist"
	case errors.Is(err, fs.ErrPermission):
		return "permission"
	default:
		return "other"
	}
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}

// factsOf reads every fact through the given primitives.
func factsOf(ppid func() int, getenv func(string) string, readFile func(string) ([]byte, error),
	stat func(string) (fs.FileInfo, error), open func(string) (io.ReadSeekCloser, fs.FileInfo, error), paths []string,
) contextFacts {
	f := contextFacts{ParentPID: ppid(), Env: map[string]string{}, Files: map[string]fileFact{}}
	for _, k := range hookContextEnvKeys {
		f.Env[k] = getenv(k)
	}
	for _, p := range paths {
		var ff fileFact
		b, err := readFile(p)
		ff.ReadErr, ff.ReadSum = errKind(err), sum(b)
		if st, err := stat(p); err != nil {
			ff.StatErr = errKind(err)
		} else {
			ff.StatSize, ff.StatMode = st.Size(), st.Mode()
		}
		r, st, err := open(p)
		ff.OpenErr = errKind(err)
		if err == nil {
			if st != nil {
				ff.OpenSize = st.Size()
			}
			ff.OpenSeek, _ = r.Seek(0, io.SeekEnd)
			_, _ = r.Seek(0, io.SeekStart)
			b, _ := io.ReadAll(r)
			ff.OpenSum = sum(b)
			_ = r.Close()
		}
		f.Files[p] = ff
	}
	return f
}

// beforeFacts is what the hook read before the seam: the operating system
// directly.
func beforeFacts(paths []string) contextFacts {
	return factsOf(os.Getppid, os.Getenv, os.ReadFile, os.Stat, func(p string) (io.ReadSeekCloser, fs.FileInfo, error) {
		f, err := os.Open(p)
		if err != nil {
			return nil, nil, err
		}
		st, _ := f.Stat()
		return f, st, nil
	}, paths)
}

// afterFacts reads the same facts through a filled hook context.
func afterFacts(c *hookctx.Context, paths []string) contextFacts {
	return factsOf(c.ParentPID, c.Getenv, c.ReadFile, c.Stat, func(p string) (io.ReadSeekCloser, fs.FileInfo, error) {
		f, err := c.Open(p)
		if err != nil {
			return nil, nil, err
		}
		st, _ := f.Stat()
		return f, st, nil
	}, paths)
}

// payloadPaths lists the string values in a payload that name a file
// (absolute, or "~/" relative), expanded the way the readers expand them.
func payloadPaths(body []byte) []string {
	var v any
	if json.Unmarshal(body, &v) != nil {
		return nil
	}
	home, _ := os.UserHomeDir()
	seen := map[string]bool{}
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case map[string]any:
			for _, e := range t {
				walk(e)
			}
		case []any:
			for _, e := range t {
				walk(e)
			}
		case string:
			s := strings.TrimSpace(t)
			if strings.HasPrefix(s, "~/") && home != "" {
				s = filepath.Join(home, s[2:])
			}
			if filepath.IsAbs(s) && !strings.ContainsAny(s, "\n\x00") {
				seen[s] = true
			}
		}
	}
	walk(v)
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// TestHookContextFillEquality is the before/after equality check of the
// seam move (joint roadmap F0-3): over every payload in testdata/ (the
// corpus the hook golden tests use), plus real files the payloads are
// pointed at, the context a handler reads through internal/hookctx (the
// entry point's host context, the host default, and a context carried on
// ctx) equals what the hook read from the operating system directly
// before the seam.
func TestHookContextFillEquality(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	t.Setenv("OBSERVER_HOOK_MAX_RUNTIME", "7s")
	t.Setenv("OBSERVER_CLAUDE_WORKTREE_ROOT", "/worktrees")
	t.Setenv("OBSERVER_SANDBOX", "1")
	t.Setenv("ANTHROPIC_API_KEY", "")
	root, err := jsoncompat.RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	payloads, err := jsoncompat.Payloads(root)
	if err != nil {
		t.Fatal(err)
	}
	// Real files for the success branch: a transcript, an unreadable file
	// and a directory, named by every payload.
	real := filepath.Join(home, "agy", "transcript.jsonl")
	if err := os.MkdirAll(filepath.Dir(real), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(real, []byte(`{"type":"USER_INPUT","content":"<USER_REQUEST>\nhi\n</USER_REQUEST>"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	locked := filepath.Join(home, "locked.json")
	if err := os.WriteFile(locked, []byte("{}"), 0o000); err != nil {
		t.Fatal(err)
	}
	extra := []string{real, locked, filepath.Dir(real)}

	entry := hookctx.Host(context.Background(), hookctx.Request{Tool: "claude-code", Event: "pre-tool"}, hookctx.Source{}, hookctx.HostProviders{})
	carried := hookctx.From(hookctx.WithContext(context.Background(), entry))
	compared := 0
	for _, p := range payloads {
		paths := append(payloadPaths(p.Body), extra...)
		want := beforeFacts(paths)
		for name, c := range map[string]*hookctx.Context{"entry": entry, "default": hookctx.HostDefault(), "carried": carried} {
			if got := afterFacts(c, paths); !reflect.DeepEqual(got, want) {
				t.Errorf("%s via %s: context differs from the direct read\n got %+v\nwant %+v", p.Name, name, got, want)
			}
		}
		compared++
	}
	if compared == 0 {
		t.Fatal("no payloads compared")
	}
	if got, ok := latestAgyUserInput(real); !ok || got != "hi" {
		t.Errorf("latestAgyUserInput through the seam = %q, %v", got, ok)
	}
}

// readAccountFileBefore is readAccountFile as it was before the seam: the
// operating system directly.
func readAccountFileBefore(ctx context.Context, path string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	const maxSize = 2 * 1024 * 1024
	if !info.Mode().IsRegular() || info.Size() > maxSize {
		return nil, fmt.Errorf("unsupported account file")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if len(data) > maxSize {
		return nil, fmt.Errorf("oversized account file")
	}
	return data, err
}

// TestAccountObservationsEquality runs the account-snapshot capture (the
// one hook reader that derives a second file from a payload path) over
// every testdata payload pointed at a real profile, before and after the
// seam, and with an override key set.
func TestAccountObservationsEquality(t *testing.T) {
	home := t.TempDir()
	profile := filepath.Join(home, ".claude")
	transcript := filepath.Join(profile, "projects", "proj", "session.jsonl")
	if err := os.MkdirAll(filepath.Dir(transcript), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"oauthAccount":{"emailAddress":"dev@example.com","displayName":"Dev","accountUuid":"acct-1"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := jsoncompat.RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	payloads, err := jsoncompat.Payloads(root)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()
	for _, override := range []string{"", "ANTHROPIC_API_KEY"} {
		for _, k := range hookContextEnvKeys {
			t.Setenv(k, "")
		}
		if override != "" {
			t.Setenv(override, "set")
		}
		hc := hookctx.From(hookctx.WithContext(ctx, hookctx.Host(ctx, hookctx.Request{}, hookctx.Source{}, hookctx.HostProviders{})))
		found := 0
		for _, p := range payloads {
			var m map[string]any
			if json.Unmarshal(p.Body, &m) != nil {
				continue
			}
			for _, pointed := range []bool{false, true} {
				if pointed {
					m["transcript_path"] = transcript
					if m["tool_use_id"] == nil {
						m["tool_use_id"] = "toolu_1"
					}
					if m["session_id"] == nil {
						m["session_id"] = "s1"
					}
				}
				body, _ := json.Marshal(m)
				for _, event := range []string{"PreToolUse", "Stop", "SessionStart"} {
					before := localAccountObservations(models.ToolClaudeCode, event, body,
						func(path string) ([]byte, error) { return readAccountFileBefore(ctx, path) }, os.Getenv, at)
					after := localAccountObservations(models.ToolClaudeCode, event, body,
						func(path string) ([]byte, error) { return readAccountFile(ctx, hc, path) }, hc.Getenv, at)
					if !reflect.DeepEqual(before, after) {
						t.Errorf("%s pointed=%v %s override=%q: before %+v, after %+v", p.Name, pointed, event, override, before, after)
					}
					found += len(after)
				}
			}
		}
		if override == "" && found == 0 {
			t.Error("no payload produced an observation; the success branch was not compared")
		}
		if override != "" && found != 0 {
			t.Errorf("override %s set, yet %d observations were produced", override, found)
		}
	}
}
