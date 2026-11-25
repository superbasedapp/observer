package cacheobs_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/adapter/claudecode"
	"github.com/marmutapp/superbased-observer/internal/adapter/cline"
	"github.com/marmutapp/superbased-observer/internal/adapter/clinecli"
	"github.com/marmutapp/superbased-observer/internal/adapter/codebuddy"
	"github.com/marmutapp/superbased-observer/internal/adapter/commandcode"
	"github.com/marmutapp/superbased-observer/internal/adapter/cowork"
	"github.com/marmutapp/superbased-observer/internal/adapter/deepagents"
	"github.com/marmutapp/superbased-observer/internal/adapter/deepseek"
	"github.com/marmutapp/superbased-observer/internal/adapter/dirac"
	"github.com/marmutapp/superbased-observer/internal/adapter/junie"
	"github.com/marmutapp/superbased-observer/internal/adapter/kimchi"
	"github.com/marmutapp/superbased-observer/internal/adapter/kirocli"
	"github.com/marmutapp/superbased-observer/internal/adapter/muse"
	"github.com/marmutapp/superbased-observer/internal/adapter/openclaw"
	"github.com/marmutapp/superbased-observer/internal/adapter/poolside"
	"github.com/marmutapp/superbased-observer/internal/models"
)

var updateTier2Golden = flag.Bool("update-tier2-golden", false, "rewrite testdata/tier2_canonical_golden.json")

// tier2GoldenPath holds, per case, the observation count, the block count
// and a SHA-256 of the full observation dump (see dumpObservations).
const tier2GoldenPath = "testdata/tier2_canonical_golden.json"

// tier2Golden is one case's pinned result.
type tier2Golden struct {
	Observations int    `json:"observations"`
	Blocks       int    `json:"blocks"`
	SHA256       string `json:"sha256"`
}

// tier2Case parses one adapter fixture through the adapter's public
// ParseSessionFile and returns the resulting cache observations.
type tier2Case struct {
	name  string
	parse func(t *testing.T) []models.CacheTurnObservation
	// implicit marks a case whose every turn is implicit-cache shape, so
	// BlockHashes are cleared by design and only the observation fields
	// are pinned.
	implicit bool
}

// TestTier2CanonicalBytesGolden is the cross-adapter golden for the Tier-2
// cache canonical forms. Every adapter that builds CacheTurnObservation
// rows through cacheobs is parsed end to end from a fixture, and the full
// observation stream (ids, model, usage, flags and, per block, the level,
// kind, role and canonical JSON bytes) is hashed and compared with the
// recorded value. The canonical bytes feed the cachetrack engine's rolling
// chain hash (spec R3), so any byte drift in a shared or per-adapter
// builder fails here, naming the adapter.
//
// Regenerate (only for an intended canonical change, which also changes
// every persisted chain hash for that adapter):
//
//	go test ./internal/adapter/cacheobs/ -run TestTier2CanonicalBytesGolden -update-tier2-golden
func TestTier2CanonicalBytesGolden(t *testing.T) {
	got := map[string]tier2Golden{}
	for _, c := range tier2Cases() {
		obs := c.parse(t)
		dump, blocks := dumpObservations(obs)
		sum := sha256.Sum256([]byte(dump))
		got[c.name] = tier2Golden{Observations: len(obs), Blocks: blocks, SHA256: hex.EncodeToString(sum[:])}
		switch {
		case len(obs) == 0:
			t.Errorf("%s: no observations; the case pins nothing", c.name)
		case c.implicit:
			for _, o := range obs {
				if !o.ImplicitCache {
					t.Errorf("%s: observation %s is not implicit-cache shape", c.name, o.SourceEventID)
				}
			}
		case blocks == 0:
			t.Errorf("%s: no canonical blocks reached the observations; the case pins nothing", c.name)
		}
	}

	if *updateTier2Golden {
		buf, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(tier2GoldenPath, append(buf, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}

	raw, err := os.ReadFile(tier2GoldenPath)
	if err != nil {
		t.Fatalf("read golden (run with -update-tier2-golden to create it): %v", err)
	}
	var want map[string]tier2Golden
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatalf("decode golden: %v", err)
	}
	for name, g := range got {
		w, ok := want[name]
		if !ok {
			t.Errorf("%s: no golden entry", name)
			continue
		}
		if g != w {
			t.Errorf("%s: canonical Tier-2 output drifted\n got  %+v\n want %+v", name, g, w)
		}
	}
	for name := range want {
		if _, ok := got[name]; !ok {
			t.Errorf("%s: golden entry has no case", name)
		}
	}
}

// dumpObservations renders every observation field the adapters control
// (SourceFile excepted: it is a temp path) into a stable text form and
// returns it with the total block count.
func dumpObservations(obs []models.CacheTurnObservation) (string, int) {
	var b strings.Builder
	blocks := 0
	for i, o := range obs {
		fmt.Fprintf(&b, "obs %d event=%q session=%q message=%q ts=%s model=%q fast=%t compaction=%t implicit=%t usage=%+v nilblocks=%t\n",
			i, o.SourceEventID, o.SessionID, o.MessageID, o.Timestamp.UTC().Format(time.RFC3339Nano),
			o.Model, o.Fast, o.CompactionSeen, o.ImplicitCache, o.Usage, o.BlockHashes == nil)
		for _, m := range o.BlockHashes {
			blocks++
			fmt.Fprintf(&b, "  %s|%s|%s|%s\n", m.LevelLabel, m.Kind, m.Role, m.CanonicalBytes)
		}
	}
	return b.String(), blocks
}

// repoTestdata resolves a path under the repository's testdata directory.
func repoTestdata(parts ...string) string {
	return filepath.Join(append([]string{"..", "..", "..", "testdata"}, parts...)...)
}

func readFixture(t *testing.T, parts ...string) []byte {
	t.Helper()
	body, err := os.ReadFile(repoTestdata(parts...))
	if err != nil {
		t.Fatalf("read fixture %v: %v", parts, err)
	}
	return body
}

func writeFile(t *testing.T, path string, body []byte) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// sessionParser is the one method every adapter case calls.
type sessionParser interface {
	ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error)
}

func parseObs(t *testing.T, a sessionParser, path string) []models.CacheTurnObservation {
	t.Helper()
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile(%s): %v", path, err)
	}
	return res.CacheObservations
}

func execSQL(t *testing.T, dbPath string, stmts ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("exec %.60q: %v", s, err)
		}
	}
}

// claudeCompactionSession is a synthetic Claude Code transcript that drives
// the compaction-reset path and a tool_use / tool_result round trip.
const claudeCompactionSession = `{"type":"user","sessionId":"sC","uuid":"u1","timestamp":"2026-06-08T12:00:00.000Z","cwd":"/tmp","message":{"role":"user","content":"Find the handler."}}
{"type":"assistant","sessionId":"sC","uuid":"a1","timestamp":"2026-06-08T12:00:01.000Z","cwd":"/tmp","message":{"id":"msg_a1","role":"assistant","model":"claude-opus-4-7","content":[{"type":"text","text":"Searching."},{"type":"tool_use","id":"tu_1","name":"Grep","input":{"pattern":"func Handle"}}],"usage":{"input_tokens":10,"output_tokens":20,"cache_read_input_tokens":300,"cache_creation_input_tokens":40,"cache_creation":{"ephemeral_5m_input_tokens":30,"ephemeral_1h_input_tokens":10}},"stop_reason":"tool_use"}}
{"type":"user","sessionId":"sC","uuid":"u2","timestamp":"2026-06-08T12:00:02.000Z","cwd":"/tmp","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"tu_1","content":"handler.go:12","is_error":false}]}}
{"type":"attachment","sessionId":"sC","uuid":"att1","timestamp":"2026-06-08T12:00:02.500Z","cwd":"/tmp","message":{"content":[{"type":"text","text":"attached file body"}]}}
{"type":"assistant","sessionId":"sC","uuid":"a2","timestamp":"2026-06-08T12:00:03.000Z","cwd":"/tmp","message":{"id":"msg_a2","role":"assistant","model":"claude-opus-4-7","content":[{"type":"text","text":"Found it."}],"usage":{"input_tokens":5,"output_tokens":7,"cache_read_input_tokens":340,"cache_creation_input_tokens":0,"speed":"fast"},"stop_reason":"end_turn"}}
{"type":"system","subtype":"compact_boundary","uuid":"comp1","sessionId":"sC","cwd":"/tmp","timestamp":"2026-06-08T12:00:04.000Z","compactMetadata":{"trigger":"manual","preTokens":5000}}
{"type":"user","sessionId":"sC","uuid":"u3","timestamp":"2026-06-08T12:00:05.000Z","cwd":"/tmp","message":{"role":"user","content":"Now fix it."}}
{"type":"assistant","sessionId":"sC","uuid":"a3","timestamp":"2026-06-08T12:00:06.000Z","cwd":"/tmp","message":{"id":"msg_a3","role":"assistant","model":"claude-opus-4-7","content":[{"type":"thinking","thinking":"plan the edit"},{"type":"text","text":"Fixed."}],"usage":{"input_tokens":8,"output_tokens":9,"cache_read_input_tokens":0,"cache_creation_input_tokens":500},"stop_reason":"end_turn"}}
`

// openclawSession is a pre-2.0 OpenClaw message log: user text, an
// assistant text + tool call with usage, the tool result, and a second
// assistant turn with usage so the tool result lands in an observation.
const openclawSession = `{"type":"session","id":"sess-golden","cwd":"/tmp/workspace","timestamp":"2026-08-30T10:00:00.000Z"}
{"type":"message","id":"u1","timestamp":"2026-08-30T10:00:01.000Z","message":{"role":"user","content":[{"type":"text","text":"List the files in this repo."}],"timestamp":1787047201000}}
{"type":"message","id":"a1","timestamp":"2026-08-30T10:00:02.000Z","message":{"role":"assistant","provider":"anthropic","model":"claude-sonnet-4","content":[{"type":"text","text":"I'll list them."},{"type":"toolCall","id":"tc1","name":"bash","arguments":{"command":"ls -la"}}],"usage":{"input":120,"output":45,"cacheRead":1000,"cacheWrite":10},"timestamp":1787047202000}}
{"type":"message","id":"r1","timestamp":"2026-08-30T10:00:03.000Z","message":{"role":"toolResult","toolCallId":"tc1","content":[{"type":"text","text":"total 8\ndrwxr-xr-x  2 u u 4096 ."}],"timestamp":1787047203000}}
{"type":"message","id":"a2","timestamp":"2026-08-30T10:00:04.000Z","message":{"role":"assistant","provider":"anthropic","model":"claude-sonnet-4","content":[{"type":"text","text":"One directory entry."}],"usage":{"input":30,"output":6,"cacheRead":1100,"cacheWrite":0},"timestamp":1787047204000}}
`

// kiroConversation is a two-entry conversations_v2 value: a prompt answered
// by a tool call, then the tool result answered by text; both carry tokens.
const kiroConversation = `{"conversation_id":"conv-golden","history":[
 {"user":{"env_context":{"env_state":{"current_working_directory":"/home/dev/project"}},"content":{"Prompt":{"prompt":"list the files"}},"timestamp":null},
  "assistant":{"ToolUse":{"message_id":"m1","content":"","tool_uses":[{"id":"tooluse_1","name":"execute_bash","args":{"command":"ls"}}]}},
  "request_metadata":{"request_id":"r1","message_id":"m1","model_id":"auto","request_start_timestamp_ms":1783571416209,"total_tokens":155,"uncached_input_tokens":100,"output_tokens":40,"cache_read_input_tokens":10,"cache_write_input_tokens":5}},
 {"user":{"env_context":{"env_state":{"current_working_directory":"/home/dev/project"}},"content":{"ToolUseResults":{"tool_use_results":[{"tool_use_id":"tooluse_1","content":[{"Text":"a.go\nb.go"}],"status":"Success"}]}},"timestamp":null},
  "assistant":{"Response":{"message_id":"m2","content":"Two files."}},
  "request_metadata":{"request_id":"r2","message_id":"m2","model_id":"auto","request_start_timestamp_ms":1783571417209,"total_tokens":80,"uncached_input_tokens":20,"output_tokens":10,"cache_read_input_tokens":50,"cache_write_input_tokens":0}}
]}`

var sqliteSequenceCreate = regexp.MustCompile(`(?m)^CREATE TABLE sqlite_sequence\([^)]*\);\s*$`)

func tier2Cases() []tier2Case {
	return []tier2Case{
		{name: "claude-code/gen-timing-real", parse: func(t *testing.T) []models.CacheTurnObservation {
			path := writeFile(t, filepath.Join(t.TempDir(), "session.jsonl"), readFixture(t, "claudecode", "gen-timing-real.jsonl"))
			return parseObs(t, claudecode.New(), path)
		}},
		{name: "claude-code/synthetic-compaction", parse: func(t *testing.T) []models.CacheTurnObservation {
			path := writeFile(t, filepath.Join(t.TempDir(), "session.jsonl"), []byte(claudeCompactionSession))
			return parseObs(t, claudecode.New(), path)
		}},
		{name: "cline", parse: func(t *testing.T) []models.CacheTurnObservation {
			path := writeFile(t, filepath.Join(t.TempDir(), "tasks", "abc123", "api_conversation_history.json"),
				readFixture(t, "cline", "api_conversation_history.json"))
			return parseObs(t, cline.New(), path)
		}},
		{name: "cline-cli", parse: parseClineCLI},
		{name: "cowork", parse: func(t *testing.T) []models.CacheTurnObservation {
			root, err := filepath.Abs(repoTestdata("cowork"))
			if err != nil {
				t.Fatal(err)
			}
			audit := filepath.Join(root, "cowork-aaaa", "dev-bbbb", "local_cccc-dddd-eeee", "audit.jsonl")
			return parseObs(t, cowork.NewWithOptions(nil, root), audit)
		}},
		{name: "command-code", parse: func(t *testing.T) []models.CacheTurnObservation {
			projects := filepath.Join(t.TempDir(), ".commandcode", "projects")
			dir := filepath.Join(projects, "home-user-project")
			path := writeFile(t, filepath.Join(dir, "session.jsonl"), readFixture(t, "commandcode", "session-sample.jsonl"))
			if meta, err := os.ReadFile(repoTestdata("commandcode", "session-sample.meta.json")); err == nil {
				writeFile(t, filepath.Join(dir, "session.meta.json"), meta)
			}
			return parseObs(t, commandcode.NewWithOptions(nil, projects), path)
		}},
		{name: "codebuddy", parse: func(t *testing.T) []models.CacheTurnObservation {
			projects := filepath.Join(t.TempDir(), ".codebuddy", "projects")
			path := writeFile(t, filepath.Join(projects, "home-user-project", "01a15e5d-65aa-751d-80c7-4e7ad26233b3.jsonl"),
				readFixture(t, "codebuddy", "windows-tool-session.jsonl"))
			return parseObs(t, codebuddy.NewWithOptions(nil, projects), path)
		}},
		{name: "dirac/linux", parse: func(t *testing.T) []models.CacheTurnObservation {
			// The fixture's openai-codex provider makes every turn
			// implicit-cache, which clears BlockHashes; renaming the provider
			// keeps the blocks so the canonical bytes are pinned.
			return parseDirac(t, "linux", "1792563515376", `"providerId":"golden-provider"`)
		}},
		{name: "dirac/windows", implicit: true, parse: func(t *testing.T) []models.CacheTurnObservation {
			return parseDirac(t, "windows", "1792563501436", "")
		}},
		{name: "poolside", parse: func(t *testing.T) []models.CacheTurnObservation {
			const name = "trajectory-standalone_11111111-2222-7333-8444-555555555555.ndjson"
			root := filepath.Join(t.TempDir(), "poolside", "trajectories")
			path := writeFile(t, filepath.Join(root, name), readFixture(t, "poolside", name))
			return parseObs(t, poolside.NewWithOptions(nil, root), path)
		}},
		{name: "muse", parse: func(t *testing.T) []models.CacheTurnObservation {
			root := filepath.Join(t.TempDir(), "muse", "sessions")
			path := writeFile(t, filepath.Join(root, "2026", "08", "06", "11111111-2222-3333-4444-555555555555", "session.jsonl"),
				readFixture(t, "muse", "simple-session.jsonl"))
			return parseObs(t, muse.NewWithOptions(nil, root), path)
		}},
		{name: "openclaw", parse: func(t *testing.T) []models.CacheTurnObservation {
			root := t.TempDir()
			path := writeFile(t, filepath.Join(root, "agents", "main", "sessions", "sess-golden.jsonl"), []byte(openclawSession))
			return parseObs(t, openclaw.NewWithOptions(nil, []string{root}), path)
		}},
		{name: "kiro-cli", parse: func(t *testing.T) []models.CacheTurnObservation {
			dir := t.TempDir()
			dbPath := filepath.Join(dir, ".local", "share", "kiro-cli", "data.sqlite3")
			value := strings.ReplaceAll(kiroConversation, "'", "''")
			execSQL(t, dbPath,
				`CREATE TABLE conversations_v2 (key TEXT NOT NULL, conversation_id TEXT NOT NULL, value TEXT NOT NULL,
					created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (key, conversation_id))`,
				`INSERT INTO conversations_v2 VALUES ('/home/dev/project', 'conv-golden', '`+value+`', 1, 100)`)
			return parseObs(t, kirocli.NewWithOptions(nil, dir), dbPath)
		}},
		{name: "junie", parse: func(t *testing.T) []models.CacheTurnObservation {
			root := filepath.Join(t.TempDir(), ".junie", "sessions")
			path := writeFile(t, filepath.Join(root, "session-260816-220304-lrfz", "events.jsonl"),
				readFixture(t, "junie", "session-260816-220304-lrfz", "events.jsonl"))
			writeFile(t, filepath.Join(root, "index.jsonl"), readFixture(t, "junie", "index.jsonl"))
			return parseObs(t, junie.NewWithOptions(nil, root), path)
		}},
		{name: "deepagents", parse: func(t *testing.T) []models.CacheTurnObservation {
			root := filepath.Join(t.TempDir(), ".deepagents", ".state")
			dbPath := filepath.Join(root, "sessions.db")
			execSQL(t, dbPath, "BEGIN;\n"+string(readFixture(t, "deepagents", "fixture.sql"))+"\nCOMMIT;")
			return parseObs(t, deepagents.NewWithOptions(nil, []string{root}), dbPath)
		}},
		{name: "kimchi", parse: func(t *testing.T) []models.CacheTurnObservation {
			// The fixture's OpenAI-wire `api` makes every turn implicit-cache,
			// which clears BlockHashes; renaming the wire keeps the blocks so
			// the canonical bytes are pinned.
			body := strings.ReplaceAll(string(readFixture(t, "kimchi", "session-wsl.jsonl")), `"api":"openai-`, `"api":"golden-`)
			root := filepath.Join(t.TempDir(), ".config", "kimchi", "harness", "sessions")
			path := writeFile(t, filepath.Join(root, "--home-user-proj--", "2026-10-21T06-40-31-166Z_01a15d30-a3bd-7702-b5d5-f25eb07c1348.jsonl"), []byte(body))
			return parseObs(t, kimchi.NewWithOptions(nil, root), path)
		}},
		{name: "deepseek", parse: func(t *testing.T) []models.CacheTurnObservation {
			root := filepath.Join(t.TempDir(), ".dsh", "sessions")
			path := writeFile(t, filepath.Join(root, "--work-project--", "session-019f1111-2222-7333-8444-555555555555", "session.jsonl.zstd"),
				readFixture(t, "deepseek", "session.jsonl.zstd"))
			return parseObs(t, deepseek.NewWithOptions(nil, root), path)
		}},
	}
}

// parseDirac copies testdata/dirac/<layout>/data into a temp .dirac/data
// tree and parses the task's operation log. A non-empty provider replaces
// the operation logs' openai-codex providerId.
func parseDirac(t *testing.T, layout, taskID, provider string) []models.CacheTurnObservation {
	t.Helper()
	src := repoTestdata("dirac", layout, "data")
	dst := filepath.Join(t.TempDir(), ".dirac", "data")
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		out := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(out, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if provider != "" && d.Name() == "api_conversation_history.jsonl" {
			b = []byte(strings.ReplaceAll(string(b), `"providerId":"openai-codex"`, provider))
		}
		return os.WriteFile(out, b, 0o600)
	})
	if err != nil {
		t.Fatalf("copy dirac fixture: %v", err)
	}
	root := filepath.Join(dst, "tasks")
	return parseObs(t, dirac.NewWithOptions(nil, root), filepath.Join(root, taskID, "api_conversation_history.jsonl"))
}

// parseClineCLI builds the cline-cli data dir (sessions.db with the live
// capture's session row, plus its messages.json) and parses the database.
func parseClineCLI(t *testing.T) []models.CacheTurnObservation {
	t.Helper()
	const sessionID = "1780701711502_0v8d2"
	dataDir := filepath.Join(t.TempDir(), "data")
	dbPath := filepath.Join(dataDir, "db", "sessions.db")
	msgPath := writeFile(t, filepath.Join(dataDir, "sessions", sessionID, sessionID+".messages.json"),
		readFixture(t, "clinecli", "sample-session-messages.json"))
	schema := sqliteSequenceCreate.ReplaceAllString(string(readFixture(t, "clinecli", "sessions.sql")), "")
	insert := fmt.Sprintf(`INSERT INTO sessions (session_id, source, pid, started_at, status, interactive, provider, model,
		cwd, workspace_root, enable_tools, enable_spawn, enable_teams, hook_path, messages_path, updated_at)
		VALUES ('%s', 'cli', 42032, '2026-06-05T23:21:51.502Z', 'idle', 1, 'cline', 'deepseek/deepseek-v4-flash',
		'/home/dev/proj', '/home/dev/proj', 1, 1, 1, '', '%s', '2026-06-05T23:28:30.654Z')`,
		sessionID, strings.ReplaceAll(msgPath, "'", "''"))
	execSQL(t, dbPath, schema, insert)
	return parseObs(t, clinecli.New(), dbPath)
}
