package cursor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

const (
	cliUsageSession = "94c12bab-0f05-41b5-bf78-cf6f1e94b61a"
	cliUsageRequest = "6904f178-1ee4-4ed0-a4aa-9ca8882d1c07"
)

// These metadata values were compared with the unmodified CLI's successful
// stream-json result on 2026-09-09. No prompts/account data belong in this fixture.
func cliUsageLine(t *testing.T, mutate func(map[string]string)) string {
	t.Helper()
	m := map[string]string{"conversation_id": cliUsageSession, "request_id": cliUsageRequest, "surface": "headless", "outcome": "success", "retries_attempted": "0", "input_tokens": "6263", "output_tokens": "39", "cache_read_tokens": "8014", "cache_write_tokens": "0"}
	if mutate != nil {
		mutate(m)
	}
	b, err := json.Marshal(map[string]any{"key": "agent_cli", "message": "agent_cli.turn.outcome", "metadata": m})
	if err != nil {
		t.Fatal(err)
	}
	return "[2026-09-09T10:37:43.783Z] structured-log.info " + string(b) + "\n"
}

func TestParseCLIUsageOutcome(t *testing.T) {
	for _, tc := range []struct {
		name        string
		change      func(map[string]string)
		want        bool
		reliability string
	}{
		{"real_success", nil, true, models.ReliabilityAccurate},
		{"real_final_retry", func(m map[string]string) {
			m["retries_attempted"] = "3"
			m["outcome"] = "error"
			m["input_tokens"] = "29"
			m["output_tokens"] = "5"
			m["cache_read_tokens"] = "16352"
		}, true, models.ReliabilityUnreliable},
		{"recorded_zero", func(m map[string]string) {
			for _, k := range []string{"input_tokens", "output_tokens", "cache_read_tokens"} {
				m[k] = "0"
			}
		}, true, models.ReliabilityAccurate},
		{"missing_field", func(m map[string]string) { delete(m, "input_tokens") }, false, ""},
		{"negative", func(m map[string]string) { m["output_tokens"] = "-1" }, false, ""},
		{"overflow", func(m map[string]string) { m["input_tokens"] = "9223372036854775808" }, false, ""},
		{"interactive", func(m map[string]string) { m["surface"] = "terminal" }, false, ""},
		{"unsafe_id", func(m map[string]string) { m["conversation_id"] = "../another-session" }, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev, ok := parseCLIOutcome(cliUsageLine(t, tc.change))
			if ok != tc.want {
				t.Fatalf("accepted=%v want=%v", ok, tc.want)
			}
			if !ok {
				return
			}
			if ev.Reliability != tc.reliability || ev.MessageID != cliUsageRequest || ev.SessionID != cliUsageSession {
				t.Fatalf("bad event: %+v", ev)
			}
			if tc.name == "real_success" && (ev.InputTokens != 6263 || ev.OutputTokens != 39 || ev.CacheReadTokens != 8014) {
				t.Fatalf("cache was subtracted twice: %+v", ev)
			}
		})
	}
}

func TestCLIUsageLogIncrementalAndSurface(t *testing.T) {
	dir := t.TempDir()
	logs := filepath.Join(dir, "cursor-agent-logs-test")
	if err := os.MkdirAll(logs, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(logs, "session-2026-09-09T10-37-18-000Z-123-1.log")
	line := cliUsageLine(t, nil)
	if err := os.WriteFile(path, []byte("unrelated\n"+strings.TrimSuffix(line, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	a := NewWithOptions(nil, logs)
	if !a.IsSessionFile(path) || a.IsSessionFile(filepath.Join(logs, "latest.log")) || a.IsSessionFile(filepath.Join(dir, filepath.Base(path))) {
		t.Fatal("incorrect log scoping")
	}
	if a.CursorSemanticsFor(path).Kind != adapter.CursorNoActions {
		t.Fatal("token-only file must not report missing actions")
	}
	first, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil || first.NewOffset != 10 || len(first.TokenEvents) != 0 {
		t.Fatalf("partial write advanced: %+v %v", first, err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	second, err := a.ParseSessionFile(context.Background(), path, first.NewOffset)
	if err != nil || len(second.TokenEvents) != 1 || len(second.SessionSurfaces) != 1 || second.SessionSurfaces[0].Surface != models.SurfaceCLI {
		t.Fatalf("missing usage/surface: %+v %v", second, err)
	}
	third, err := a.ParseSessionFile(context.Background(), path, second.NewOffset)
	if err != nil || len(third.TokenEvents) != 0 {
		t.Fatalf("replayed usage: %+v %v", third, err)
	}
}

func TestCLIUsageRootsCrossMount(t *testing.T) {
	home := t.TempDir()
	logDir := filepath.Join(home, "AppData", "Local", "Temp", "cursor-agent-logs-test")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, path := range cliUsageRoots([]crossmount.HomeRoot{{Path: home, OS: crossmount.OSWindows}}) {
		if path == logDir {
			return
		}
	}
	t.Fatal("Windows CLI logs missing from cross-mount roots")
}

func TestCLIUsageModelDoesNotGuessAcrossModels(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		t.Run(map[bool]string{false: "single", true: "mixed"}[mixed], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "store.db")
			blobs := map[string][]byte{"a": []byte(`{"role":"assistant","content":[{"providerOptions":{"cursor":{"modelName":"composer-2.5"}}}]}`)}
			if mixed {
				blobs["b"] = []byte(`{"role":"assistant","content":[{"providerOptions":{"cursor":{"modelName":"another-model"}}}]}`)
			}
			writeCursorStoreDB(t, path, blobs)
			got := cliUsageModel(context.Background(), path)
			if (!mixed && got != "composer-2.5") || (mixed && got != "") {
				t.Fatalf("model=%q mixed=%v", got, mixed)
			}
		})
	}
}
