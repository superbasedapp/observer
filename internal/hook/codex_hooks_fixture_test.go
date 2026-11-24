package hook

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
)

// codexHooksConfig is a TEST-ONLY typed view of ~/.codex/hooks.json
// (`{"hooks": {<event>: [<group>...]}}`), for fixtures that seed or read
// the file. It models only the fields Observer writes, so production never
// decodes a file it is about to rewrite into it (NEW-06: the writers use
// readCodexHooksFile, which keeps every field raw).
type codexHooksConfig struct {
	Hooks map[string][]codexHookGroup `json:"hooks"`
}

// readCodexHooks loads hooks.json into the typed fixture view (an empty
// config when the file does not exist).
func readCodexHooks(path string) (codexHooksConfig, error) {
	cfg := codexHooksConfig{Hooks: map[string][]codexHookGroup{}}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("readCodexHooks: read: %w", err)
	}
	if len(raw) == 0 {
		return cfg, nil
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("readCodexHooks: parse %s: %w", path, err)
	}
	if cfg.Hooks == nil {
		cfg.Hooks = map[string][]codexHookGroup{}
	}
	return cfg, nil
}

// writeCodexHooks writes a fixture config as 2-space-indented JSON with
// sorted events (the layout the production writer produces for a file it
// created).
func writeCodexHooks(dir string, pinned pinnedTarget, cfg codexHooksConfig) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("writeCodexHooks: mkdir: %w", err)
	}
	keys := make([]string, 0, len(cfg.Hooks))
	for k := range cfg.Hooks {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var buf bytes.Buffer
	buf.WriteString("{\n  \"hooks\": {")
	for i, k := range keys {
		if i > 0 {
			buf.WriteString(",")
		}
		buf.WriteString("\n    ")
		ke, _ := json.Marshal(k)
		buf.Write(ke)
		buf.WriteString(": ")
		ge, err := json.MarshalIndent(cfg.Hooks[k], "    ", "  ")
		if err != nil {
			return fmt.Errorf("writeCodexHooks: encode %s: %w", k, err)
		}
		buf.Write(ge)
	}
	if len(keys) > 0 {
		buf.WriteString("\n  ")
	}
	buf.WriteString("}\n}\n")
	return atomicWriteFile(pinned, buf.Bytes())
}
