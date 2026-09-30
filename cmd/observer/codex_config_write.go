// codex_config_write.go — V6-2 auto-fix: write openai_base_url into
// $CODEX_HOME/config.toml so codex 0.130+ routes through the observer
// proxy.
//
// V6-2 (docs/observer-platform-issues-v6.md §V6-2): codex 0.130+
// silently drops the wrapper's argv-injected `-c openai_base_url=…`.
// Only the file value reaches the inner app-server. Until the upstream
// codex bug is fixed, the proxy story REQUIRES the value sit in
// config.toml. checkCodexConfigTOMLBaseURL surfaces the misconfig;
// writeCodexConfigBaseURL fixes it on operator opt-in (--write-config).
//
// File-mutation rules:
//   - Always back up to <configPath>.bak.<RFC3339Nano> before writing.
//   - Missing file → create with a one-line header comment + the key.
//   - Has key, wrong value → replace just the matching top-level line.
//   - Missing key → append at the end with a comment header.
//   - Inside-table `openai_base_url` (e.g. under [model_provider.xxx])
//     is left alone — only the top-level key is the V6-2 target.
//
// We DO NOT round-trip parse → re-emit the whole file. BurntSushi/toml
// is decoder-only, so a string-replace + append on the raw bytes is
// the surgical option that preserves the operator's comments and key
// ordering verbatim.

package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// writeCodexConfigBaseURL ensures configPath sets the top-level
// openai_base_url to targetURL. Returns the backup path written
// (empty when the file didn't exist) and a non-nil error if any FS
// operation failed.
//
// stamp is the suffix appended to the backup filename — passed in so
// tests can pin a deterministic value. Callers in main code pass
// time.Now().UTC().Format(time.RFC3339Nano).
func writeCodexConfigBaseURL(configPath, targetURL, stamp string) (string, error) {
	if configPath == "" {
		return "", errors.New("configPath empty")
	}
	if targetURL == "" {
		return "", errors.New("targetURL empty")
	}
	parent := filepath.Dir(configPath)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", parent, err)
	}
	existing, readErr := os.ReadFile(configPath)
	if readErr != nil {
		if !errors.Is(readErr, fs.ErrNotExist) {
			return "", fmt.Errorf("read %s: %w", configPath, readErr)
		}
		// Create fresh.
		body := codexConfigHeader(targetURL) + "openai_base_url = \"" + targetURL + "\"\n"
		if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
			return "", fmt.Errorf("write %s: %w", configPath, err)
		}
		return "", nil
	}

	backupPath := configPath + ".bak." + stamp
	if err := os.WriteFile(backupPath, existing, 0o600); err != nil {
		return "", fmt.Errorf("backup %s: %w", backupPath, err)
	}

	newBody, replaced := replaceTopLevelOpenAIBaseURL(existing, targetURL)
	if !replaced {
		// Append at end with a header comment.
		if len(newBody) > 0 && !bytes.HasSuffix(newBody, []byte("\n")) {
			newBody = append(newBody, '\n')
		}
		newBody = append(newBody, []byte("\n"+codexConfigHeader(targetURL)+"openai_base_url = \""+targetURL+"\"\n")...)
	}
	if err := os.WriteFile(configPath, newBody, 0o600); err != nil {
		return backupPath, fmt.Errorf("write %s: %w", configPath, err)
	}
	return backupPath, nil
}

// codexConfigHeader returns the comment lines stamped above an
// observer-managed openai_base_url entry. Short on purpose — the
// pointer is to the canonical doc, not a verbose explainer.
func codexConfigHeader(targetURL string) string {
	return "# observer codex: route through the observer proxy (V6-2).\n" +
		"# See docs/proxy-wrappers.md or docs/observer-platform-issues-v6.md.\n"
}

// topLevelOpenAIBaseURLLine matches `openai_base_url = ...` lines that
// sit at top-level (not indented, not inside a [section]). We track
// section state line-by-line in replaceTopLevelOpenAIBaseURL because
// regex alone can't tell which TOML table a line lives under.
var topLevelOpenAIBaseURLLine = regexp.MustCompile(`^[ \t]*openai_base_url[ \t]*=`)

// tomlSectionHeader matches `[section]` and `[section.sub]` — anything
// inside a section is NOT top-level.
var tomlSectionHeader = regexp.MustCompile(`^[ \t]*\[`)

// replaceTopLevelOpenAIBaseURL rewrites a top-level
// `openai_base_url = "..."` line to point at targetURL. Returns the
// new bytes plus a flag indicating whether a replace happened. If no
// top-level openai_base_url line exists the input is returned
// unchanged with replaced=false; the caller appends.
func replaceTopLevelOpenAIBaseURL(input []byte, targetURL string) ([]byte, bool) {
	var out bytes.Buffer
	out.Grow(len(input) + 64)
	scanner := bufio.NewScanner(bytes.NewReader(input))
	// Allow long config lines without crashing.
	scanner.Buffer(make([]byte, 1<<16), 1<<20)
	inSection := false
	replaced := false
	first := true
	for scanner.Scan() {
		raw := scanner.Bytes()
		if !first {
			out.WriteByte('\n')
		}
		first = false
		trimmed := bytes.TrimLeft(raw, " \t")
		if len(trimmed) == 0 || trimmed[0] == '#' {
			out.Write(raw)
			continue
		}
		if tomlSectionHeader.Match(trimmed) {
			inSection = true
			out.Write(raw)
			continue
		}
		if !inSection && !replaced && topLevelOpenAIBaseURLLine.Match(raw) {
			indent := raw[:len(raw)-len(bytes.TrimLeft(raw, " \t"))]
			out.Write(indent)
			out.WriteString("openai_base_url = \"")
			out.WriteString(targetURL)
			out.WriteString("\"")
			replaced = true
			continue
		}
		out.Write(raw)
	}
	// Preserve trailing newline if the input had one.
	if len(input) > 0 && input[len(input)-1] == '\n' {
		out.WriteByte('\n')
	}
	return out.Bytes(), replaced
}

// runWriteCodexConfig writes config for each misconfig and emits a
// stderr line per outcome. Returns nil so the wrapper continues with
// the normal exec path even when one home fails (best-effort, like
// the rest of the pre-flight pipeline).
func runWriteCodexConfig(stderr interface{ Write([]byte) (int, error) }, misconfigs []codexConfigMisconfig) {
	if len(misconfigs) == 0 {
		return
	}
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	// Some filesystems disallow ':' in filenames (notably NTFS). Use a
	// safe separator for the backup stamp.
	stamp = strings.ReplaceAll(stamp, ":", "-")
	for _, m := range misconfigs {
		if !m.fixable() {
			// A wrong [model_providers.<id>].base_url: appending a top-level
			// openai_base_url would not change the selected provider's route.
			continue
		}
		backup, err := writeCodexConfigBaseURL(m.ConfigPath, m.WantURL, stamp)
		if err != nil {
			fmt.Fprintf(stderr,
				"observer codex: --write-config: failed to write %s: %v (run unchanged)\n",
				m.ConfigPath, err)
			continue
		}
		if backup == "" {
			fmt.Fprintf(stderr,
				"observer codex: --write-config: created %s with openai_base_url=%q\n",
				m.ConfigPath, m.WantURL)
		} else {
			fmt.Fprintf(stderr,
				"observer codex: --write-config: updated %s with openai_base_url=%q (backup: %s)\n",
				m.ConfigPath, m.WantURL, backup)
		}
	}
}
