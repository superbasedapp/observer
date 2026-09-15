package codex

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/adapter"
)

const terminalMetadataLimit = 1 << 20

type terminalMetadataState uint8

const (
	terminalMetadataUncertain terminalMetadataState = iota
	terminalMetadataExcluded
	terminalMetadataPrimary
)

// TerminalNativeExecutableOnly reports that Codex-family script entrypoints
// launch a distinct native process which owns the rollout descriptor.
func (*Adapter) TerminalNativeExecutableOnly() bool { return true }

// TerminalNativeExecutablePaths resolves exact installed native binaries from
// the configured launcher. Codex's npm entrypoint selects one architecture
// package (or its own bundled vendor directory) at fixed paths; the current
// Open Interpreter standalone launcher is already the native executable.
func (a *Adapter) TerminalNativeExecutablePaths(launcher string) []string {
	launcher = strings.TrimSpace(launcher)
	if launcher == "" {
		return nil
	}
	if native, ok := terminalNativeBinary(launcher); ok {
		return []string{native}
	}
	if a.homeDirName == ".openinterpreter" {
		return nil
	}

	entrypoint, err := filepath.EvalSymlinks(launcher)
	if err != nil || filepath.Base(entrypoint) != "codex.js" || filepath.Base(filepath.Dir(entrypoint)) != "bin" {
		return nil
	}
	triple, platformPackage, executable := codexNativeTarget()
	if triple == "" {
		return nil
	}
	packageRoot := filepath.Dir(filepath.Dir(entrypoint))
	nodeModulesRoot := filepath.Dir(filepath.Dir(packageRoot))
	vendorRoots := []string{
		filepath.Join(packageRoot, "node_modules", "@openai", platformPackage, "vendor"),
		filepath.Join(nodeModulesRoot, "@openai", platformPackage, "vendor"),
		filepath.Join(packageRoot, "vendor"),
	}

	var paths []string
	seen := map[string]struct{}{}
	for _, vendorRoot := range vendorRoots {
		for _, layout := range []string{"bin", "codex"} {
			candidate, ok := terminalNativeBinary(filepath.Join(vendorRoot, triple, layout, executable))
			if !ok {
				continue
			}
			if _, duplicate := seen[candidate]; duplicate {
				continue
			}
			seen[candidate] = struct{}{}
			paths = append(paths, candidate)
		}
	}
	return paths
}

func codexNativeTarget() (triple, platformPackage, executable string) {
	executable = "codex"
	switch runtime.GOOS {
	case "linux", "android":
		switch runtime.GOARCH {
		case "amd64":
			return "x86_64-unknown-linux-musl", "codex-linux-x64", executable
		case "arm64":
			return "aarch64-unknown-linux-musl", "codex-linux-arm64", executable
		}
	case "darwin":
		switch runtime.GOARCH {
		case "amd64":
			return "x86_64-apple-darwin", "codex-darwin-x64", executable
		case "arm64":
			return "aarch64-apple-darwin", "codex-darwin-arm64", executable
		}
	case "windows":
		executable = "codex.exe"
		switch runtime.GOARCH {
		case "amd64":
			return "x86_64-pc-windows-msvc", "codex-win32-x64", executable
		case "arm64":
			return "aarch64-pc-windows-msvc", "codex-win32-arm64", executable
		}
	}
	return "", "", ""
}

func terminalNativeBinary(path string) (string, bool) {
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", false
	}
	f, err := os.Open(realPath) //nolint:gosec // registry-derived installed executable candidate
	if err != nil {
		return "", false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0) {
		return "", false
	}
	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return "", false
	}
	if string(magic[:]) == "\x7fELF" || string(magic[:2]) == "MZ" || isMachOMagic(magic) {
		return filepath.Clean(realPath), true
	}
	return "", false
}

func isMachOMagic(magic [4]byte) bool {
	switch magic {
	case [4]byte{0xfe, 0xed, 0xfa, 0xce}, [4]byte{0xce, 0xfa, 0xed, 0xfe},
		[4]byte{0xfe, 0xed, 0xfa, 0xcf}, [4]byte{0xcf, 0xfa, 0xed, 0xfe},
		[4]byte{0xca, 0xfe, 0xba, 0xbe}, [4]byte{0xbe, 0xba, 0xfe, 0xca}:
		return true
	default:
		return false
	}
}

// ResolveTerminalSession identifies the one primary CLI rollout held open for
// append by a validated Codex-family process. The adapter instance supplies
// the authoritative root and tool variant, so the same decoder covers Codex
// and the current Rust Open Interpreter fork without admitting either one's
// desktop or IDE rollouts.
func (a *Adapter) ResolveTerminalSession(ctx context.Context, process adapter.TerminalProcess) (adapter.TerminalSessionIdentity, error) {
	if err := ctx.Err(); err != nil {
		return adapter.TerminalSessionIdentity{}, err
	}
	if process.PID <= 1 {
		return adapter.TerminalSessionIdentity{}, nil
	}

	var found adapter.TerminalSessionIdentity
	uncertain := false
	for _, file := range process.Files {
		if err := ctx.Err(); err != nil {
			return adapter.TerminalSessionIdentity{}, err
		}
		if !file.Append || !file.Writable || file.ReadPath == "" || !a.IsSessionFile(file.Path) ||
			!adapter.UnderAnyWatchRoot(file.Path, a.WatchPaths()) {
			continue
		}
		id, state := readTerminalSessionMeta(file.ReadPath, file.Path)
		switch state {
		case terminalMetadataExcluded:
			continue
		case terminalMetadataUncertain:
			uncertain = true
			continue
		}
		candidate := adapter.TerminalSessionIdentity{SessionID: id, Evidence: filepath.Clean(file.Path)}
		if found.SessionID != "" && found != candidate {
			return adapter.TerminalSessionIdentity{}, nil
		}
		found = candidate
	}
	if err := ctx.Err(); err != nil {
		return adapter.TerminalSessionIdentity{}, err
	}
	if uncertain {
		return adapter.TerminalSessionIdentity{}, nil
	}
	return found, nil
}

// readTerminalSessionMeta reads only the rollout's first complete record. A
// valid terminal identity requires the native session metadata, a primary CLI
// source and agreement between the metadata id and rollout filename.
func readTerminalSessionMeta(readPath, sourcePath string) (string, terminalMetadataState) {
	f, err := os.Open(readPath) //nolint:gosec // caller supplies a revalidated descriptor path
	if err != nil {
		return "", terminalMetadataUncertain
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() {
		return "", terminalMetadataUncertain
	}

	line, err := bufio.NewReaderSize(f, terminalMetadataLimit).ReadSlice('\n')
	if err != nil || len(line) > terminalMetadataLimit {
		return "", terminalMetadataUncertain
	}
	var meta struct {
		Type    string `json:"type"`
		Payload struct {
			ID             string          `json:"id"`
			SessionID      string          `json:"session_id"`
			Source         json.RawMessage `json:"source"`
			Originator     string          `json:"originator"`
			ParentThreadID string          `json:"parent_thread_id"`
			ThreadSource   string          `json:"thread_source"`
		} `json:"payload"`
	}
	if json.Unmarshal(line, &meta) != nil || meta.Type != "session_meta" {
		return "", terminalMetadataUncertain
	}
	source, sourceState := classifyTerminalSessionSource(meta.Payload.Source)
	if sourceState != terminalMetadataPrimary {
		return "", sourceState
	}
	if meta.Payload.ParentThreadID != "" || meta.Payload.ThreadSource == "subagent" || meta.Payload.Originator == "codex_ui" {
		return "", terminalMetadataExcluded
	}
	if source == "vscode" || meta.Payload.Originator == "Codex Desktop" || meta.Payload.Originator == "codex_vscode" || strings.HasPrefix(meta.Payload.Originator, "JetBrains.") {
		return "", terminalMetadataExcluded
	}
	if source != "cli" && source != "exec" {
		return "", terminalMetadataUncertain
	}
	id := strings.TrimSpace(meta.Payload.ID)
	if id == "" {
		id = strings.TrimSpace(meta.Payload.SessionID)
	}
	if id == "" || strings.ContainsAny(id, `/\\`) || !strings.HasSuffix(filepath.Base(sourcePath), "-"+id+".jsonl") {
		return "", terminalMetadataUncertain
	}
	after, err := os.Stat(readPath)
	if err != nil || !os.SameFile(before, after) {
		return "", terminalMetadataUncertain
	}
	return id, terminalMetadataPrimary
}

func classifyTerminalSessionSource(raw json.RawMessage) (string, terminalMetadataState) {
	if len(raw) > 0 && raw[0] == '{' {
		var sourceObject map[string]json.RawMessage
		if json.Unmarshal(raw, &sourceObject) != nil {
			return "", terminalMetadataUncertain
		}
		subagent, ok := sourceObject["subagent"]
		if !ok || len(subagent) == 0 {
			return "", terminalMetadataUncertain
		}
		// Serde unit variants such as review/compact use a string; spawned
		// workers carry an object. Both explicitly identify a subagent.
		var kind string
		if json.Unmarshal(subagent, &kind) == nil && kind != "" {
			return "", terminalMetadataExcluded
		}
		var details map[string]json.RawMessage
		if json.Unmarshal(subagent, &details) != nil || details == nil {
			return "", terminalMetadataUncertain
		}
		return "", terminalMetadataExcluded
	}
	var source string
	if json.Unmarshal(raw, &source) != nil {
		return "", terminalMetadataUncertain
	}
	return source, terminalMetadataPrimary
}

var (
	_ adapter.TerminalSessionResolver  = (*Adapter)(nil)
	_ adapter.TerminalNativeExecutable = (*Adapter)(nil)
)
