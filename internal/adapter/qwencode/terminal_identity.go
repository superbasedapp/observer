package qwencode

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
)

const (
	terminalLeaseLimit      = 64 << 10
	terminalLeaseEntryLimit = 512
	terminalTranscriptLimit = 1 << 20
	terminalPackageLimit    = 64 << 10
)

type terminalWriterLease struct {
	SchemaVersion        int    `json:"schema_version"`
	SessionID            string `json:"session_id"`
	OwnerID              string `json:"owner_id"`
	PID                  int    `json:"pid"`
	ProcessStartIdentity string `json:"process_start_identity"`
	Hostname             string `json:"hostname"`
	ProcessKind          string `json:"process_kind"`
	AcquiredAt           string `json:"acquired_at"`
}

type terminalLeaseState uint8

const (
	terminalLeaseUncertain terminalLeaseState = iota
	terminalLeaseExcluded
	terminalLeasePrimary
)

// TerminalScriptExecutablePaths resolves the exact Node entrypoint used by a
// Qwen launcher. Current cli-entry.js is a wrapper which starts cli.js with
// --expose-gc; older installations may expose cli.js directly.
func (*Adapter) TerminalScriptExecutablePaths(launcher string) []string {
	entrypoint, err := filepath.EvalSymlinks(strings.TrimSpace(launcher))
	if err != nil {
		return nil
	}
	base := filepath.Base(entrypoint)
	if base != "cli-entry.js" && base != "cli.js" {
		return nil
	}
	entrypoint, ok := terminalRegularScript(entrypoint, base)
	if !ok {
		return nil
	}
	if !isQwenPackageEntrypoint(entrypoint) {
		return nil
	}
	if base == "cli.js" {
		return []string{filepath.Clean(entrypoint)}
	}
	for _, candidate := range []string{
		filepath.Join(filepath.Dir(entrypoint), "cli.js"),
		filepath.Join(filepath.Dir(entrypoint), "..", "dist", "cli.js"),
	} {
		if script, ok := terminalRegularScript(candidate, "cli.js"); ok {
			return []string{script}
		}
	}
	return nil
}

func isQwenPackageEntrypoint(path string) bool {
	for _, dir := range []string{filepath.Dir(path), filepath.Dir(filepath.Dir(path))} {
		body, _, ok := readBoundedRegularFile(filepath.Join(dir, "package.json"), terminalPackageLimit)
		if !ok {
			continue
		}
		var manifest struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if json.Unmarshal(body, &manifest) == nil && manifest.Name == "@qwen-code/qwen-code" && manifest.Version != "" {
			return true
		}
	}
	return false
}

func terminalRegularScript(path, basename string) (string, bool) {
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil || filepath.Base(realPath) != basename {
		return "", false
	}
	info, err := os.Stat(realPath)
	if err != nil || !info.Mode().IsRegular() {
		return "", false
	}
	return filepath.Clean(realPath), true
}

// ResolveTerminalSession first uses Qwen's current native session-writer
// lease, whose process-start identity is the same boot-id/start-ticks tuple
// supplied by the terminal process walker. Older releases are supported when
// the validated process itself holds the per-session transcript open for
// append and its runtime sidecar and transcript metadata agree.
func (a *Adapter) ResolveTerminalSession(ctx context.Context, process adapter.TerminalProcess) (adapter.TerminalSessionIdentity, error) {
	if err := ctx.Err(); err != nil {
		return adapter.TerminalSessionIdentity{}, err
	}
	if process.PID <= 1 {
		return adapter.TerminalSessionIdentity{}, nil
	}
	if identity, matched, ambiguous := a.resolveTerminalWriterLease(ctx, process); matched || ambiguous {
		return identity, nil
	}
	if err := ctx.Err(); err != nil {
		return adapter.TerminalSessionIdentity{}, err
	}
	return a.resolveLegacyTerminalWriter(ctx, process)
}

// resolveTerminalWriterLease scans only Qwen's bounded native lease
// directories. A lease is re-read after the scan so an atomic release or
// replacement between discovery and return becomes an abstention.
func (a *Adapter) resolveTerminalWriterLease(ctx context.Context, process adapter.TerminalProcess) (adapter.TerminalSessionIdentity, bool, bool) {
	if process.StartIdentity == "" {
		return adapter.TerminalSessionIdentity{}, false, false
	}
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		return adapter.TerminalSessionIdentity{}, false, false
	}

	type candidate struct {
		identity adapter.TerminalSessionIdentity
		lease    terminalWriterLease
		path     string
	}
	var found candidate
	uncertain := false
	for _, root := range a.WatchPaths() {
		if err := ctx.Err(); err != nil {
			return adapter.TerminalSessionIdentity{}, false, false
		}
		if !strings.EqualFold(filepath.Base(filepath.Clean(root)), "projects") {
			continue
		}
		dir := filepath.Join(filepath.Dir(filepath.Clean(root)), "tmp", "session-writer-locks")
		entries, exists, ok := readBoundedLeaseDirectory(dir)
		if !exists {
			continue
		}
		if !ok {
			return adapter.TerminalSessionIdentity{}, false, true
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return adapter.TerminalSessionIdentity{}, false, false
			}
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".lock") {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			lease, state := readTerminalWriterLease(path, process, hostname)
			switch state {
			case terminalLeaseExcluded:
				continue
			case terminalLeaseUncertain:
				uncertain = true
				continue
			}
			identity := adapter.TerminalSessionIdentity{SessionID: lease.SessionID, Evidence: terminalWriterLeaseEvidence(path, lease)}
			if found.identity.SessionID != "" && found.identity != identity {
				return adapter.TerminalSessionIdentity{}, false, true
			}
			found = candidate{identity: identity, lease: lease, path: path}
		}
	}
	if uncertain {
		return adapter.TerminalSessionIdentity{}, false, true
	}
	if found.identity.SessionID == "" {
		return adapter.TerminalSessionIdentity{}, false, false
	}
	if ctx.Err() != nil {
		return adapter.TerminalSessionIdentity{}, false, false
	}
	fresh, state := readTerminalWriterLease(found.path, process, hostname)
	if state != terminalLeasePrimary || fresh != found.lease {
		return adapter.TerminalSessionIdentity{}, false, true
	}
	if ctx.Err() != nil {
		return adapter.TerminalSessionIdentity{}, false, false
	}
	return found.identity, true, false
}

func readBoundedLeaseDirectory(path string) ([]os.DirEntry, bool, bool) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, false, true
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, true, false
	}
	dir, err := os.Open(path) //nolint:gosec // adapter-rooted native lease directory
	if err != nil {
		return nil, true, false
	}
	defer dir.Close()
	opened, err := dir.Stat()
	if err != nil || !opened.IsDir() || !os.SameFile(info, opened) {
		return nil, true, false
	}
	entries, err := dir.ReadDir(terminalLeaseEntryLimit + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, true, false
	}
	if len(entries) > terminalLeaseEntryLimit {
		return nil, true, false
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(opened, after) {
		return nil, true, false
	}
	return entries, true, true
}

func readTerminalWriterLease(path string, process adapter.TerminalProcess, hostname string) (terminalWriterLease, terminalLeaseState) {
	body, before, ok := readBoundedRegularFile(path, terminalLeaseLimit)
	if !ok {
		return terminalWriterLease{}, terminalLeaseUncertain
	}
	var lease terminalWriterLease
	if json.Unmarshal(body, &lease) != nil {
		return terminalWriterLease{}, terminalLeaseUncertain
	}
	if lease.PID != 0 && lease.PID != process.PID {
		return terminalWriterLease{}, terminalLeaseExcluded
	}
	if lease.ProcessStartIdentity != "" && lease.ProcessStartIdentity != process.StartIdentity {
		return terminalWriterLease{}, terminalLeaseExcluded
	}
	if lease.Hostname != "" && !strings.EqualFold(lease.Hostname, hostname) {
		return terminalWriterLease{}, terminalLeaseExcluded
	}
	if lease.ProcessKind != "" && lease.ProcessKind != "interactive" {
		return terminalWriterLease{}, terminalLeaseExcluded
	}
	if lease.SchemaVersion != 1 || lease.OwnerID == "" || lease.SessionID == "" || lease.PID != process.PID ||
		lease.ProcessStartIdentity == "" || lease.Hostname == "" || lease.ProcessKind == "" {
		return terminalWriterLease{}, terminalLeaseUncertain
	}
	if strings.ContainsAny(lease.SessionID, `/\\`) || strings.TrimSuffix(filepath.Base(path), ".lock") != lease.SessionID {
		return terminalWriterLease{}, terminalLeaseUncertain
	}
	if _, err := time.Parse(time.RFC3339Nano, lease.AcquiredAt); err != nil {
		return terminalWriterLease{}, terminalLeaseUncertain
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) {
		return terminalWriterLease{}, terminalLeaseUncertain
	}
	return lease, terminalLeasePrimary
}

func terminalWriterLeaseEvidence(path string, lease terminalWriterLease) string {
	body, _ := json.Marshal(lease)
	digest := sha256.Sum256(body)
	return filepath.Clean(path) + ":sha256:" + hex.EncodeToString(digest[:])
}

func (a *Adapter) resolveLegacyTerminalWriter(ctx context.Context, process adapter.TerminalProcess) (adapter.TerminalSessionIdentity, error) {
	var found adapter.TerminalSessionIdentity
	uncertain := false
	for _, file := range process.Files {
		if err := ctx.Err(); err != nil {
			return adapter.TerminalSessionIdentity{}, err
		}
		if !file.Append || !file.Writable || file.ReadPath == "" || !a.IsSessionFile(file.Path) {
			continue
		}
		id, ok := readLegacyTerminalIdentity(file, process.PID)
		if !ok {
			uncertain = true
			continue
		}
		identity := adapter.TerminalSessionIdentity{
			SessionID: id,
			Evidence:  strings.TrimSuffix(filepath.Clean(file.Path), ".jsonl") + ".runtime.json",
		}
		if found.SessionID != "" && found != identity {
			return adapter.TerminalSessionIdentity{}, nil
		}
		found = identity
	}
	if err := ctx.Err(); err != nil {
		return adapter.TerminalSessionIdentity{}, err
	}
	if uncertain {
		return adapter.TerminalSessionIdentity{}, nil
	}
	return found, nil
}

func readLegacyTerminalIdentity(file adapter.TerminalSessionFile, pid int) (string, bool) {
	id := strings.TrimSuffix(filepath.Base(file.Path), ".jsonl")
	if id == "" || strings.ContainsAny(id, `/\\`) {
		return "", false
	}
	transcript, before, ok := readBoundedDescriptor(file.ReadPath, terminalTranscriptLimit)
	if !ok || !terminalTranscriptIDsAgree(transcript, id) {
		return "", false
	}

	sidecarPath := strings.TrimSuffix(file.Path, ".jsonl") + ".runtime.json"
	body, _, ok := readBoundedRegularFile(sidecarPath, terminalLeaseLimit)
	if !ok {
		return "", false
	}
	var sidecar struct {
		SchemaVersion int     `json:"schema_version"`
		PID           int     `json:"pid"`
		SessionID     string  `json:"session_id"`
		Hostname      string  `json:"hostname"`
		StartedAt     float64 `json:"started_at"`
	}
	if json.Unmarshal(body, &sidecar) != nil || sidecar.SchemaVersion != 1 || sidecar.PID != pid || sidecar.SessionID != id || sidecar.StartedAt <= 0 {
		return "", false
	}
	hostname, err := os.Hostname()
	if err != nil || hostname == "" || !strings.EqualFold(sidecar.Hostname, hostname) {
		return "", false
	}
	after, err := os.Stat(file.ReadPath)
	if err != nil || !os.SameFile(before, after) {
		return "", false
	}
	freshBody, _, ok := readBoundedRegularFile(sidecarPath, terminalLeaseLimit)
	if !ok || !bytes.Equal(body, freshBody) {
		return "", false
	}
	return id, true
}

// terminalTranscriptIDsAgree validates every complete record in the bounded
// prefix and requires at least one explicit sessionId. A partial record at the
// bound is ignored; a partial first record cannot establish identity.
func terminalTranscriptIDsAgree(body []byte, want string) bool {
	lastComplete := bytes.LastIndexByte(body, '\n')
	if lastComplete < 0 {
		return false
	}
	seen := false
	for _, line := range bytes.Split(body[:lastComplete], []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var record struct {
			SessionID string `json:"sessionId"`
		}
		if json.Unmarshal(line, &record) != nil {
			return false
		}
		if record.SessionID == "" {
			continue
		}
		seen = true
		if record.SessionID != want {
			return false
		}
	}
	return seen
}

func readBoundedRegularFile(path string, limit int64) ([]byte, os.FileInfo, bool) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > limit {
		return nil, nil, false
	}
	f, err := os.Open(path) //nolint:gosec // adapter-rooted metadata or revalidated descriptor path
	if err != nil {
		return nil, nil, false
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, nil, false
	}
	body, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(body)) > limit {
		return nil, nil, false
	}
	return body, opened, true
}

func readBoundedDescriptor(path string, limit int64) ([]byte, os.FileInfo, bool) {
	f, err := os.Open(path) //nolint:gosec // caller supplies a revalidated descriptor path
	if err != nil {
		return nil, nil, false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, nil, false
	}
	body, err := io.ReadAll(io.LimitReader(f, limit))
	if err != nil {
		return nil, nil, false
	}
	return body, info, true
}

var (
	_ adapter.TerminalSessionResolver  = (*Adapter)(nil)
	_ adapter.TerminalScriptExecutable = (*Adapter)(nil)
)
