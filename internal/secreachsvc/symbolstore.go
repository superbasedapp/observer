package secreachsvc

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/fsatomic"
	"github.com/marmutapp/superbased-observer/internal/secreach"
)

// symbolstore.go is the ONE owner of the Go symbol checks' node-local
// record (plan section 14.5 item 3b): one file per project,
// <security dir>/reach/<project root hash>.json, holding the latest symbol
// check of each target (a binary for govulncheck-binary, a go.mod for
// govulncheck-source). The dependency scan writes the binary checks after
// each scan (ReplaceSymbolRuns); a surface reads them at view time
// (LoadSymbolRuns) and secreach.ApplySymbol combines them with the 3a tier.
//
// What it holds: advisory ids, module paths and versions, a closed verdict,
// a listed function name and the project-relative target path. Never
// content, never an absolute path, never engine prose. Node-local: no org
// row builder reads it.

// SymbolDirName is the record's directory under the security directory.
const SymbolDirName = "reach"

// maxSymbolFileBytes caps the file LoadSymbolRuns reads.
const maxSymbolFileBytes = 4 << 20

// maxSymbolRuns and maxSymbolRecords cap what one file keeps.
const (
	maxSymbolRuns    = 64
	maxSymbolRecords = 2000
	maxSymbolBytes   = 160
)

// symbolFile is the file's shape.
type symbolFile struct {
	Version int         `json:"version"`
	Runs    []storedRun `json:"runs"`
}

type storedRun struct {
	secreach.SymbolRun
	// RanAt is when the check ran (RFC 3339, UTC).
	RanAt string `json:"ran_at"`
}

const symbolFileVersion = 1

// SymbolPath is the project's record file; "" for a hash that is not a
// lowercase sha256 hex (a hash never names another file).
func SymbolPath(securityDir, rootHash string) string {
	if securityDir == "" || !validRootHash(rootHash) {
		return ""
	}
	return filepath.Join(securityDir, SymbolDirName, rootHash+".json")
}

func validRootHash(h string) bool {
	if len(h) != 64 {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// LoadSymbolRuns returns the project's stored symbol checks; nil when there
// are none or the file cannot be read (a view then shows the 3a tier).
func LoadSymbolRuns(securityDir, rootHash string) []secreach.SymbolRun {
	f, ok := readSymbolFile(SymbolPath(securityDir, rootHash))
	if !ok {
		return nil
	}
	out := make([]secreach.SymbolRun, 0, len(f.Runs))
	for _, r := range f.Runs {
		out = append(out, r.SymbolRun)
	}
	return out
}

func readSymbolFile(p string) (symbolFile, bool) {
	if p == "" {
		return symbolFile{}, false
	}
	h, err := os.Open(p) //nolint:gosec // G304: SymbolPath's own file under the security directory
	if err != nil {
		return symbolFile{}, false
	}
	defer func() { _ = h.Close() }()
	b, err := io.ReadAll(io.LimitReader(h, maxSymbolFileBytes+1))
	if err != nil || len(b) > maxSymbolFileBytes {
		return symbolFile{}, false
	}
	var f symbolFile
	if json.Unmarshal(b, &f) != nil || f.Version != symbolFileVersion {
		return symbolFile{}, false
	}
	return f, true
}

// ReplaceSymbolRuns replaces the project's stored checks of source: every
// one when targets is nil (a dependency scan's binary checks), else only
// those whose target is in targets (one go.mod's source check). runs are
// validated (CleanSymbolRun) and stamped with at; an invalid run is
// dropped. Writing nothing for a source removes its checks.
func ReplaceSymbolRuns(securityDir, rootHash, source string, targets []string, runs []secreach.SymbolRun, at time.Time) error {
	p := SymbolPath(securityDir, rootHash)
	if p == "" {
		return errors.New("secreachsvc.ReplaceSymbolRuns: no record path for this project")
	}
	only := map[string]bool{}
	for _, t := range targets {
		only[t] = true
	}
	cur, _ := readSymbolFile(p)
	next := symbolFile{Version: symbolFileVersion}
	for _, r := range cur.Runs {
		if r.Source == source && (targets == nil || only[r.Target]) {
			continue
		}
		next.Runs = append(next.Runs, r)
	}
	stamp := at.UTC().Format(time.RFC3339)
	for _, r := range runs {
		c, ok := CleanSymbolRun(r)
		if !ok || c.Source != source || (targets != nil && !only[c.Target]) {
			continue
		}
		next.Runs = append(next.Runs, storedRun{SymbolRun: c, RanAt: stamp})
	}
	sort.SliceStable(next.Runs, func(i, j int) bool {
		if next.Runs[i].Source != next.Runs[j].Source {
			return next.Runs[i].Source < next.Runs[j].Source
		}
		return next.Runs[i].Target < next.Runs[j].Target
	})
	if len(next.Runs) > maxSymbolRuns {
		next.Runs = next.Runs[:maxSymbolRuns]
	}
	if len(next.Runs) == 0 {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("secreachsvc.ReplaceSymbolRuns: %w", err)
		}
		return nil
	}
	b, err := json.Marshal(next)
	if err != nil {
		return fmt.Errorf("secreachsvc.ReplaceSymbolRuns: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return fmt.Errorf("secreachsvc.ReplaceSymbolRuns: %w", err)
	}
	if err := fsatomic.WriteFile(p, b, fsatomic.Options{TempPattern: ".reach-*"}); err != nil {
		return fmt.Errorf("secreachsvc.ReplaceSymbolRuns: %w", err)
	}
	return nil
}

// symbolSources, symbolVerdicts and symbolReasons are the closed
// vocabularies a stored run may carry.
var (
	symbolSources  = map[string]bool{secreach.SourceGovulncheckBinary: true, secreach.SourceGovulncheckSource: true}
	symbolVerdicts = map[secreach.SymbolVerdict]bool{secreach.VerdictCalled: true, secreach.VerdictNotCalled: true, secreach.VerdictUnknown: true}
	symbolReasons  = map[secreach.Reason]bool{
		secreach.ReasonStripped: true, secreach.ReasonSymbolCheckFailed: true, secreach.ReasonOutOfMemory: true,
		secreach.ReasonTimedOut: true, secreach.ReasonNoToolchain: true, secreach.ReasonUnsupportedBinary: true,
		secreach.ReasonBinaryCap: true, secreach.ReasonModuleCap: true, secreach.ReasonToolchainTooOld: true,
		secreach.ReasonModulesMissing: true,
	}
)

// CleanSymbolRun validates a run from the scan child (a child of the same
// binary, but one that read project input): a closed source, verdict and
// reason, a clean project-relative target, ids, modules and versions in a
// safe charset, a listed function name in a safe charset and length. ok
// false drops the run; a bad record is dropped alone.
func CleanSymbolRun(r secreach.SymbolRun) (secreach.SymbolRun, bool) {
	if !symbolSources[r.Source] || !cleanTarget(r.Target) {
		return secreach.SymbolRun{}, false
	}
	out := secreach.SymbolRun{Source: r.Source, Target: r.Target}
	if r.Reason != "" {
		if !symbolReasons[r.Reason] {
			return secreach.SymbolRun{}, false
		}
		out.Reason = r.Reason
		return out, true
	}
	for _, rec := range r.Records {
		if len(out.Records) >= maxSymbolRecords {
			break
		}
		if !symbolVerdicts[rec.Verdict] || !safeToken(rec.ID, 128, "-_.:") || !safeToken(rec.Module, 300, "-_.~/+") ||
			(rec.Version != "" && !safeToken(rec.Version, 128, "-_.+")) || (rec.Symbol != "" && !safeToken(rec.Symbol, maxSymbolBytes, "-_.*()[]/")) ||
			(rec.AssumedGo != "" && (rec.Module != "stdlib" || !safeToken(rec.AssumedGo, 64, "-_.+"))) {
			continue
		}
		out.Records = append(out.Records, rec)
	}
	return out, true
}

func cleanTarget(p string) bool {
	if p == "" || len(p) > 1024 || strings.ContainsAny(p, "\\\x00") || path.IsAbs(p) || (len(p) > 1 && p[1] == ':') {
		return false
	}
	c := path.Clean(p)
	return c == p && c != "." && c != ".." && !strings.HasPrefix(c, "../")
}

func safeToken(s string, max int, extra string) bool {
	if s == "" || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte(extra, c) >= 0 {
			continue
		}
		return false
	}
	return true
}
