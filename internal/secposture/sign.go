package secposture

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/fsatomic"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// keyBytes is the HMAC key length.
const keyBytes = 32

// Layout locates the security directory and its files. Dir is
// <observer home>/security.
type Layout struct {
	Dir string
}

// LayoutFor returns the layout beside the resolved global config path, the
// guardposture precedent (the hook finds it without parsing any TOML). An
// empty configPath gives the zero Layout, whose paths are all "".
func LayoutFor(configPath string) Layout {
	if configPath == "" {
		return Layout{}
	}
	return Layout{Dir: filepath.Join(filepath.Dir(configPath), DirName)}
}

func (l Layout) join(parts ...string) string {
	if l.Dir == "" {
		return ""
	}
	return filepath.Join(append([]string{l.Dir}, parts...)...)
}

// PostureDir is the directory of the per-project posture files.
func (l Layout) PostureDir() string { return l.join(PostureDirName) }

// PosturePath is one project's posture file.
func (l Layout) PosturePath(rootHash string) string {
	if !validHash(rootHash) {
		return ""
	}
	return l.join(PostureDirName, rootHash+PostureExt)
}

// KeyPath is the posture HMAC key.
func (l Layout) KeyPath() string { return l.join(PostureDirName, KeyFilename) }

// DirtyPath is one project's dirty marker.
func (l Layout) DirtyPath(rootHash string) string {
	if !validHash(rootHash) {
		return ""
	}
	return l.join(DirtyDirName, rootHash)
}

// SeenPath is one project's seen mark.
func (l Layout) SeenPath(rootHash string) string {
	if !validHash(rootHash) {
		return ""
	}
	return l.join(SeenDirName, rootHash)
}

// ProjectRootHash is the sha256 hex of a project root, the same spelling
// guard uses for guard_approvals.project_root_hash, so one hash names a
// project in every node-local file and table. Empty in, empty out. Callers
// pass the root internal/git resolved.
func ProjectRootHash(root string) string {
	if root == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(root))
	return hex.EncodeToString(sum[:])
}

// validHash accepts only a lowercase sha256 hex, so a hash can never name a
// path outside its directory.
func validHash(h string) bool {
	if len(h) != 64 {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// normalize is the one shape Encode, Sign and the MAC agree on: the schema
// stamped, every time in UTC, every list sorted and deduplicated, and the
// blocking list capped with Overflow set.
func normalize(f File) File {
	f.Schema = SchemaVersion
	f.IssuedAt = f.IssuedAt.UTC()
	f.ExpiresAt = f.ExpiresAt.UTC()
	f.ScannedAt = f.ScannedAt.UTC()
	f.Packs = sortedSet(f.Packs)
	// The floors keep only the values that raise something (lane SEC-P4):
	// the axis's weakest value is the node's own behaviour, so it is not
	// signed, and a value outside the vocabulary is dropped.
	if f.CommitGateFloor != policy.CommitGateFloorQuickScan {
		f.CommitGateFloor = ""
	}
	if f.PrelaunchTrustFloor != PrelaunchTrustAsk && f.PrelaunchTrustFloor != PrelaunchTrustRefuse {
		f.PrelaunchTrustFloor = ""
	}
	f.Blocking = sortedSet(f.Blocking)
	if len(f.Blocking) > MaxBlocking {
		f.Blocking = f.Blocking[:MaxBlocking]
		f.Overflow = true
	}
	f.HistoryOnly = subsetOf(sortedSet(f.HistoryOnly), f.Blocking)
	f.HistoryCapped = subsetOf(sortedSet(f.HistoryCapped), f.HistoryOnly)
	// The [security.scanning] values keep only what changes the built-in
	// behaviour (lane LEFT-SEC): a budget the picker offers above 2 s, a
	// staleness within the floor's bounds.
	if !slices.Contains(QuickScanBudgetsS, f.QuickScanBudgetS) {
		f.QuickScanBudgetS = 0
	}
	if f.MaxScanStalenessMin < 1 || f.MaxScanStalenessMin > MaxScanStalenessMin {
		f.MaxScanStalenessMin = 0
	}
	f.HistoryOnlyOn = normalizeOn(f.HistoryOnlyOn, len(f.HistoryOnly))
	f.Held, f.HeldOverflow = normalizeHeld(f.Held, f.HeldOverflow, len(f.HistoryOnly) > 0)
	if len(f.HistoryOnly) == 0 || !policy.IsRemoteName(f.DefaultPushRemote) {
		f.DefaultPushRemote = ""
	}
	f.TrustReasons = sortedSet(f.TrustReasons)
	f.OrgProjectIDs = sortedSet(f.OrgProjectIDs)
	counts := append([]Count(nil), f.Counts...)
	sort.Slice(counts, func(i, j int) bool {
		if counts[i].Category != counts[j].Category {
			return counts[i].Category < counts[j].Category
		}
		return counts[i].Severity < counts[j].Severity
	})
	if len(counts) == 0 {
		counts = nil
	}
	f.Counts = counts
	return f
}

// normalizeOn keeps the per-remote counts with a remote name, capped at
// limit (the HistoryOnly count), above zero, at most MaxRemotes remotes
// (the first in name order), nil when none is left.
func normalizeOn(on map[string]int, limit int) map[string]int {
	if limit == 0 || len(on) == 0 {
		return nil
	}
	names := make([]string, 0, len(on))
	for r, n := range on {
		if n > 0 && policy.IsRemoteName(r) {
			names = append(names, r)
		}
	}
	sort.Strings(names)
	if len(names) > MaxRemotes {
		names = names[:MaxRemotes]
	}
	if len(names) == 0 {
		return nil
	}
	out := make(map[string]int, len(names))
	for _, r := range names {
		out[r] = min(on[r], limit)
	}
	return out
}

// normalizeRemotes keeps the remote names, sorted, deduplicated, at most
// MaxRemotes.
func normalizeRemotes(in []string) []string {
	var out []string
	for _, r := range sortedSet(in) {
		if policy.IsRemoteName(r) && len(out) < MaxRemotes {
			out = append(out, r)
		}
	}
	return out
}

// normalizeHeld keeps the held commits with a full commit id (lower case),
// merged per commit, sorted, at most MaxHeld (overflow set beyond it);
// none when there is no history-only key.
func normalizeHeld(in []HeldCommit, overflow, any bool) ([]HeldCommit, bool) {
	if !any {
		return nil, false
	}
	by := map[string][]string{}
	for _, h := range in {
		c := strings.ToLower(h.Commit)
		if !fullCommitID(c) {
			continue
		}
		by[c] = append(by[c], h.Remotes...)
	}
	ids := make([]string, 0, len(by))
	for c := range by {
		ids = append(ids, c)
	}
	sort.Strings(ids)
	if len(ids) > MaxHeld {
		ids, overflow = ids[:MaxHeld], true
	}
	var out []HeldCommit
	for _, c := range ids {
		out = append(out, HeldCommit{Commit: c, Remotes: normalizeRemotes(by[c])})
	}
	return out, overflow
}

// fullCommitID reports a full lower-case hex commit id (40 or 64).
func fullCommitID(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// subsetOf keeps the members of xs (sorted) that are in set (sorted), nil
// when none is.
func subsetOf(xs, set []string) []string {
	var out []string
	for _, x := range xs {
		if i := sort.SearchStrings(set, x); i < len(set) && set[i] == x {
			out = append(out, x)
		}
	}
	return out
}

func sortedSet(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := append([]string(nil), in...)
	sort.Strings(out)
	n := 0
	for i, s := range out {
		if i > 0 && s == out[n-1] {
			continue
		}
		out[n] = s
		n++
	}
	return out[:n]
}

// canonical is the MAC input: the domain, then the JSON of the normalized
// file with its MAC cleared.
func canonical(f File) []byte {
	f = normalize(f)
	f.MAC = ""
	body, _ := json.Marshal(f)
	var b bytes.Buffer
	b.WriteString(MACDomain)
	b.WriteByte('\n')
	b.Write(body)
	return b.Bytes()
}

func mac(f File, key []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write(canonical(f))
	return hex.EncodeToString(h.Sum(nil))
}

// Sign returns f normalized and carrying its MAC under key.
func Sign(f File, key []byte) File {
	f = normalize(f)
	f.MAC = mac(f, key)
	return f
}

// Verify reports whether f carries a valid MAC under key.
func Verify(f *File, key []byte) bool {
	if f == nil || len(key) == 0 || f.MAC == "" {
		return false
	}
	want, err := hex.DecodeString(f.MAC)
	if err != nil {
		return false
	}
	got, _ := hex.DecodeString(mac(*f, key))
	return hmac.Equal(want, got)
}

// Encode renders f (normalized, MAC as given) as the bytes Write stores.
func Encode(f File) ([]byte, error) {
	data, err := json.Marshal(normalize(f))
	if err != nil {
		return nil, fmt.Errorf("secposture.Encode: %w", err)
	}
	return data, nil
}

// ErrTooLarge reports a posture file over MaxFileBytes.
var ErrTooLarge = errors.New("secposture: posture file over its size cap")

// Decode parses one posture file's bytes. Over the cap is ErrTooLarge; a
// foreign schema is an error.
func Decode(data []byte) (*File, error) {
	if len(data) > MaxFileBytes {
		return nil, ErrTooLarge
	}
	var f File
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("secposture.Decode: %w", err)
	}
	if f.Schema != SchemaVersion {
		return nil, errors.New("secposture.Decode: unsupported schema")
	}
	return &f, nil
}

// ReadKey loads the key file. A missing file is (nil, nil); a malformed
// one is an error.
func ReadKey(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("secposture.ReadKey: %w", err)
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != keyBytes {
		return nil, errors.New("secposture.ReadKey: malformed key file")
	}
	return key, nil
}

// LoadOrCreateKey returns the key at path, creating a fresh random one when
// the file is missing or malformed. Daemon only (the one writer).
func LoadOrCreateKey(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("secposture.LoadOrCreateKey: empty path")
	}
	if key, err := ReadKey(path); err == nil && key != nil {
		return key, nil
	}
	key := make([]byte, keyBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("secposture.LoadOrCreateKey: %w", err)
	}
	if err := fsatomic.WriteFile(path, []byte(hex.EncodeToString(key)+"\n"), fsatomic.Options{TempPattern: ".sec-posture-key-*.tmp"}); err != nil {
		return nil, fmt.Errorf("secposture.LoadOrCreateKey: %w", err)
	}
	return key, nil
}

// Write signs f under key and replaces the project's posture file
// atomically (the security.posture loop is the one writer). A file that
// would exceed MaxFileBytes is refused with ErrTooLarge: the writer caps
// the blocking list first, so this only fires on an oversized reason or
// count list.
func Write(l Layout, f File, key []byte) ([]byte, error) {
	path := l.PosturePath(f.ProjectRootHash)
	if path == "" {
		return nil, errors.New("secposture.Write: no path for the project hash")
	}
	if len(key) == 0 {
		return nil, errors.New("secposture.Write: no key")
	}
	data, err := Encode(Sign(f, key))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxFileBytes {
		return nil, ErrTooLarge
	}
	if err := fsatomic.WriteFile(path, data, fsatomic.Options{TempPattern: ".sec-posture-*.tmp"}); err != nil {
		return nil, fmt.Errorf("secposture.Write: %w", err)
	}
	return data, nil
}

// Remove deletes one project's posture file (a missing file is fine).
func Remove(l Layout, rootHash string) error {
	path := l.PosturePath(rootHash)
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("secposture.Remove: %w", err)
	}
	return nil
}

// RemoveAllPostures deletes every posture file and the key, at module
// deactivation (section 4.3: no sidecar file while inactive). The dirty
// markers and seen marks stay: they are monotonic and carry no findings.
func RemoveAllPostures(l Layout) error {
	dir := l.PostureDir()
	if dir == "" {
		return nil
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("secposture.RemoveAllPostures: %w", err)
	}
	return nil
}

// PostureHashes lists the project root hashes that have a posture file
// (the key and any other name are skipped). A missing directory lists
// none.
func PostureHashes(l Layout) ([]string, error) {
	return hashesIn(l.PostureDir(), PostureExt, time.Time{})
}

// hashesIn lists the valid project root hashes named by the regular files
// in dir (each name the hash plus ext), modified at or after since when
// since is set.
func hashesIn(dir, ext string, since time.Time) ([]string, error) {
	if dir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("secposture: list %s: %w", filepath.Base(dir), err)
	}
	var out []string
	for _, e := range entries {
		h, ok := strings.CutSuffix(e.Name(), ext)
		if !ok || !validHash(h) || !e.Type().IsRegular() {
			continue
		}
		if !since.IsZero() {
			fi, err := e.Info()
			if err != nil || fi.ModTime().Before(since) {
				continue
			}
		}
		out = append(out, h)
	}
	sort.Strings(out)
	return out, nil
}
