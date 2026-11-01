package sandboxremote

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
)

// manifest.go is the upload manifest (sandbox plan v2 section 5.7, lane
// SBX-P7 "what leaves the machine"): the exact set of workspace files a
// remote box receives. The cmd layer lists the candidates (git's tracked
// plus untracked-not-ignored files under the workspace root, each lstat'd,
// never followed); this file decides, so the consent preview and the upload
// read the same answer.
//
// The rules, in order:
//   - the root is never the home directory, never above it, and never empty;
//   - a workspace that is not a git repository is never uploaded (no
//     surface let a user name one, so that dead path was removed at the
//     SBX-P7 merge, audit finding 8);
//   - a candidate outside the root (absolute, "..") is excluded;
//   - anything under .git is excluded (history never leaves the machine;
//     the box gets a fresh baseline repository of the uploaded tree);
//   - a symlink is excluded, never followed (in-root or not);
//   - anything not a regular file is excluded;
//   - a credential-shaped file is excluded and listed;
//   - a file over the per-file cap is excluded and listed;
//   - the total count and bytes over the caps refuse the upload (never a
//     silent partial upload).

// ManifestVersion moves with every rule change; it is part of the scope
// key, so a rule change re-asks for consent.
//
// 2: every name starting with .env is credential-shaped (.envrc, .env-prod,
// .env_local; the SBX-P7 merge's audit finding 4), and the non-repository
// path was removed.
const ManifestVersion = 2

// FileKind is what an lstat of a candidate found.
type FileKind string

// The closed FileKind vocabulary.
const (
	KindRegular FileKind = "regular"
	KindSymlink FileKind = "symlink"
	KindDir     FileKind = "dir"
	KindOther   FileKind = "other"
)

// Candidate is one listed workspace path.
type Candidate struct {
	// Path is slash-separated and relative to the workspace root.
	Path string
	Kind FileKind
	Size int64
}

// ManifestLimits bound one upload.
type ManifestLimits struct {
	MaxFiles     int
	MaxBytes     int64
	MaxFileBytes int64
}

// DefaultManifestLimits are the shipped caps: 20000 files, 512 MiB in all,
// 64 MiB per file.
var DefaultManifestLimits = ManifestLimits{MaxFiles: 20000, MaxBytes: 512 << 20, MaxFileBytes: 64 << 20}

// ManifestInput is what one manifest is planned from.
type ManifestInput struct {
	// Root and Home are cleaned absolute slash paths (the cmd layer converts
	// them).
	Root string
	Home string
	// Repository: the root is a git working tree; its candidates come from
	// git's index and untracked-not-ignored listing.
	Repository bool
	Candidates []Candidate
	Limits     ManifestLimits
}

// ManifestFile is one file the box receives.
type ManifestFile struct {
	Path string
	Size int64
}

// Exclusion is one candidate that stays home, with its reason.
type Exclusion struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// The closed exclusion reasons.
const (
	ExcludeOutsideRoot     = "outside_root"
	ExcludeGitDir          = "git_dir"
	ExcludeSymlink         = "symlink_not_followed"
	ExcludeNotRegular      = "not_a_regular_file"
	ExcludeCredentialShape = "credential_shaped" //nolint:gosec // G101: an exclusion reason, not a credential
	ExcludeTooLarge        = "over_file_cap"
)

// Manifest is the planned upload.
type Manifest struct {
	Root     string
	Files    []ManifestFile
	Excluded []Exclusion
	Count    int
	Bytes    int64
	// ScopeKey names the rules and the root (not the contents): consent is
	// bound to it, so editing a file never re-asks, a different root or a
	// rule change does.
	ScopeKey string
}

// The manifest refusal codes.
var (
	ErrScopeHome          = errors.New("upload_scope_home")
	ErrScopeNotRepository = errors.New("upload_scope_not_repository")
	ErrScopeTooLarge      = errors.New("upload_scope_too_large")
	ErrScopeRoot          = errors.New("upload_scope_root")
)

// PlanManifest applies the rules.
func PlanManifest(in ManifestInput) (Manifest, error) {
	root := path.Clean(in.Root)
	home := path.Clean(in.Home)
	lim := in.Limits
	if lim == (ManifestLimits{}) {
		lim = DefaultManifestLimits
	}
	switch {
	case in.Root == "" || !path.IsAbs(root) || root == "/":
		return Manifest{}, fmt.Errorf("%w: the workspace root %q is not an absolute directory below /", ErrScopeRoot, in.Root)
	case in.Home != "" && (root == home || within(home, root)):
		return Manifest{}, fmt.Errorf("%w: the workspace root %s is the home directory or holds it; the home directory is never uploaded", ErrScopeHome, root)
	case !in.Repository:
		return Manifest{}, fmt.Errorf("%w: %s is not a git repository; only a repository's tracked and untracked-not-ignored files are uploaded", ErrScopeNotRepository, root)
	}
	m := Manifest{Root: root, ScopeKey: ScopeKey(root, in.Repository, lim)}
	seen := map[string]bool{}
	for _, c := range in.Candidates {
		p, reason := classify(c, lim)
		if reason != "" {
			m.Excluded = append(m.Excluded, Exclusion{Path: c.Path, Reason: reason})
			continue
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		m.Files = append(m.Files, ManifestFile{Path: p, Size: c.Size})
		m.Count++
		m.Bytes += c.Size
	}
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })
	sort.Slice(m.Excluded, func(i, j int) bool { return m.Excluded[i].Path < m.Excluded[j].Path })
	if m.Count > lim.MaxFiles || m.Bytes > lim.MaxBytes {
		return m, fmt.Errorf("%w: %d files and %d bytes, over the caps of %d files and %d bytes; narrow the workspace", ErrScopeTooLarge, m.Count, m.Bytes, lim.MaxFiles, lim.MaxBytes)
	}
	return m, nil
}

// classify returns the cleaned path, or the exclusion reason.
func classify(c Candidate, lim ManifestLimits) (string, string) {
	p := c.Path
	if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, "\\") || strings.ContainsRune(p, 0) {
		return "", ExcludeOutsideRoot
	}
	p = path.Clean(p)
	if p == "." || p == ".." || strings.HasPrefix(p, "../") {
		return "", ExcludeOutsideRoot
	}
	for _, part := range strings.Split(p, "/") {
		if part == ".git" {
			return "", ExcludeGitDir
		}
	}
	switch c.Kind {
	case KindSymlink:
		return "", ExcludeSymlink
	case KindRegular:
	default:
		return "", ExcludeNotRegular
	}
	if CredentialShaped(p) {
		return "", ExcludeCredentialShape
	}
	if c.Size < 0 || c.Size > lim.MaxFileBytes {
		return "", ExcludeTooLarge
	}
	return p, ""
}

// credentialDirs are directory components whose contents are credentials.
var credentialDirs = map[string]bool{".aws": true, ".azure": true, ".kube": true, ".ssh": true, ".gnupg": true, ".docker": true}

// credentialNames are exact base names that hold credentials.
var credentialNames = map[string]bool{
	".netrc": true, "_netrc": true, ".npmrc": true, ".pypirc": true, ".git-credentials": true,
	"credentials": true, "credentials.json": true, "application_default_credentials.json": true,
	"kubeconfig": true, ".dockercfg": true, "service-account.json": true,
}

// credentialSuffixes are extensions that hold keys or certificates.
var credentialSuffixes = []string{".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".ppk", ".asc", ".gpg"}

// CredentialShaped reports whether a slash path looks like a credential:
// every name starting with .env (.env, .env.local, .envrc, .env-prod,
// .env_local), keys and certificates, ssh identities
// (id_rsa, id_ed25519 and their .pub), .netrc, .npmrc, .pypirc, git
// credentials, and the cloud credential files and directories. The id_*
// rule matches identity files only (no extension, or .pub), so a source
// file named id_test.go is not caught.
func CredentialShaped(p string) bool {
	p = path.Clean(p)
	parts := strings.Split(p, "/")
	for _, d := range parts[:len(parts)-1] {
		if credentialDirs[d] {
			return true
		}
	}
	if strings.Contains(p, ".config/gcloud/") {
		return true
	}
	base := parts[len(parts)-1]
	lower := strings.ToLower(base)
	switch {
	case credentialNames[lower]:
		return true
	case strings.HasPrefix(lower, ".env"):
		return true
	case strings.HasPrefix(lower, "id_") && (!strings.Contains(lower, ".") || strings.HasSuffix(lower, ".pub")):
		return true
	}
	for _, s := range credentialSuffixes {
		if strings.HasSuffix(lower, s) {
			return true
		}
	}
	return false
}

// ScopeKey names an upload scope: the root, the repository mode, the caps
// and the rule version, hashed.
func ScopeKey(root string, repository bool, lim ManifestLimits) string {
	h := sha256.New()
	fmt.Fprintf(h, "v%d\x00%s\x00%t\x00%d\x00%d\x00%d", ManifestVersion, path.Clean(root), repository, lim.MaxFiles, lim.MaxBytes, lim.MaxFileBytes)
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// Summary is the one-line preview of a manifest.
func (m Manifest) Summary() string {
	return strconv.Itoa(m.Count) + " files, " + humanBytes(m.Bytes) + ", " + strconv.Itoa(len(m.Excluded)) + " excluded"
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return strconv.FormatFloat(float64(n)/(1<<30), 'f', 1, 64) + " GiB"
	case n >= 1<<20:
		return strconv.FormatFloat(float64(n)/(1<<20), 'f', 1, 64) + " MiB"
	case n >= 1<<10:
		return strconv.FormatFloat(float64(n)/(1<<10), 'f', 1, 64) + " KiB"
	}
	return strconv.FormatInt(n, 10) + " B"
}

// within reports whether p is inside root (not equal).
func within(p, root string) bool {
	return strings.HasPrefix(p, strings.TrimSuffix(root, "/")+"/")
}
