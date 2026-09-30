package mcprelay

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/agentid"
	"github.com/marmutapp/superbased-observer/internal/git"
)

// P11(e) relay-attested project context (doc3 §11.12b (e), R10.9). The relay
// RESOLVES the coding session's project itself - internal/git's project
// identity root, hashed with the resolver-v2 derivation
// (agentid.ProjectHashOfRoot) - and signs the result into its sbo-actor+jwt
// (sbo_project_hash) and into the node-local PDP principal. It never accepts
// a hash from a caller, and a directory that does not exist or does not
// resolve yields no project context at all (project-scoped grants then fail
// closed).
//
// Attestation sources (P11 fold PF2, the IE Q-IE-2 ruling) - exactly two:
//
//   - the stdio wrapper (`observer mcp-relay wrap`): the AI client spawned it
//     in the project, and it records its OWN working directory at spawn
//     (WrapperOptions.ProjectDir) - the caller never names a directory;
//   - the secret-bound IPC path: the hello's project_dir, on a stream the
//     per-client bootstrap secret binds to a registered product client
//     (ipc_bound).
//
// The loopback HTTP surface is NOT a source: its caller is the node-wide
// principal (R2), so HeaderProjectDir is ignored (the fail-closed choice -
// not "accepted as configured", which would still stamp a hash any local
// process could choose).

// HeaderProjectDir is the header name an older hook / launcher may still set
// on a loopback call. It is deliberately NOT honoured (loopback is not an
// attestation source, see above); the constant stays so tests can prove the
// header is ignored.
const HeaderProjectDir = "X-Sbo-Project-Dir"

// projectCacheTTL bounds how long a dir -> hash resolution is reused (a
// directory can become a git repo, or move between repos, meanwhile).
const projectCacheTTL = 5 * time.Minute

// projectCacheMax bounds the resolver cache (it is reset, not grown, past it).
const projectCacheMax = 256

// ErrNoProjectDir is GitProjectHash's refusal of a relative, missing or
// non-directory path.
var ErrNoProjectDir = errors.New("mcprelay: project dir must be an existing absolute directory")

// GitProjectHash resolves dir to its canonical project hash: the project
// identity root internal/git reports (the git root, or dir itself outside a
// repository) hashed by agentid.ProjectHashOfRoot.
func GitProjectHash(dir string) (string, error) {
	if dir == "" || !filepath.IsAbs(dir) {
		return "", ErrNoProjectDir
	}
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		return "", ErrNoProjectDir
	}
	id, err := git.ResolveIdentity(dir, git.IdentityOptions{SkipContentFingerprint: true})
	if err != nil {
		return "", fmt.Errorf("mcprelay.GitProjectHash: %w", err)
	}
	h := agentid.ProjectHashOfRoot(id.Root)
	if !agentid.ValidProjectHash(h) {
		return "", fmt.Errorf("mcprelay.GitProjectHash: no project root for %s", dir)
	}
	return h, nil
}

// ProjectResolver maps a session's declared working directory to the project
// hash the relay attests, with a small bounded TTL cache. It is the ONE
// owner of that mapping; the zero value is not usable - use
// NewProjectResolver.
type ProjectResolver struct {
	resolve func(dir string) (string, error)
	now     func() time.Time

	mu    sync.Mutex
	cache map[string]projectEntry
}

type projectEntry struct {
	hash string
	at   time.Time
}

// NewProjectResolver returns a resolver over resolve (nil -> GitProjectHash).
func NewProjectResolver(resolve func(dir string) (string, error)) *ProjectResolver {
	if resolve == nil {
		resolve = GitProjectHash
	}
	return &ProjectResolver{resolve: resolve, now: time.Now, cache: map[string]projectEntry{}}
}

// Hash returns the attested project hash of dir, or "" (no project context)
// when dir is empty or does not resolve. A nil resolver attests nothing.
func (p *ProjectResolver) Hash(dir string) string {
	if p == nil || dir == "" {
		return ""
	}
	dir = filepath.Clean(dir)
	now := p.now()
	p.mu.Lock()
	if e, ok := p.cache[dir]; ok && now.Sub(e.at) < projectCacheTTL {
		p.mu.Unlock()
		return e.hash
	}
	p.mu.Unlock()
	h, err := p.resolve(dir)
	if err != nil || !agentid.ValidProjectHash(h) {
		h = ""
	}
	p.mu.Lock()
	if len(p.cache) >= projectCacheMax {
		p.cache = map[string]projectEntry{}
	}
	p.cache[dir] = projectEntry{hash: h, at: now}
	p.mu.Unlock()
	return h
}
