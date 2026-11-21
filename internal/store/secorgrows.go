package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// secorgrows.go owns the security pillar's org wire on the node (security
// plan 7.4, lane SEC-E2): the READS over the node-local sec_* tables the
// SecurityOrgProviders seam binds, and composeSecurity, the one function
// orgpush.go calls. orgpush.go names no sec_* table (the privacy sentinel
// forbids it there); this file does, read-only. The one writer of those
// tables stays internal/store/secfindings.go.
//
// Nothing is composed unless the cmd layer bound the providers, which it
// does only while the `security` module is active
// (cmd/observer/security_orgpush.go), and unless the share level allows:
// with no providers or level off the envelope is byte-identical to a build
// without this file.

// secOrgFindingWindow keeps a closed finding on the wire this long after it
// closed, so the org sees the close; open findings ship whatever their age.
const secOrgFindingWindow = 30 * 24 * time.Hour

// SecurityShare is one push's resolved security share: the level and
// whether this node holds the org dedupe key (so it may ship org_key).
type SecurityShare struct {
	Level       string
	HoldsOrgKey bool
}

// SetSecurityOrgProviders wires the security wire seam. The zero value
// unbinds it, and with it every security row.
func (s *Store) SetSecurityOrgProviders(p SecurityOrgProviders) { s.secOrg = p }

// SecurityOrgBound reports whether the security wire seam is bound (the
// daemon binds it wherever it runs the push loop, cmd/observer/start.go).
func (s *Store) SecurityOrgBound() bool { return s.secOrg.Level != nil }

// SecurityScope is one push's project scope over the sec_* tables'
// project_root_hash key (lane SEC-E2 audit finding 1): the [org_client]
// project allow and deny lists, exactly as the delivery rows honour them, so
// the findings and the posture counts of a project outside the scope never
// ship. The zero value admits every project.
type SecurityScope struct {
	allow map[string]bool // nil: every project
	deny  map[string]bool
}

// Admits reports whether a project root hash is inside the scope.
func (s SecurityScope) Admits(rootHash string) bool {
	if s.deny[rootHash] {
		return false
	}
	return s.allow == nil || s.allow[rootHash]
}

func (s SecurityScope) scoped() bool { return s.allow != nil || len(s.deny) > 0 }

// where is the SQL restriction of col to the scope (" AND ..." or "") and
// its arguments.
func (s SecurityScope) where(col string) (string, []any) {
	var b strings.Builder
	var args []any
	if s.allow != nil {
		b.WriteString(" AND " + col + " IN (SELECT value FROM json_each(?))")
		args = append(args, secScopeList(s.allow))
	}
	if len(s.deny) > 0 {
		b.WriteString(" AND " + col + " NOT IN (SELECT value FROM json_each(?))")
		args = append(args, secScopeList(s.deny))
	}
	return b.String(), args
}

// digest is a stable fingerprint of the scope for the change probes.
func (s SecurityScope) digest() string {
	if !s.scoped() {
		return "all"
	}
	allow := "*"
	if s.allow != nil {
		allow = secScopeList(s.allow)
	}
	sum := sha256.Sum256([]byte(allow + "\x00" + secScopeList(s.deny)))
	return hex.EncodeToString(sum[:8])
}

func secScopeList(m map[string]bool) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	b, _ := json.Marshal(keys)
	return string(b)
}

// maxScopeWorktrees caps the linked worktree checkouts securityScope adds
// per listed root (the trust baseline's 200-root cap).
const maxScopeWorktrees = 200

// securityScope maps the push's ScopeOptions onto project root hashes: each
// listed root's sha256 as listed and as normalized (the spelling
// secposture.ProjectRootHash and projects.root_path_hash share), plus the
// stored root_path_hash of the project with that root, and the same three
// for each linked worktree checkout of that root (git.LinkedWorktreeCheckouts).
// An allowlist that
// names no project admits nothing (fail closed, as resolveScopeFilter's
// noMatch does).
func (s *Store) securityScope(ctx context.Context, scope ScopeOptions) (SecurityScope, error) {
	if !scope.IsScoped() {
		return SecurityScope{}, nil
	}
	hashes := func(roots []string) (map[string]bool, error) {
		out := map[string]bool{}
		add := func(rp string) error {
			out[sha256Hex(rp)] = true
			out[sha256Hex(normalizeProjectRoot(rp))] = true
			var h sql.NullString
			err := s.db.QueryRowContext(ctx, `SELECT root_path_hash FROM projects WHERE root_path = ?`, rp).Scan(&h)
			switch {
			case errors.Is(err, sql.ErrNoRows):
			case err != nil:
				return err
			case h.String != "":
				out[h.String] = true
			}
			return nil
		}
		for _, rp := range roots {
			if rp == "" {
				continue
			}
			if err := add(rp); err != nil {
				return nil, err
			}
			// A listed project's linked worktree checkouts: the trust
			// baseline and custom scanners keep a worktree's findings under
			// the checkout's own hash, so the deny list and the allow list
			// cover them too (audit finding 2, lane shr-worktree2).
			for _, wt := range git.LinkedWorktreeCheckouts(rp, maxScopeWorktrees) {
				if err := add(wt); err != nil {
					return nil, err
				}
			}
		}
		return out, nil
	}
	var out SecurityScope
	var err error
	if len(scope.ProjectRootAllowlist) > 0 {
		if out.allow, err = hashes(scope.ProjectRootAllowlist); err != nil {
			return out, fmt.Errorf("store.securityScope: %w", err)
		}
	}
	if out.deny, err = hashes(scope.ProjectRootDenylist); err != nil {
		return out, fmt.Errorf("store.securityScope: %w", err)
	}
	return out, nil
}

// secProbeSalt holds the security change-probe salt (lane SEC-E2 audit
// finding 7). composeSecurity sets it before it consults the snapshot gate;
// the probes in secorgrows_reads.go append it.
type secProbeSalt struct {
	mu sync.Mutex
	v  string
}

func (p *secProbeSalt) set(v string) {
	p.mu.Lock()
	p.v = v
	p.mu.Unlock()
}

func (p *secProbeSalt) get() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.v
}

// securityProbeSalt is what a re-send depends on besides the sec_* rows:
// the share level, the raw-content flag, the org-key state and the scope.
func securityProbeSalt(lvl SecurityShare, raw bool, scope SecurityScope) string {
	return lvl.Level + "|" + strconv.FormatBool(raw) + "|" + strconv.FormatBool(lvl.HoldsOrgKey) + "|" + scope.digest()
}

// secWireScan is internal/scrub's detector for the P-055 secret gate
// (orgcontract.GateSecuritySecrets), the same one the server runs.
var secWireScan = orgcontract.SecuritySecretScan{
	Certain: func(v string) bool { return len(scrub.CertainSecretTypes(v)) > 0 },
	Any:     func(v string) bool { return len(scrub.DetectSecrets(v)) > 0 },
	Mask: func(v string) string {
		m, _ := scrub.MaskSecrets(v, func(scrub.TypedFinding) bool { return true })
		return m
	},
}

// ResolveSecurityShareFacts is what ResolveSecurityShare decides on.
type ResolveSecurityShareFacts struct {
	// Managed: a managed-tenancy enrolment whose grant is in force.
	Managed bool
	// PullLevel is finding_share of the in-force security managed pull, ""
	// when none is in force or it sets none.
	PullLevel string
	// PullOrgKey: the in-force pull carries the org dedupe key.
	PullOrgKey bool
	// LocalLevel is [org_client.share].security.
	LocalLevel string
}

// securityShareRules is the ordered share table (CLAUDE.md rule 5), walked
// top-down; the first row that matches decides. An individual node is
// decided by its own key only (never remote, Q7): unset is posture (ruling
// R1 of lane CODESEC-ORG, 2026-11-03), an explicit "off" or an unknown
// value is off. A managed node is decided by the org's pull, posture by
// default.
var securityShareRules = []struct {
	match func(f ResolveSecurityShareFacts) bool
	level func(f ResolveSecurityShareFacts) string
}{
	{func(f ResolveSecurityShareFacts) bool { return !f.Managed && f.LocalLevel == "" }, func(ResolveSecurityShareFacts) string { return orgcontract.SecuritySharePosture }},
	{func(f ResolveSecurityShareFacts) bool { return !f.Managed }, func(f ResolveSecurityShareFacts) string { return knownShareLevel(f.LocalLevel) }},
	{func(f ResolveSecurityShareFacts) bool { return f.PullLevel != "" }, func(f ResolveSecurityShareFacts) string { return knownShareLevel(f.PullLevel) }},
	{func(ResolveSecurityShareFacts) bool { return true }, func(ResolveSecurityShareFacts) string { return orgcontract.SecuritySharePosture }},
}

// knownShareLevel maps an unknown or empty level to off (fail closed).
func knownShareLevel(v string) string {
	for _, l := range orgcontract.SecurityShareLevels {
		if v == l {
			return v
		}
	}
	return orgcontract.SecurityShareOff
}

// ResolveSecurityShare is the node's security share for one push. The org
// dedupe key is held only on a managed node whose in-force pull carries it
// and only at the findings level (an individual node never receives it).
func ResolveSecurityShare(f ResolveSecurityShareFacts) SecurityShare {
	out := SecurityShare{Level: orgcontract.SecurityShareOff}
	for _, r := range securityShareRules {
		if r.match(f) {
			out.Level = r.level(f)
			break
		}
	}
	out.HoldsOrgKey = f.Managed && f.PullOrgKey && out.Level == orgcontract.SecurityShareFindings
	return out
}

// composeSecurity composes the security wire into batch (orgpush.go's one
// call). The posture row ships at posture and findings levels, the finding
// and change-record rows at findings only; only the projects inside the
// push's scope are read; every row is normalized, raw fields are stripped
// unless share.shipsRawContent(), org_key is cleared unless the node holds
// the org dedupe key, and the P-055 secret gate runs last (a row it refuses
// does not ship).
func (s *Store) composeSecurity(ctx context.Context, batch *PushBatch, budget *envelopeBudget, orgID, userEmail string, share ShareOptions, scope ScopeOptions) error {
	p := s.secOrg
	if p.Level == nil {
		return nil
	}
	lvl := p.Level(ctx, share)
	if lvl.Level != orgcontract.SecuritySharePosture && lvl.Level != orgcontract.SecurityShareFindings {
		return nil
	}
	sc, err := s.securityScope(ctx, scope)
	if err != nil {
		return fmt.Errorf("store.composeSecurity: %w", err)
	}
	raw := share.shipsRawContent()
	s.secSalt.set(securityProbeSalt(lvl, raw, sc))
	if p.Posture != nil && s.snapChanged(ctx, snapFamSecurityPosture) {
		row, ok, err := p.Posture(ctx, time.Now().UTC().Format("2006-01-02"), sc)
		if err != nil {
			return fmt.Errorf("store.composeSecurity: posture: %w", err)
		}
		if ok {
			row.OrgID, row.UserEmail, row.ShareLevel = orgID, userEmail, lvl.Level
			if row, ok = orgcontract.NormalizeSecurityPosture(row); ok {
				if err := orgcontract.StripSecurityRaw(&row, raw); err != nil {
					return fmt.Errorf("store.composeSecurity: %w", err)
				}
				if orgcontract.GateSecuritySecrets(&row, secWireScan) {
					batch.SecurityPosture = fitSnapshot(s, budget, snapFamSecurityPosture, []orgcontract.SecurityPostureRow{row})
				}
			}
		}
	}
	if lvl.Level != orgcontract.SecurityShareFindings {
		return nil
	}
	if p.Findings != nil && s.snapChanged(ctx, snapFamSecurityFindings) {
		rows, err := p.Findings(ctx, orgcontract.MaxSecurityRowsPerPush, sc)
		if err != nil {
			return fmt.Errorf("store.composeSecurity: findings: %w", err)
		}
		out := make([]orgcontract.SecurityFindingRow, 0, len(rows))
		for _, r := range rows {
			r.OrgID, r.UserEmail = orgID, userEmail
			if !lvl.HoldsOrgKey {
				r.OrgKey = ""
			}
			n, ok := orgcontract.NormalizeSecurityFinding(r)
			if !ok {
				continue
			}
			if err := orgcontract.StripSecurityRaw(&n, raw); err != nil {
				return fmt.Errorf("store.composeSecurity: %w", err)
			}
			if !orgcontract.GateSecuritySecrets(&n, secWireScan) {
				continue
			}
			out = append(out, n)
		}
		batch.SecurityFindings = fitSnapshot(s, budget, snapFamSecurityFindings, out)
	}
	// The change records (lane SEC-F2A) are gated like the findings: an
	// unbound provider (security.provenance not selected) costs nothing,
	// and a bound one whose loop is not up yet is skipped, never committed
	// empty (audit finding F6).
	if p.ChangeRecords != nil && (p.ChangeRecordsLive == nil || p.ChangeRecordsLive()) && s.snapChanged(ctx, snapFamSecurityChangeRecords) {
		rows, err := p.ChangeRecords(ctx, orgcontract.MaxSecurityRowsPerPush, sc)
		if err != nil {
			return fmt.Errorf("store.composeSecurity: change records: %w", err)
		}
		out := make([]orgcontract.AIChangeRecordRow, 0, len(rows))
		for _, r := range rows {
			r.OrgID, r.UserEmail = orgID, userEmail
			n, ok := orgcontract.NormalizeAIChangeRecord(r)
			if !ok {
				continue
			}
			if err := orgcontract.StripSecurityRaw(&n, raw); err != nil {
				return fmt.Errorf("store.composeSecurity: %w", err)
			}
			if !orgcontract.GateSecuritySecrets(&n, secWireScan) {
				continue
			}
			out = append(out, n)
		}
		batch.AIChangeRecords = fitSnapshot(s, budget, snapFamSecurityChangeRecords, out)
	}
	return nil
}

// SecurityFindingRef is the opaque per-node handle of a finding on the wire:
// a domain-separated digest of the node-local id, never the id itself.
func SecurityFindingRef(id string) string {
	sum := sha256.Sum256([]byte("sbo-secfinding-ref-v1\x00" + id))
	return hex.EncodeToString(sum[:16])
}

// secFreshnessBuckets is the scan-freshness table, walked top-down.
var secFreshnessBuckets = []struct {
	under  time.Duration
	bucket string
}{
	{time.Hour, "under_1h"},
	{24 * time.Hour, "under_1d"},
	{7 * 24 * time.Hour, "under_7d"},
}

func secFreshness(newest string, now time.Time) string {
	t, err := time.Parse(time.RFC3339Nano, newest)
	if newest == "" || err != nil {
		return "never"
	}
	age := now.Sub(t)
	for _, b := range secFreshnessBuckets {
		if age < b.under {
			return b.bucket
		}
	}
	return "over_7d"
}
