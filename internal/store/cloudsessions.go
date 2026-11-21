package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// SetSessionExecution stamps the cloud-execution attribution (agent
// migration 240: sessions.execution_location / sessions.vendor_session_ref)
// onto an existing session row. It is the ONE write path for those columns;
// UpsertSession never touches them, so a re-parse that carries no
// attribution can never clear a stamped value.
//
// SEMANTICS: FIRST-WINS-UNLESS-EMPTY, per column, the SetSessionSurface
// shape. Where a session ran and which vendor reference it carries are
// properties of its ORIGIN; the first grounded stamp sticks and a later stamp
// can only FILL a column that is still empty. The two columns are
// independent: a stamp carrying only a reference fills an empty
// vendor_session_ref and leaves a stamped location alone.
//
// The returned bool reports whether the UPDATE changed anything: true only
// when an empty column became non-empty. An identical re-stamp, a differing
// later stamp and an all-empty stamp return false. A missing session id is a
// silent no-op (a capture path may see the marker before the row exists; the
// next pass re-stamps).
//
// Validation is STRICT: the location must be a models.KnownExecutionLocation
// kind and the reference must pass orgcontract.ValidVendorSessionRef (the
// same grammar the org ingest re-checks). A capture path that leaks a raw
// vendor token or a free-text field is a programming error and fails loudly
// here rather than persisting it.
func (s *Store) SetSessionExecution(ctx context.Context, ex models.SessionExecution) (bool, error) {
	if ex.SessionID == "" {
		return false, errors.New("store.SetSessionExecution: SessionID is required")
	}
	if ex.ExecutionLocation != "" && !models.KnownExecutionLocation(ex.ExecutionLocation) {
		return false, fmt.Errorf("store.SetSessionExecution: unknown execution location %q (session %s) - resolve vendor markers through a table", ex.ExecutionLocation, ex.SessionID)
	}
	if ex.VendorSessionRef != "" && !orgcontract.ValidVendorSessionRef(ex.VendorSessionRef) {
		return false, fmt.Errorf("store.SetSessionExecution: malformed vendor session reference (session %s): want orgcontract.ValidVendorSessionRef", ex.SessionID)
	}
	if ex.ExecutionLocation == "" && ex.VendorSessionRef == "" {
		return false, nil
	}
	res, err := s.db.ExecContext(
		ctx,
		`UPDATE sessions SET
		   execution_location = COALESCE(NULLIF(execution_location, ''), NULLIF(?, '')),
		   vendor_session_ref = COALESCE(NULLIF(vendor_session_ref, ''), NULLIF(?, ''))
		 WHERE id = ?
		   AND ( (? != '' AND IFNULL(execution_location, '') = '')
		      OR (? != '' AND IFNULL(vendor_session_ref, '') = '') )`,
		ex.ExecutionLocation, ex.VendorSessionRef, ex.SessionID,
		ex.ExecutionLocation, ex.VendorSessionRef,
	)
	if err != nil {
		return false, fmt.Errorf("store.SetSessionExecution: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// LoadSessionExecution returns the stored cloud-execution attribution for a
// session. Both fields are "" when the session exists but nothing stamped it
// (the honest unknown). sql.ErrNoRows propagates unwrapped when the session
// does not exist so callers can 404.
func (s *Store) LoadSessionExecution(ctx context.Context, sessionID string) (models.SessionExecution, error) {
	out := models.SessionExecution{SessionID: sessionID}
	if sessionID == "" {
		return out, errors.New("store.LoadSessionExecution: sessionID is required")
	}
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT COALESCE(execution_location, ''), COALESCE(vendor_session_ref, '') FROM sessions WHERE id = ?`,
		sessionID,
	).Scan(&out.ExecutionLocation, &out.VendorSessionRef); err != nil {
		return out, err // sql.ErrNoRows propagates to the caller unwrapped.
	}
	return out, nil
}

// SessionIDByVendorRef returns the id of the session of tool that carries
// vendor reference ref (the cross-rail join of CA-D2 / CA-D12: a second rail
// that knows only the vendor's secondary reference finds the session the
// first rail created). ok is false when no session matches. Should two
// sessions of one tool ever carry the same reference, the earliest started
// one wins, then the lowest id, so the answer is deterministic.
func (s *Store) SessionIDByVendorRef(ctx context.Context, tool, ref string) (string, bool, error) {
	if tool == "" || ref == "" {
		return "", false, errors.New("store.SessionIDByVendorRef: tool and ref are required")
	}
	var id string
	err := s.db.QueryRowContext(
		ctx,
		`SELECT id FROM sessions
		  WHERE vendor_session_ref = ? AND tool = ?
		  ORDER BY started_at, id
		  LIMIT 1`,
		ref, tool,
	).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("store.SessionIDByVendorRef: %w", err)
	}
	return id, true, nil
}

// RemoteProject is one projects row matched by normalized git remote.
type RemoteProject struct {
	ID       int64
	RootPath string
	// Synthetic is true for a "cloud:<remote>" root created for a
	// remote-only session (models.IsSyntheticCloudProjectRoot).
	Synthetic bool
}

// remoteProjectPreference is the ordered rule table that picks one project
// when several rows share a normalized remote. Walked top-down; the first
// rule that tells two candidates apart decides.
var remoteProjectPreference = []struct {
	name string
	less func(a, b RemoteProject) (decided, aFirst bool)
}{
	// 1. A real local checkout beats a synthetic cloud root (CA-D3: "first an
	//    existing local project with the same git_remote").
	{"local before synthetic", func(a, b RemoteProject) (bool, bool) {
		if a.Synthetic == b.Synthetic {
			return false, false
		}
		return true, !a.Synthetic
	}},
	// 2. The oldest row (lowest id) wins, so the answer never depends on
	//    scan order.
	{"oldest row", func(a, b RemoteProject) (bool, bool) {
		if a.ID == b.ID {
			return false, false
		}
		return true, a.ID < b.ID
	}},
}

func sortRemoteProjects(c []RemoteProject) {
	sort.SliceStable(c, func(i, j int) bool {
		for _, r := range remoteProjectPreference {
			if decided, first := r.less(c[i], c[j]); decided {
				return first
			}
		}
		return false
	})
}

// loadProjectsByRemote groups every projects row that carries a git remote by
// its normalized remote. projects.git_remote holds the RAW remote
// (git.Resolve's Info.Remote), so normalization happens here, in Go, with the
// one normalizer (internal/git.NormalizeRemote). Each group is sorted by
// remoteProjectPreference.
func (s *Store) loadProjectsByRemote(ctx context.Context) (map[string][]RemoteProject, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, root_path, git_remote FROM projects
		  WHERE git_remote IS NOT NULL AND git_remote <> '' ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("store.loadProjectsByRemote: %w", err)
	}
	defer rows.Close()
	out := map[string][]RemoteProject{}
	for rows.Next() {
		var p RemoteProject
		var remote string
		if err := rows.Scan(&p.ID, &p.RootPath, &remote); err != nil {
			return nil, fmt.Errorf("store.loadProjectsByRemote: scan: %w", err)
		}
		norm := git.NormalizeRemote(remote)
		if norm == "" {
			continue
		}
		p.Synthetic = models.IsSyntheticCloudProjectRoot(p.RootPath)
		out[norm] = append(out[norm], p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.loadProjectsByRemote: rows: %w", err)
	}
	for k := range out {
		sortRemoteProjects(out[k])
	}
	return out, nil
}

// ProjectByRemote returns the project a remote-only session belongs to, by
// normalized git remote (CA-D3): an existing local project with that remote
// if there is one, else the synthetic "cloud:<remote>" project if it was
// already created, else ok=false. The input is normalized again
// (NormalizeRemote is idempotent), so a raw remote works too.
func (s *Store) ProjectByRemote(ctx context.Context, remote string) (RemoteProject, bool, error) {
	norm := git.NormalizeRemote(remote)
	if norm == "" {
		return RemoteProject{}, false, errors.New("store.ProjectByRemote: remote is required")
	}
	groups, err := s.loadProjectsByRemote(ctx)
	if err != nil {
		return RemoteProject{}, false, err
	}
	if c := groups[norm]; len(c) > 0 {
		return c[0], true, nil
	}
	return RemoteProject{}, false, nil
}

// errNotARemote rejects a remote that git.NormalizeRemote returned unchanged
// because it is a filesystem path, not a hosted repository: a synthetic
// project named after a local path would be a fabricated identity.
var errNotARemote = errors.New("store.ResolveRemoteProject: remote is not a hosted git remote")

// hostedRemote reports whether a normalized remote has the "<host>/<path>"
// shape NormalizeRemote gives a real hosted repository.
func hostedRemote(norm string) bool {
	if norm == "" || strings.ContainsAny(norm, " \t\r\n\\") {
		return false
	}
	if strings.HasPrefix(norm, "/") || strings.HasPrefix(norm, ".") || strings.HasPrefix(norm, "~") {
		return false
	}
	host, path, ok := strings.Cut(norm, "/")
	return ok && host != "" && path != ""
}

// ResolveRemoteProject returns the projects row id a remote-only session is
// filed under (CA-D3): the project ProjectByRemote finds, else a new
// synthetic project with root "cloud:<normalized-remote>" and that remote,
// created through UpsertProject (so the org wire carries its root and remote
// hashes like any project). The org project resolver's remote rule then folds
// a synthetic project onto the developer's local one; on this node
// CloudProjectTwins pairs them once a local checkout appears.
func (s *Store) ResolveRemoteProject(ctx context.Context, remote string) (int64, error) {
	norm := git.NormalizeRemote(remote)
	if !hostedRemote(norm) {
		return 0, errNotARemote
	}
	p, ok, err := s.ProjectByRemote(ctx, norm)
	if err != nil {
		return 0, err
	}
	if ok {
		return p.ID, nil
	}
	id, err := s.UpsertProject(ctx, models.SyntheticCloudProjectRoot(norm), norm)
	if err != nil {
		return 0, fmt.Errorf("store.ResolveRemoteProject: %w", err)
	}
	return id, nil
}

// CloudProjectTwin pairs a synthetic cloud project with the local project
// that carries the same normalized remote.
type CloudProjectTwin struct {
	SyntheticID int64
	LocalID     int64
	Remote      string // normalized
}

// CloudProjectTwins returns, for every synthetic "cloud:" project whose
// normalized remote is also carried by a real local project, the pair to
// merge: the one merge rule of plan section 4.3 (the node Projects page groups
// a synthetic cloud project under its local twin when one appears later). The
// local side is the remoteProjectPreference winner among real projects. Pairs
// are ordered by synthetic id. Read-only; the rows themselves are never
// rewritten, so a twin that later disappears simply stops pairing.
func (s *Store) CloudProjectTwins(ctx context.Context) ([]CloudProjectTwin, error) {
	groups, err := s.loadProjectsByRemote(ctx)
	if err != nil {
		return nil, err
	}
	var out []CloudProjectTwin
	for remote, c := range groups {
		if len(c) == 0 || c[0].Synthetic {
			continue // no real local project carries this remote
		}
		for _, p := range c[1:] {
			if p.Synthetic {
				out = append(out, CloudProjectTwin{SyntheticID: p.ID, LocalID: c[0].ID, Remote: remote})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SyntheticID < out[j].SyntheticID })
	return out, nil
}
