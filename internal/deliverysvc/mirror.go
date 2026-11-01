package deliverysvc

import (
	"context"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/delivery"
	"github.com/marmutapp/superbased-observer/internal/deliverynet"
)

// The mirror statuses this package writes (delivery.Mirror.Status).
const (
	MirrorOK      = "ok"
	MirrorCloning = "cloning"
	MirrorFailed  = "failed"
	MirrorOverCap = "over_cap"
	// MirrorNeedsCredentials is a mirror whose clone, ls-remote or fetch
	// stopped at a credential prompt it is never allowed to show
	// (deliverynet.KindNeedsNonInteractive). The UI reads it as "Needs
	// non-interactive credentials".
	MirrorNeedsCredentials = string(deliverynet.KindNeedsNonInteractive)
)

// failureStatus is the mirror status a failed git operation leaves: the
// refused credential prompt has its own status, everything else is
// fallback (MirrorFailed for a clone, the unchanged status for a refresh).
func failureStatus(err error, fallback string) string {
	if deliverynet.KindOf(err) == deliverynet.KindNeedsNonInteractive {
		return MirrorNeedsCredentials
	}
	return fallback
}

// needsClone reports whether a mirror row still needs its first clone: no
// row, or a row that never completed one. A mirror that cloned once and
// later hit a credential prompt on refresh keeps its directory and is
// refreshed, not cloned again.
func needsClone(m delivery.Mirror, found bool) bool {
	if !found {
		return true
	}
	if m.Status == MirrorNeedsCredentials && !m.LastRefreshAt.IsZero() {
		return false
	}
	return m.Status != MirrorOK
}

// Mirror pass results (RepoResult.Status).
const (
	resultCloned    = "cloned"
	resultRefreshed = "refreshed"
	resultUnchanged = "unchanged"
	resultNotDue    = "not_due"
)

// scheduledMirrors refreshes the mirrors of projects that opted into a
// refresh schedule, for remotes no provider link serves.
func (s *Service) scheduledMirrors(ctx context.Context, now time.Time, touched map[int64]bool) {
	settings, err := s.o.Store.ListDeliveryProjectSettings(ctx)
	if err != nil {
		s.o.Logger.Warn("delivery: list project settings", "err", err)
		return
	}
	var links []delivery.ProviderLink
	loaded := false
	for _, ps := range settings {
		every := scheduleOf(ps.ScheduleMinutes)
		if !ps.MirrorEnabled || every == 0 || ctx.Err() != nil {
			continue
		}
		if !loaded {
			if links, err = s.o.Store.ListProviderLinks(ctx); err != nil {
				s.o.Logger.Warn("delivery: list links", "err", err)
				return
			}
			loaded = true
		}
		remotes, err := s.o.Store.LoadProjectRemotes(ctx, ps.ProjectID)
		if err != nil {
			s.o.Logger.Warn("delivery: load remotes", "project", ps.ProjectID, "err", err)
			continue
		}
		for _, r := range remotes {
			if _, ok := usableLink(links, r); ok {
				continue
			}
			rr := s.mirrorPass(ctx, r, every, false, now)
			if rr.Status == resultCloned || rr.Status == resultRefreshed {
				touched[r.ProjectID] = true
			}
		}
	}
}

// syncMirror is the forced ("Check now") mirror pass for one remote.
func (s *Service) syncMirror(ctx context.Context, r delivery.Remote) RepoResult {
	return s.mirrorPass(ctx, r, 0, true, s.o.Now())
}

// mirrorPass ensures r's Observer-owned mirror exists (clone under the cap)
// and, when due or forced, runs the ls-remote no-change check and refreshes
// only when the remote tip moved.
func (s *Service) mirrorPass(ctx context.Context, r delivery.Remote, every time.Duration, force bool, now time.Time) RepoResult {
	rr := RepoResult{RemoteName: r.Name, RepoSlug: r.RepoSlug, Source: delivery.SourceMirror}
	url, err := s.o.Net.SanitizeRemoteURL(r.URL)
	if err != nil {
		rr.Status, rr.Detail = string(deliverynet.KindOf(err)), safeDetail(err)
		return rr
	}
	dir, err := s.o.Net.MirrorDir(url)
	if err != nil {
		rr.Status, rr.Detail = string(deliverynet.KindOf(err)), safeDetail(err)
		return rr
	}
	mirrors, err := s.o.Store.ListDeliveryMirrors(ctx)
	if err != nil {
		rr.Status, rr.Detail = "error", "could not read mirrors"
		return rr
	}
	hash := deliverynet.URLHash(url)
	var m delivery.Mirror
	var used int64
	found := false
	for _, x := range mirrors {
		if x.URLHash == hash {
			m, found = x, true
			continue
		}
		used += x.SizeBytes
	}
	if needsClone(m, found) {
		if !found {
			m = delivery.Mirror{URLHash: hash, URL: url, Path: dir, CreatedAt: now}
		}
		if !force && found && m.LastCheckAt.Add(every).After(now) {
			rr.Status = resultNotDue
			return rr
		}
		return s.clone(ctx, r, m, used, rr, now)
	}
	if !force && (every == 0 || m.LastCheckAt.Add(every).After(now)) {
		rr.Status = resultNotDue
		return rr
	}
	return s.refresh(ctx, r, m, rr, now)
}

// clone creates a mirror, refusing when the cap is already reached or the
// new mirror would exceed it.
func (s *Service) clone(ctx context.Context, r delivery.Remote, m delivery.Mirror, used int64, rr RepoResult, now time.Time) RepoResult {
	capB := s.o.MirrorCapBytes
	m.LastCheckAt = now
	if capB > 0 && used >= capB {
		m.Status, m.LastError = MirrorOverCap, "The mirror disk cap is reached. Delete a mirror or raise the cap."
		s.upsertMirror(ctx, m)
		rr.Status, rr.Detail = MirrorOverCap, m.LastError
		return rr
	}
	m.Status, m.LastError = MirrorCloning, ""
	m.ID = s.upsertMirror(ctx, m)
	if err := s.o.Net.Clone(ctx, m.URL, m.Path); err != nil {
		m.Status, m.LastError = failureStatus(err, MirrorFailed), safeDetail(err)
		s.upsertMirror(ctx, m)
		rr.Status, rr.Detail = string(deliverynet.KindOf(err)), m.LastError
		return rr
	}
	size, err := s.o.Net.Size(m.Path)
	if err != nil {
		size = 0
	}
	if capB > 0 && used+size > capB {
		_ = s.o.Net.RemoveMirror(m.Path)
		m.Status, m.SizeBytes = MirrorOverCap, 0
		m.LastError = fmt.Sprintf("This mirror needs %d MB, over the mirror disk cap. It was removed.", (size+(1<<20)-1)>>20)
		s.upsertMirror(ctx, m)
		rr.Status, rr.Detail = MirrorOverCap, m.LastError
		return rr
	}
	branch, err := s.o.Net.HeadBranch(ctx, m.Path)
	if err != nil || branch == "" {
		branch = r.DefaultBranch
	}
	m.DefaultBranch = branch
	if branch != "" {
		if tip, err := s.o.Net.LocalTip(ctx, m.Path, branch); err == nil {
			m.TipSHA = tip
		}
	}
	m.Status, m.SizeBytes, m.LastRefreshAt = MirrorOK, size, now
	s.upsertMirror(ctx, m)
	rr.Status = resultCloned
	return rr
}

// refresh runs the ls-remote no-change check and fetches the default branch
// into the mirror only when the remote tip moved.
func (s *Service) refresh(ctx context.Context, r delivery.Remote, m delivery.Mirror, rr RepoResult, now time.Time) RepoResult {
	branch := m.DefaultBranch
	if branch == "" {
		branch = r.DefaultBranch
	}
	m.LastCheckAt = now
	if !deliverynet.ValidBranch(branch) {
		m.LastError = "The default branch is unknown."
		s.upsertMirror(ctx, m)
		rr.Status, rr.Detail = string(deliverynet.KindInvalid), m.LastError
		return rr
	}
	tip, err := s.o.Net.LsRemote(ctx, m.URL, "refs/heads/"+branch)
	if err != nil {
		m.Status, m.LastError = failureStatus(err, m.Status), safeDetail(err)
		s.upsertMirror(ctx, m)
		rr.Status, rr.Detail = string(deliverynet.KindOf(err)), m.LastError
		return rr
	}
	if tip == m.TipSHA {
		m.Status, m.LastError = MirrorOK, ""
		s.upsertMirror(ctx, m)
		rr.Status = resultUnchanged
		return rr
	}
	if err := s.o.Net.Refresh(ctx, m.Path, branch); err != nil {
		m.Status, m.LastError = failureStatus(err, m.Status), safeDetail(err)
		s.upsertMirror(ctx, m)
		rr.Status, rr.Detail = string(deliverynet.KindOf(err)), m.LastError
		return rr
	}
	if size, err := s.o.Net.Size(m.Path); err == nil {
		m.SizeBytes = size
	}
	m.TipSHA, m.DefaultBranch, m.LastRefreshAt, m.LastError = tip, branch, now, ""
	m.Status = MirrorOK
	s.upsertMirror(ctx, m)
	rr.Status = resultRefreshed
	return rr
}

func (s *Service) upsertMirror(ctx context.Context, m delivery.Mirror) int64 {
	id, err := s.o.Store.UpsertDeliveryMirror(ctx, m)
	if err != nil {
		s.o.Logger.Warn("delivery: upsert mirror", "err", err)
		return m.ID
	}
	return id
}

// DeleteMirror removes a mirror's directory, then its row.
func (s *Service) DeleteMirror(ctx context.Context, mirrorID int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	mirrors, err := s.o.Store.ListDeliveryMirrors(ctx)
	if err != nil {
		return fmt.Errorf("deliverysvc.DeleteMirror: %w", err)
	}
	for _, m := range mirrors {
		if m.ID != mirrorID {
			continue
		}
		if m.Path != "" {
			if err := s.o.Net.RemoveMirror(m.Path); err != nil {
				return fmt.Errorf("deliverysvc.DeleteMirror: %w", err)
			}
		}
		if err := s.o.Store.DeleteDeliveryMirror(ctx, mirrorID); err != nil {
			return fmt.Errorf("deliverysvc.DeleteMirror: %w", err)
		}
		return nil
	}
	return ErrNotFound
}

// MirrorUsage returns the bytes all mirrors use, the cap (0 = none) and the
// mirror rows, for the Code hosts card.
func (s *Service) MirrorUsage(ctx context.Context) (used, capBytes int64, mirrors []delivery.Mirror, err error) {
	mirrors, err = s.o.Store.ListDeliveryMirrors(ctx)
	if err != nil {
		return 0, s.o.MirrorCapBytes, nil, fmt.Errorf("deliverysvc.MirrorUsage: %w", err)
	}
	for _, m := range mirrors {
		used += m.SizeBytes
	}
	return used, s.o.MirrorCapBytes, mirrors, nil
}
