package dashboard

// notifications.go: the node dashboard's notification bell (D-323, T-424),
// the developer-side sibling of the org dashboard's budget alert bell.
//
//	GET  /api/notifications        -> the feed + unread count + the confirm
//	                                  token the state POST echoes (Local)
//	POST /api/notifications/state  -> {ids, action: read|dismiss} (Local,
//	                                  double-submit confirm token, audited)
//
// The handler only LOADS facts the node already records (each through the
// loader its own page uses) and hands them to the pure aggregation package
// internal/notify/feed; read / dismiss state lives in the one state seam
// internal/notify/feedstate (a file beside the database, node-local). Nothing
// here reaches the network: the access-grant and request facts come from the
// node's cached grant document and outbox, never a live org call.
//
// Governance: the routes are cross-cutting (SectionNone, never hidden), and
// the feed itself drops every notification whose owning section the org hid
// on this machine, plus every link into a hidden page.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/marmutapp/superbased-observer/internal/budgetwarnfile"
	"github.com/marmutapp/superbased-observer/internal/cachewarm"
	"github.com/marmutapp/superbased-observer/internal/cachewarmsvc"
	"github.com/marmutapp/superbased-observer/internal/notify/feed"
	"github.com/marmutapp/superbased-observer/internal/notify/feedstate"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// notificationsLookback bounds the guard denials the feed aggregates.
const notificationsLookback = 24 * time.Hour

// notificationsResponse is GET /api/notifications.
type notificationsResponse struct {
	Notifications []feed.Notification `json:"notifications"`
	Unread        int                 `json:"unread"`
	GeneratedAt   string              `json:"generated_at"`
	// ConfirmToken is the owner-local double-submit token the bell echoes
	// on POST /api/notifications/state (T-530, the review M3-05 discipline
	// every other new mutation route follows).
	ConfirmToken string `json:"confirm_token"`
}

// notificationState returns this server's one state store (lazily created;
// the path follows the database the dashboard was started for).
func (s *Server) notificationState() *feedstate.Store {
	s.notifyStateOnce.Do(func() {
		s.notifyState = feedstate.New(feedstate.Path(s.opts.DBPath))
	})
	return s.notifyState
}

func (s *Server) handleNotifications(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	in := s.notificationFacts(r)
	list, unread := feed.ApplyState(feed.Build(in), s.notificationState().Load())
	writeJSON(w, notificationsResponse{
		Notifications: list,
		Unread:        unread,
		GeneratedAt:   in.Now.Format(time.RFC3339),
		ConfirmToken:  setConfirmCookie(w, r),
	})
}

// handleNotificationState marks notifications read or dismissed. Like every
// other owner-local write it refuses a request that does not echo the
// confirm token before it acts (POST only, JSON only, token match), and it
// records one metadata-only audit row per accepted change (T-530): the
// action and the count, never the ids' content.
func (s *Server) handleNotificationState(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	var req struct {
		IDs    []string `json:"ids"`
		Action string   `json:"action"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(req.IDs) == 0 || len(req.IDs) > 500 {
		http.Error(w, "ids must hold 1 to 500 notification ids", http.StatusBadRequest)
		return
	}
	action := feedstate.Action(req.Action)
	if action != feedstate.ActionRead && action != feedstate.ActionDismiss {
		http.Error(w, `action must be "read" or "dismiss"`, http.StatusBadRequest)
		return
	}
	if err := s.notificationState().Mark(req.IDs, action, s.now()); err != nil {
		writeErr(w, err)
		return
	}
	s.recordManageAudit(r, "notifications_state", fmt.Sprintf("action=%s count=%d", action, len(req.IDs)))
	writeJSON(w, map[string]any{"ok": true, "action": req.Action, "count": len(req.IDs)})
}

// notificationFacts loads every fact the feed reads, one loader per source
// (notificationLoaders, walked in order). Each loader is best-effort: a
// source that fails contributes nothing rather than failing the bell (the
// page that owns it reports its own error).
func (s *Server) notificationFacts(r *http.Request) feed.Input {
	in := feed.Input{Now: s.now().UTC(), Hidden: s.hiddenSections(r.Context())}
	for _, load := range notificationLoaders {
		load(s, r, &in)
	}
	return in
}

// notificationLoaders is the source table: each row fills its slice of
// feed.Input.
var notificationLoaders = []func(s *Server, r *http.Request, in *feed.Input){
	(*Server).loadBudgetNotifications,
	(*Server).loadRequestNotifications,
	(*Server).loadGuardNotifications,
	(*Server).loadCacheNotifications,
	(*Server).loadUpdateNotifications,
	(*Server).loadOrgNotifications,
	(*Server).loadMessageNotifications,
	func(s *Server, r *http.Request, in *feed.Input) { in.Ingest = s.ingestFacts(r.Context()) },
}

func (s *Server) loadBudgetNotifications(r *http.Request, in *feed.Input) {
	cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err != nil {
		return
	}
	if f, err := budgetwarnfile.Read(budgetwarnfile.StatusPath(cfg.Observer.DBPath)); err == nil && f != nil {
		for _, n := range f.Active {
			in.OrgBudget = append(in.OrgBudget, feed.BudgetNotice{
				ID: n.ID, Window: n.Window, Subject: n.Subject, Threshold: n.Threshold, Ratio: n.Ratio,
				Level: n.Level, Message: n.Message, CrossedAt: n.CrossedAt,
			})
		}
	}
	in.MonthlyBudgets = s.monthlyBudgetFacts(r, cfg.Intelligence.MonthlyBudgetUSD, cfg.Intelligence.ProjectBudgetsUSD, in.Now)
}

func (s *Server) loadRequestNotifications(r *http.Request, in *feed.Input) {
	svc := s.opts.Requests
	if svc == nil {
		return
	}
	ctx := r.Context()
	if v, ok, err := svc.AccessGrantsView(ctx); err == nil && ok {
		for _, g := range v.Grants {
			in.Grants = append(in.Grants, feedGrant(g, v.Unverified))
		}
	}
	if q, err := svc.QueuedAccessRequests(ctx); err == nil {
		for _, o := range q {
			in.Queued = append(in.Queued, feed.QueuedRequest{
				ID: o.ID, CreatedAt: parseStampLoose(o.CreatedAt), Attempts: o.Attempts,
				LastError: o.LastError, LastAttempt: parseStampLoose(o.LastAttempt),
			})
		}
	}
}

// feedGrant maps one cached grant (and the document's verification state)
// onto the feed's plain fact.
func feedGrant(g store.AccessGrantView, unverified bool) feed.Grant {
	fg := feed.Grant{
		ID: g.Grant.ID, Type: g.Grant.Type, Target: g.Grant.Target, RuleID: g.Grant.RuleID,
		RequestID: g.Grant.RequestID, Honoured: g.Honoured && !unverified, Reason: g.Reason,
	}
	if unverified && fg.Reason == "" {
		fg.Reason = "unverified"
	}
	if g.Grant.StartsAtNs > 0 {
		fg.StartsAt = time.Unix(0, g.Grant.StartsAtNs).UTC()
	}
	if g.Grant.ExpiresAtNs > 0 {
		fg.ExpiresAt = time.Unix(0, g.Grant.ExpiresAtNs).UTC()
	}
	return fg
}

func (s *Server) loadGuardNotifications(r *http.Request, in *feed.Input) {
	ctx := r.Context()
	st := store.New(s.db())
	if blocks, err := st.GuardBlocksSince(ctx, in.Now.Add(-notificationsLookback)); err == nil {
		for _, b := range blocks {
			in.GuardBlocks = append(in.GuardBlocks, feed.GuardBlock{
				RuleID: b.RuleID, Decision: b.Decision, Day: b.Day, Count: b.Count, Last: b.Last,
			})
		}
	}
	if held, err := st.ListPromptReconsider(ctx, 50); err == nil {
		for _, p := range held {
			if !p.ConfirmedAt.IsZero() {
				continue
			}
			in.HeldPrompts = append(in.HeldPrompts, feed.HeldPrompt{
				Fingerprint: p.Fingerprint, SessionID: p.SessionID, Detectors: p.Detectors,
				WarnedAt: p.WarnedAt, ExpiresAt: p.ExpiresAt,
			})
		}
	}
}

func (s *Server) loadCacheNotifications(r *http.Request, in *feed.Input) {
	if !s.opts.CacheWarm.Enabled {
		return
	}
	var lookup cachewarmsvc.PriceLookup
	if s.opts.CostEngine != nil {
		lookup = s.opts.CostEngine.Lookup
	}
	ws, err := cachewarmsvc.Load(r.Context(), store.New(s.db()), lookup, s.opts.CacheWarm, cachewarmsvc.LoadOpts{Limit: 20})
	if err != nil {
		return
	}
	for _, w := range ws {
		if w.Severity != cachewarm.SeverityCritical {
			continue
		}
		in.CacheCritical = append(in.CacheCritical, feed.CacheWarning{
			SessionID: w.Window.SessionID, Model: w.Window.Model, ExpiresAt: w.Window.ExpiresAt,
			SecondsToExpiry: w.SecondsToExpiry, ValueAtRiskUSD: w.ValueAtRiskUSD, Estimated: w.Estimated,
		})
	}
}

func (s *Server) loadUpdateNotifications(r *http.Request, in *feed.Input) {
	if s.opts.UpdateStatusFunc == nil {
		return
	}
	ctx := r.Context()
	if u, err := s.opts.UpdateStatusFunc(ctx); err == nil {
		uf := &feed.UpdateFacts{
			Enabled: u.Enabled, State: u.State, TargetVersion: u.TargetVersion,
			SelfApply: u.SelfApply, Advice: u.Advice,
		}
		if u.OrgRefusal != nil {
			uf.RefusalMin, uf.RefusalMsg = u.OrgRefusal.MinVersion, u.OrgRefusal.Message
		}
		in.Update = uf
	}
	if evs, err := store.New(s.db()).LoadUpdateEvents(ctx, 20); err == nil {
		for _, e := range evs {
			in.UpdateEvents = append(in.UpdateEvents, feed.UpdateEvent{
				ID: e.ID, At: e.At, ToVersion: e.ToVersion, State: string(e.State),
			})
		}
	}
}

func (s *Server) loadOrgNotifications(r *http.Request, in *feed.Input) {
	ctx := r.Context()
	for _, a := range s.orgAnnouncements(ctx) {
		in.Announcements = append(in.Announcements, feed.Announcement{
			ID: a.ID, Severity: string(a.Severity), Title: a.Title, Body: a.Body, Source: string(a.Source),
		})
	}
	if states, err := store.New(s.db()).ListPolicyResourceStates(ctx); err == nil {
		for _, p := range states {
			in.PolicyChanges = append(in.PolicyChanges, feed.PolicyChange{
				Family: p.Family, Version: p.LastVersion, UpdatedAt: p.UpdatedAt,
			})
		}
	}
}

// hiddenSections is the feed's view of the governance posture: every nav
// section the org hid on this machine, and every hidden Settings subsection
// as "settings#<id>". nil on an ungoverned node.
func (s *Server) hiddenSections(ctx context.Context) map[string]bool {
	if s.opts.Governance == nil {
		return nil
	}
	eff := s.opts.Governance(ctx)
	if !eff.VisibilityActive() {
		return nil
	}
	v := s.dashboardVisibility(ctx, eff)
	out := make(map[string]bool, len(v.HiddenSections)+len(v.HiddenSettings))
	for _, id := range v.HiddenSections {
		out[id] = true
	}
	for _, id := range v.HiddenSettings {
		out["settings#"+id] = true
	}
	return out
}

// monthlyBudgetFacts reproduces /api/budget's threshold reading (the
// BudgetBanner's source) without its response shape. Nothing is loaded when
// no budget is configured, so an unbudgeted node pays one config read.
func (s *Server) monthlyBudgetFacts(r *http.Request, global float64, perProject map[string]float64, now time.Time) []feed.MonthlyBudget {
	configured := global > 0
	for _, b := range perProject {
		if b > 0 {
			configured = true
		}
	}
	if !configured || s.db() == nil {
		return nil
	}
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	globalMTD, perRoot, err := s.monthToDateCostByProject(r, monthStart)
	if err != nil {
		return nil
	}
	daysElapsed := int(now.Sub(monthStart).Hours()/24) + 1
	daysInMonth := time.Date(now.Year(), now.Month()+1, 0, 0, 0, 0, 0, time.UTC).Day()
	proj := float64(daysInMonth) / float64(daysElapsed)
	month := now.Format("2006-01")
	var out []feed.MonthlyBudget
	if global > 0 {
		sc := scopeFor("", global, globalMTD, proj)
		out = append(out, feed.MonthlyBudget{Month: month, Pct: sc.Pct, Threshold: sc.Threshold})
	}
	roots := make([]string, 0, len(perProject))
	for root := range perProject {
		roots = append(roots, root)
	}
	sort.Strings(roots)
	for _, root := range roots {
		if perProject[root] <= 0 {
			continue
		}
		sc := scopeFor(root, perProject[root], perRoot[root], proj)
		out = append(out, feed.MonthlyBudget{Month: month, Root: root, Pct: sc.Pct, Threshold: sc.Threshold})
	}
	return out
}

// ingestFacts reads the watcher-health picture (the memoized payload when
// the read caches are on, as /api/health/watcher does).
func (s *Server) ingestFacts(ctx context.Context) *feed.IngestFacts {
	if s.opts.DB == nil {
		return nil
	}
	var (
		out map[string]any
		err error
	)
	if s.opts.ReadCaches {
		out, err = s.watcherHealthCached(ctx)
	} else {
		out, err = s.computeWatcherHealth(ctx)
	}
	if err != nil {
		return nil
	}
	files, _ := out["files"].([]fileHealth)
	g := &feed.IngestFacts{}
	for _, f := range files {
		if f.BehindBytes <= 0 || f.OrphanUnmatched {
			continue
		}
		g.BehindFiles++
		g.BehindBytes += f.BehindBytes
		if f.BehindSeconds > g.OldestBehindSeconds {
			g.OldestBehindSeconds = f.BehindSeconds
		}
	}
	return g
}

// parseStampLoose parses the outbox's RFC3339 stamps ("" = zero).
func parseStampLoose(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC()
	}
	return time.Time{}
}
