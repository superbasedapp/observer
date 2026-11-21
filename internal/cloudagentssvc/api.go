package cloudagentssvc

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudagents"
	"github.com/marmutapp/superbased-observer/internal/keystore"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// The API connectors' sync (lane CA-B2): cursor-cloud, devin and
// openhands-cloud. Same order as the CLI path: discovery pages, then the
// per-session reads the row declares (Cursor runs and usage, then run
// streams; Devin messages; OpenHands events), every session landed through
// store.Ingest with its metadata-only activity, then the history and stream
// checkpoints, then the discovery checkpoint and ledger rows through
// CommitCloudSyncPage. The key is read from the keychain at the start of the
// pass and handed to the egress per call; it is never logged, stored
// elsewhere or returned.

// APIEgress performs the API connectors' HTTPS calls
// (internal/cloudagentsnet).
type APIEgress interface {
	Call(ctx context.Context, req cloudagents.Request, key string) ([]byte, error)
	Stream(ctx context.Context, req cloudagents.Request, key string, window time.Duration, onEvent func(cloudagents.SSEEvent) bool) (cloudagents.StreamEnd, error)
}

// ErrKeychain is returned when the keychain cannot hold an API key; the
// account is then not linked.
var ErrKeychain = errors.New("cloudagents: the OS keychain could not store the key")

// ErrKeychainDelete is returned by Disconnect when the keychain refuses to
// delete an account's key; the account then stays linked so the disconnect
// can be retried, rather than leaving a live key with no row pointing at it.
var ErrKeychainDelete = errors.New("cloudagents: the OS keychain could not delete the key; the account stays linked, retry disconnect")

// maxKeyLen bounds a pasted key.
const maxKeyLen = 4096

// cleanKey trims a pasted key and refuses one that is not a plain token.
func cleanKey(k string) (string, error) {
	k = strings.TrimSpace(k)
	switch {
	case k == "":
		return "", fmt.Errorf("%w: an API key is required for this connector", ErrInvalid)
	case len(k) > maxKeyLen || strings.ContainsAny(k, "\r\n\x00 \t"):
		return "", fmt.Errorf("%w: that is not an API key (too long, or it holds a space or a line break)", ErrInvalid)
	}
	return k, nil
}

func (s *Service) testAPI(ctx context.Context, c cloudagents.Connector, cred Credentials) (ProbeResult, error) {
	res := ProbeResult{Connector: c.ID}
	key, err := cleanKey(cred.Key)
	if err != nil {
		return res, err
	}
	params, err := cloudagents.ValidateParams(c, cred.Params)
	if err != nil {
		return res, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if s.api == nil {
		return res, fmt.Errorf("%w: the HTTPS egress is not wired in this process", ErrInvalid)
	}
	req, err := cloudagents.APIIdentityRequest(c, params)
	if err != nil {
		return res, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	b, err := s.api.Call(ctx, req, key)
	if err == nil {
		var id cloudagents.Identity
		id, err = cloudagents.ParseAPIIdentity(c, params, b)
		res.AccountID, res.Display = id.AccountID, id.Display
	}
	res.ErrorClass = cloudagents.ClassOf(err)
	res.Coverage = cloudagents.CoverageAfter("", res.ErrorClass)
	res.OK = err == nil
	return res, nil
}

func (s *Service) storeKey(c cloudagents.Connector, accountPK int64, raw string) error {
	key, err := cleanKey(raw)
	if err != nil {
		return err
	}
	if s.keys == nil {
		return ErrKeychain
	}
	if err := s.keys.Set(SecretName(c.ID, accountPK), key); err != nil {
		s.log.Info("cloud agents: keychain refused the key", "connector", c.ID)
		return ErrKeychain
	}
	return nil
}

// readKey returns the account's key, or a not_signed_in failure when the
// keychain has none (removed outside Observer, or a keychain reset).
func (s *Service) readKey(c cloudagents.Connector, accountPK int64) (string, error) {
	if s.keys == nil {
		return "", cloudagents.NewError(cloudagents.ErrNotSignedIn, "no keychain")
	}
	k, err := s.keys.Get(SecretName(c.ID, accountPK))
	if err != nil || strings.TrimSpace(k) == "" {
		if err != nil && !errors.Is(err, keystore.ErrNotFound) {
			return "", cloudagents.NewError(cloudagents.ErrNotSignedIn, "keychain unavailable")
		}
		return "", cloudagents.NewError(cloudagents.ErrNotSignedIn, "no key in the keychain")
	}
	return k, nil
}

// passFatal says, per error class, whether a PER-SESSION failure (a detail,
// usage, history or stream read of one session) stops the whole pass. The
// account cannot collect at all, the vendor asked us to slow down, or the
// network itself is down: stop. A vendor server error (HTTP 5xx) or a
// timeout on one session is that session's problem: it stays owed for the
// next pass (counted in detail_pending) and the pass goes on (live check
// 2026-11-01: one Cursor 500 on a usage read aborted a whole pass). An
// unlisted class leaves the session owed. Discovery (list) failures always
// fail the pass, whatever their class.
var passFatal = map[cloudagents.ErrorClass]bool{
	cloudagents.ErrNotSignedIn:      true,
	cloudagents.ErrPermissionDenied: true,
	cloudagents.ErrRateLimited:      true,
	cloudagents.ErrUnreachable:      true,
	cloudagents.ErrServerError:      false,
	cloudagents.ErrTimeout:          false,
}

// fatalForPass reports whether a per-session failure stops the whole pass
// (passFatal).
func fatalForPass(err error) bool { return passFatal[cloudagents.ClassOf(err)] }

// apiSession is one session the pass works on.
type apiSession struct {
	task   cloudagents.Task
	listed bool // its row is (re)landed this pass
	state  cloudagents.HistoryCursor
	hadCP  bool
	// lastSeen is when the session was last listed (the checkpoint's
	// last success); an unlisted session past OpenSessionTTL is abandoned.
	lastSeen time.Time
	acts     []cloudagents.Activity
	// drained: history read to its end this pass (or none declared) and no
	// run stream still owed.
	drained bool
}

// vendorFailure marks an error a phase hit at the vendor: the pass is
// recorded as failed (s.fail) rather than returned as a local error.
type vendorFailure struct{ err error }

func (v vendorFailure) Error() string { return v.err.Error() }
func (v vendorFailure) Unwrap() error { return v.err }

// apiPass is the state of one API connector pass.
type apiPass struct {
	c        cloudagents.Connector
	a        store.CloudConnectorAccount
	key      string
	params   map[string]string
	prev     cloudagents.Checkpoint
	now      time.Time
	d        *cloudagents.Discovery
	open     []store.CloudSyncCheckpoint // session_history checkpoints at the start
	sessions []*apiSession
	streamed map[string]*streamResult
	ledger   []store.CloudUsageEntry
	res      *SyncResult
	// details memoizes this pass's detail responses by URL: sessions that
	// share one environment read it once (Qoder).
	details map[string][]byte
	// owner is a member-scoped account's chosen vendor user ("" for any
	// other connector); purge is true on the pass that removes the sessions
	// other members started that landed before the user was chosen.
	owner string
	purge bool
	// listed are the discovery's tasks the account keeps
	// (cloudagents.OwnershipOf); skipped names the listed sessions it does
	// not keep, which no later phase reads, lands or links.
	listed  []cloudagents.Task
	skipped map[string]bool
}

func (s *Service) syncAPI(ctx context.Context, c cloudagents.Connector, a store.CloudConnectorAccount, res SyncResult) (SyncResult, error) {
	now := s.now().UTC()
	res.UserState = cloudagents.VendorUserStateOf(c, a.VendorUserID)
	if res.UserState == cloudagents.VendorUserNotChosen {
		// A member-scoped account with no vendor user named pulls nothing
		// and makes no call (not even the keychain read): the organization's
		// list would be every member's sessions, and "everything" is never
		// the fallback (CLOUDAGENTS-6).
		res.Coverage = cloudagents.CoverageState(a.CoverageState)
		if res.Coverage == "" {
			res.Coverage = cloudagents.CoverageNotEstablished
		}
		return res, nil
	}
	purge := res.UserState == cloudagents.VendorUserChosen && a.VendorUserPurged != a.VendorUserID
	if purge {
		if err := s.resetForOwner(ctx, a.ID); err != nil {
			return res, err
		}
	}
	prevStore, _, err := s.st.LoadCloudSyncCheckpoint(ctx, a.ID, models.SyncStreamDiscovery, "")
	if err != nil {
		return res, err
	}
	if s.api == nil {
		return res, fmt.Errorf("%w: the HTTPS egress is not wired in this process", ErrInvalid)
	}
	key, err := s.readKey(c, a.ID)
	if err != nil {
		return s.fail(ctx, a, prevStore, now, res, err)
	}
	p := &apiPass{
		c: c, a: a, key: key, params: cloudagents.AccountParams(c, a.AccountID),
		prev: fromStoreCheckpoint(prevStore), now: now, streamed: map[string]*streamResult{}, res: &res,
		details: map[string][]byte{}, purge: purge, skipped: map[string]bool{},
	}
	if res.UserState == cloudagents.VendorUserChosen {
		p.owner = a.VendorUserID
	}
	for _, phase := range []func(context.Context, *apiPass) error{
		s.apiDiscover, s.apiOwnership, s.apiCollect, s.apiDetail, s.apiHistory, s.apiStreams, s.apiLand, s.apiLineage, s.apiSaveStates,
	} {
		if err := phase(ctx, p); err != nil {
			var vf vendorFailure
			if errors.As(err, &vf) {
				return s.fail(ctx, a, prevStore, now, res, vf.err)
			}
			return res, err
		}
	}
	return res, s.apiCommit(ctx, p)
}

// apiDiscover reads the discovery pages (step 1). Sessions a checkpoint
// says are owed a read are wanted: a newest-first list keeps paging until it
// has listed them, so they can be re-read even when they did not change.
func (s *Service) apiDiscover(ctx context.Context, p *apiPass) error {
	open, err := s.st.ListCloudSyncCheckpoints(ctx, p.a.ID, models.SyncStreamSessionHistory)
	if err != nil {
		return err
	}
	sort.Slice(open, func(i, j int) bool { return open[i].Scope < open[j].Scope })
	p.open = open
	since := cloudagents.Since(p.prev)
	until := p.now.Add(time.Minute)
	p.d = cloudagents.NewDiscovery(p.c, since)
	var want []string
	for _, o := range open {
		want = append(want, o.Scope)
	}
	p.d.Want(want)
	cursor := ""
	for {
		req, err := cloudagents.APIListRequest(p.c, p.params, since, until, cursor)
		if err != nil {
			return vendorFailure{err}
		}
		b, err := s.api.Call(ctx, req, p.key)
		if err != nil {
			return vendorFailure{err}
		}
		page, err := cloudagents.ParseAPIList(p.c, p.params, cursor, b)
		if err != nil {
			return vendorFailure{err}
		}
		cursor = page.Cursor
		if !p.d.Add(page) {
			break
		}
	}
	p.res.Pages = p.d.Pages()
	p.res.Tasks = len(p.d.Tasks())
	return nil
}

// resetForOwner clears an account's collection state before the pass that
// follows a vendor user choice (first or changed): the discovery checkpoint
// (so the pass re-lists from the start of the vendor's history), every
// session_history checkpoint and every pending child link. After that pass
// every checkpoint the account holds belongs to a session the list showed
// the chosen user started, so a later pass may re-read an unlisted
// checkpointed session without knowing its owner again.
func (s *Service) resetForOwner(ctx context.Context, accountPK int64) error {
	if _, err := s.st.DeleteCloudSyncCheckpoint(ctx, accountPK, models.SyncStreamDiscovery, ""); err != nil {
		return err
	}
	hist, err := s.st.ListCloudSyncCheckpoints(ctx, accountPK, models.SyncStreamSessionHistory)
	if err != nil {
		return err
	}
	for _, cp := range hist {
		if _, err := s.st.DeleteCloudSyncCheckpoint(ctx, accountPK, models.SyncStreamSessionHistory, cp.Scope); err != nil {
			return err
		}
	}
	live, err := s.st.ListCloudSyncCheckpoints(ctx, accountPK, models.SyncStreamLive)
	if err != nil {
		return err
	}
	for _, cp := range live {
		if strings.HasPrefix(cp.Scope, childScopePrefix) {
			if _, err := s.st.DeleteCloudSyncCheckpoint(ctx, accountPK, models.SyncStreamLive, cp.Scope); err != nil {
				return err
			}
		}
	}
	return nil
}

// apiOwnership keeps the listed tasks the account owns (step 1b,
// cloudagents.OwnershipOf; every task of a connector that is not member
// scoped). The others are counted, never landed, read or linked. On the pass
// after a vendor user choice it also removes the sessions of this connector
// the list says someone other than the chosen user started, through the
// adapter purge's decision table (store.PurgeToolSessions): their actions,
// ledger rows, checkpoints and links go with them. A task of theirs that
// landed no session (a Warp run of a harness with no Observer tool) left only
// ledger rows, removed through store.DeleteSessionlessCloudUsage.
func (s *Service) apiOwnership(ctx context.Context, p *apiPass) error {
	var notOwned []cloudagents.Task
	for _, t := range p.d.Tasks() {
		switch cloudagents.OwnershipOf(p.c, p.owner, t) {
		case cloudagents.OwnerKeep:
			p.listed = append(p.listed, t)
			continue
		case cloudagents.OwnerSkipServiceUser:
			p.res.SkippedServiceUser++
		case cloudagents.OwnerSkipNoUser:
			p.res.SkippedNoUser++
		default:
			p.res.SkippedOtherMember++
		}
		p.skipped[t.ID] = true
		notOwned = append(notOwned, t)
	}
	p.res.Tasks = len(p.listed)
	if !p.purge || len(notOwned) == 0 {
		return nil
	}
	byTool := map[string][]string{}
	var sessionless []string
	for _, t := range notOwned {
		c, attributed := cloudagents.ForTask(p.c, t)
		if !attributed {
			// A task of a harness with no Observer tool (Warp oz) landed only
			// its ledger rows, scoped to its own id (landTask).
			sessionless = append(sessionless, t.ID)
			continue
		}
		var lookupErr error
		id, _ := cloudagents.ResolveSessionID(t, func(ref string) (string, bool) {
			found, ok, err := s.st.SessionIDByVendorRef(ctx, c.Tool, ref)
			if err != nil {
				lookupErr = err
			}
			return found, ok
		})
		if lookupErr != nil {
			return lookupErr
		}
		if id != "" {
			byTool[c.Tool] = append(byTool[c.Tool], id)
		}
	}
	tools := make([]string, 0, len(byTool))
	for tool := range byTool {
		tools = append(tools, tool)
	}
	sort.Strings(tools)
	for _, tool := range tools {
		r, err := s.st.PurgeToolSessions(ctx, tool, byTool[tool])
		if err != nil {
			return err
		}
		p.res.PurgedOtherMember += r.Deleted["sessions"] + r.KeptSessions
	}
	n, err := s.st.DeleteSessionlessCloudUsage(ctx, p.c.ID, sessionless)
	if err != nil {
		return err
	}
	p.res.PurgedLedgerOnly += n
	return nil
}

// apiCollect builds the sessions of the pass (step 2): the window's, then
// those a checkpoint says are still owed a read (live, detail pending, a run
// stream owed, history not drained), in a stable order. A listing of a
// finished, fully read session that only the overlap window brought back
// (not updated past the previous high-water mark, no checkpoint left) is not
// re-read or re-landed.
func (s *Service) apiCollect(ctx context.Context, p *apiPass) error {
	byID := map[string]*apiSession{}
	for _, t := range p.listed {
		ss := &apiSession{task: t, listed: true}
		p.sessions = append(p.sessions, ss)
		byID[t.ID] = ss
	}
	for _, o := range p.open {
		h := cloudagents.DecodeHistoryCursor(o.Cursor)
		if ss, ok := byID[o.Scope]; ok {
			ss.state, ss.hadCP, ss.lastSeen = h, true, o.LastSuccessAt
			continue
		}
		if !cloudagents.ValidSessionID(o.Scope) {
			continue
		}
		if p.skipped[o.Scope] {
			// Listed this pass as a session the account does not keep.
			continue
		}
		ss := &apiSession{state: h, hadCP: true, lastSeen: o.LastSuccessAt, task: cloudagents.Task{Connector: p.c.ID, ID: o.Scope, Harness: h.Harness}}
		if t, ok := p.d.Older(o.Scope); ok {
			if cloudagents.OwnershipOf(p.c, p.owner, t) != cloudagents.OwnerKeep {
				// Listed (unchanged) as a session the account does not keep:
				// its read is no longer owed.
				p.skipped[o.Scope] = true
				if _, err := s.st.DeleteCloudSyncCheckpoint(ctx, p.a.ID, models.SyncStreamSessionHistory, o.Scope); err != nil {
					return err
				}
				continue
			}
			// Listed but unchanged (a list with no server window): re-read
			// and re-landed while its detail or a run stream is owed, or it
			// may still be running.
			ss.task, ss.listed = t, h.Owed() || !cloudagents.Lifecycle(h.Lifecycle).Terminal()
		}
		p.sessions = append(p.sessions, ss)
		byID[o.Scope] = ss
	}
	for _, ss := range p.sessions {
		changed := p.prev.HighWater.IsZero() || ss.task.UpdatedAt.After(p.prev.HighWater)
		if ss.listed && !ss.hadCP && !changed {
			ss.listed, ss.drained = false, true
		}
		if !p.c.History {
			ss.drained = true
		}
	}
	return nil
}

// detailRank orders detail reads: owed first (detail or a run stream), then
// live, then new.
func detailRank(ss *apiSession) int {
	switch {
	case ss.state.Owed():
		return 0
	case ss.hadCP:
		return 1
	}
	return 2
}

// apiDetail makes the detail calls (step 3: Cursor runs and usage), for at
// most MaxViews sessions; the rest are owed to a later pass.
func (s *Service) apiDetail(ctx context.Context, p *apiPass) error {
	if len(p.c.Detail) == 0 {
		return nil
	}
	sort.SliceStable(p.sessions, func(i, j int) bool { return detailRank(p.sessions[i]) < detailRank(p.sessions[j]) })
	budget := p.c.MaxViews
	for _, ss := range p.sessions {
		if !ss.listed || !cloudagents.NeedsDetail(p.c, ss.task) {
			// A run none of the row's detail calls applies to (Warp: an oz
			// harness run has no harness usage) owes nothing.
			continue
		}
		if budget <= 0 {
			ss.task.DetailPending = true
			p.res.DetailPending++
			continue
		}
		budget--
		t, err := s.readDetail(ctx, p.c, p.key, p.params, p.details, ss.task, p.res)
		if err != nil {
			if fatalForPass(err) {
				return vendorFailure{err}
			}
			ss.task.DetailPending = true
			p.res.DetailPending++
			continue
		}
		ss.task = t
	}
	return nil
}

// apiHistory reads message or event history (step 4: Devin, OpenHands), for
// at most MaxHistory sessions and HistoryPages pages each.
func (s *Service) apiHistory(ctx context.Context, p *apiPass) error {
	if !p.c.History {
		return nil
	}
	budget := p.c.MaxHistory
	for _, ss := range p.sessions {
		if budget <= 0 {
			break
		}
		if !ss.listed && !ss.hadCP {
			continue
		}
		if _, ok := cloudagents.ForTask(p.c, ss.task); !ok {
			// A session that lands no tool rows reads no history.
			ss.drained = true
			continue
		}
		budget--
		if err := s.readHistory(ctx, p.c, p.key, p.params, ss, p.now, p.res); err != nil {
			if fatalForPass(err) {
				return vendorFailure{err}
			}
			// Not drained: the checkpoint keeps the session owed.
			p.res.DetailPending++
		}
	}
	return nil
}

// apiStreams reads the run streams (step 5: Cursor), at most MaxStreams.
func (s *Service) apiStreams(ctx context.Context, p *apiPass) error {
	if !p.c.Stream {
		return nil
	}
	owed, err := s.readStreams(ctx, p.c, p.a, p.key, p.sessions, p.streamed, p.now, p.res)
	if err != nil {
		return vendorFailure{err}
	}
	// A session whose runs were considered this pass records whether a run
	// stream is still owed; one not considered (unlisted, or its detail
	// still pending) keeps what its checkpoint said.
	for _, ss := range p.sessions {
		if ss.listed && !ss.task.DetailPending {
			ss.state.StreamsOwed = owed[ss.task.ID]
		}
	}
	return nil
}

// apiLand lands the pass (step 6): a listed session its row and activity;
// one only owed history its activity under the root it already has.
func (s *Service) apiLand(ctx context.Context, p *apiPass) error {
	for _, ss := range p.sessions {
		acts := ss.acts
		for _, sr := range p.streamed {
			if sr.sessionID == ss.task.ID && sr.stream != nil {
				acts = append(acts, sr.stream.Activity...)
			}
		}
		if ss.listed {
			if err := s.apiLandListed(ctx, p, ss, acts); err != nil {
				return err
			}
			continue
		}
		c, attributed := cloudagents.ForTask(p.c, ss.task)
		if !attributed || (len(acts) == 0 && len(ss.task.Usage) == 0) {
			continue
		}
		root, err := s.st.ProjectRootForSession(ctx, ss.task.ID)
		if err != nil {
			return err
		}
		if root == "" {
			continue
		}
		r, err := s.st.Ingest(ctx, cloudagents.MapActivity(c, ss.task.ID, root, acts), nil,
			store.IngestOptions{OutcomeUpdates: cloudagents.MapOutcomes(c, ss.task.ID, acts)})
		if err != nil {
			return err
		}
		p.res.ActionsNew += r.ActionsInserted
		// A session only owed history still lands the native usage its
		// history read reported (the row exists: it has a root).
		entries, err := s.ledgerEntries(ctx, c, ss.task.ID, cloudagents.MapLedger(c, ss.task, ss.task.ID, p.a.AccountID))
		if err != nil {
			return err
		}
		p.ledger = append(p.ledger, entries...)
	}
	return nil
}

func (s *Service) apiLandListed(ctx context.Context, p *apiPass, ss *apiSession, acts []cloudagents.Activity) error {
	r, entries, err := s.landTask(ctx, p.c, p.a, ss.task, acts...)
	if err != nil {
		return err
	}
	p.res.SessionsNew += r.SessionsTouched
	p.res.ActionsNew += r.ActionsInserted
	if r.skippedNoTime {
		p.res.SkippedNoTime++
	}
	if r.repoNotReported {
		p.res.RepositoryNotReported++
	}
	if r.noToolRows {
		p.res.NoToolRows++
	}
	p.ledger = append(p.ledger, entries...)
	return nil
}

// apiSaveStates writes the stream and history checkpoints (step 7), after
// the rows they cover.
func (s *Service) apiSaveStates(ctx context.Context, p *apiPass) error {
	for _, sr := range p.streamed {
		if err := s.st.SaveCloudSyncCheckpoint(ctx, sr.checkpoint(p.a.ID, p.now)); err != nil {
			return err
		}
	}
	for _, ss := range p.sessions {
		if err := s.saveSessionState(ctx, p.a.ID, ss, p.now); err != nil {
			return err
		}
	}
	return nil
}

// apiCommit commits the discovery checkpoint and the ledger rows in one
// transaction and records the account's state (step 8).
func (s *Service) apiCommit(ctx context.Context, p *apiPass) error {
	next, partial := p.d.Next(p.prev, p.now)
	cp := toStoreCheckpoint(p.a.ID, next)
	cp.LastAttemptAt = p.now
	added, err := s.st.CommitCloudSyncPage(ctx, p.ledger, cp)
	if err != nil {
		return err
	}
	p.res.LedgerNew = added
	p.res.Partial = partial
	if p.purge {
		// The removal of the other members' sessions is done for this user
		// (a user changed meanwhile keeps its own removal owed).
		if _, err := s.st.MarkCloudConnectorVendorUserPurged(ctx, p.a.ID, p.owner); err != nil {
			return err
		}
	}
	p.res.Coverage = cloudagents.CoverageVerified
	if partial {
		p.res.Coverage = cloudagents.CoveragePartialHistory
	}
	if _, err := s.st.SetCloudConnectorAccountState(ctx, p.a.ID, string(p.res.Coverage), ""); err != nil {
		return err
	}
	s.clearBackoff(p.a.ID)
	if remaining, err := s.st.ListCloudSyncCheckpoints(ctx, p.a.ID, models.SyncStreamSessionHistory); err == nil {
		p.res.OpenTasks, p.res.Waiting, p.res.Owed = checkpointCounts(remaining)
	}
	return nil
}

// readDetail makes a session's detail calls and folds them in. A response
// already read this pass for the same URL is reused (memo); a skippable
// detail that fails (cloudagents.DetailSkippable) is left out for this task.
func (s *Service) readDetail(ctx context.Context, c cloudagents.Connector, key string, params map[string]string, memo map[string][]byte, t cloudagents.Task, res *SyncResult) (cloudagents.Task, error) {
	for _, kind := range c.Detail {
		if !cloudagents.DetailApplies(kind, t) {
			continue
		}
		req, err := cloudagents.APIDetailRequestFor(c, params, kind, t)
		if err != nil {
			if cloudagents.DetailSkippable(kind, err) {
				continue
			}
			return t, err
		}
		b, ok := memo[req.URL]
		if !ok {
			b, err = s.api.Call(ctx, req, key)
			if err != nil {
				if cloudagents.DetailSkippable(kind, err) {
					continue
				}
				return t, err
			}
			res.Details++
			if memo != nil {
				memo[req.URL] = b
			}
		}
		if t, err = cloudagents.ApplyAPIDetail(c, kind, t, b); err != nil {
			return t, err
		}
	}
	t.DetailPending = false
	return t, nil
}

// readHistory pages one session's history from its checkpoint.
func (s *Service) readHistory(ctx context.Context, c cloudagents.Connector, key string, params map[string]string, ss *apiSession, now time.Time, res *SyncResult) error {
	cursor := ss.state.After
	since := time.Time{}
	if !ss.state.Since.IsZero() {
		since = ss.state.Since.Add(-c.Overlap)
	}
	until := now.Add(time.Minute)
	newest := ss.state.Since
	for page := 0; page < c.HistoryPages; page++ {
		req, err := cloudagents.APIHistoryRequest(c, params, ss.task.ID, cursor, since, until)
		if err != nil {
			return err
		}
		b, err := s.api.Call(ctx, req, key)
		if err != nil {
			return err
		}
		hp, err := cloudagents.ParseAPIHistory(c, params, ss.task.ID, cursor, b)
		if err != nil {
			return err
		}
		res.HistoryPages++
		ss.acts = append(ss.acts, hp.Activity...)
		// A history that reports the session's figures (Cline's message
		// metrics) fills them; one that reports none leaves them absent.
		if hp.Tokens != nil {
			ss.task.Tokens = hp.Tokens
		}
		// Native usage a history reports (Cline's message cost) lands with
		// the session in the ledger; each figure carries its own record id
		// or revision key, so a re-read lands nothing twice.
		ss.task.Usage = append(ss.task.Usage, hp.Usage...)
		if hp.Newest.After(newest) {
			newest = hp.Newest
		}
		if c.ID == cloudagents.ConnectorDevin {
			// The page cursor that fetched this page is the resume point:
			// the next pass re-reads it (overlap, deduplicated by id).
			ss.state.After = cursor
		}
		if hp.Next == "" {
			ss.drained = true
			break
		}
		cursor = hp.Next
	}
	if c.ID != cloudagents.ConnectorDevin {
		ss.state.After = ""
		ss.state.Since = newest
	}
	return nil
}

// streamResult is one run stream read this pass.
type streamResult struct {
	sessionID string
	run       cloudagents.Run
	stream    *cloudagents.RunStream
	cursor    cloudagents.StreamCursor
	prev      store.CloudSyncCheckpoint
	gap       *store.CloudSyncGap
	// retention is the X-Cursor-Stream-Retention-Seconds the read saw (0
	// when none).
	retention int64
}

func (r *streamResult) checkpoint(accountPK int64, now time.Time) store.CloudSyncCheckpoint {
	cp := r.prev
	cp.AccountPK, cp.Stream, cp.Scope = accountPK, models.SyncStreamLive, streamScope(r.sessionID, r.run.ID)
	cp.Cursor = cloudagents.EncodeStreamCursor(r.cursor)
	cp.LastAttemptAt = now
	if r.gap == nil {
		cp.LastSuccessAt = now
	}
	if cp.Gaps == nil {
		cp.Gaps = []store.CloudSyncGap{}
	}
	if r.gap != nil {
		cp.Gaps = append(cp.Gaps, *r.gap)
	}
	return cp
}

func streamScope(sessionID, runID string) string { return sessionID + "/" + runID }

// readStreams reads the run streams the plan table selects, newest runs of
// the detailed sessions first, at most MaxStreams. An expired stream (or a
// refused resume that cannot restart) records the run's interval as a gap;
// the run's terminal state from the runs list stands as the fallback.
func (s *Service) readStreams(ctx context.Context, c cloudagents.Connector, a store.CloudConnectorAccount, key string, sessions []*apiSession, out map[string]*streamResult, now time.Time, res *SyncResult) (map[string]bool, error) {
	type cand struct {
		sessionID string
		run       cloudagents.Run
	}
	var cands []cand
	for _, ss := range sessions {
		if !ss.listed || ss.task.DetailPending {
			continue
		}
		for _, r := range ss.task.Runs {
			cands = append(cands, cand{ss.task.ID, r})
		}
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].run.CreatedAt.After(cands[j].run.CreatedAt) })
	// The retention in force: the last one the vendor sent, else the row's.
	retCP, _, err := s.st.LoadCloudSyncCheckpoint(ctx, a.ID, models.SyncStreamLive, cloudagents.StreamRetentionScope)
	if err != nil {
		return nil, err
	}
	observed := cloudagents.DecodeStreamRetention(retCP.Cursor)
	retention := cloudagents.StreamRetentionFor(c, observed)
	seen := int64(0)
	defer func() {
		if seen <= 0 || seen == observed {
			return
		}
		retCP.AccountPK, retCP.Stream, retCP.Scope = a.ID, models.SyncStreamLive, cloudagents.StreamRetentionScope
		retCP.Cursor, retCP.LastAttemptAt, retCP.LastSuccessAt = cloudagents.EncodeStreamRetention(seen), now, now
		if retCP.Gaps == nil {
			retCP.Gaps = []store.CloudSyncGap{}
		}
		if err := s.st.SaveCloudSyncCheckpoint(ctx, retCP); err != nil {
			s.log.Info("cloud agents: could not keep the stream retention", "connector", c.ID)
		}
	}()
	// owed marks a session with a run stream a later pass still has to read
	// (over budget, or still open), so its checkpoint is kept.
	owed := map[string]bool{}
	budget := c.MaxStreams
	for _, cd := range cands {
		prev, found, err := s.st.LoadCloudSyncCheckpoint(ctx, a.ID, models.SyncStreamLive, streamScope(cd.sessionID, cd.run.ID))
		if err != nil {
			return owed, err
		}
		cur := cloudagents.DecodeStreamCursor(prev.Cursor)
		action, _ := cloudagents.PlanStream(cloudagents.StreamPlanInput{
			Run: cd.run, Cursor: cur, Found: found, Now: now, Retention: retention,
		})
		switch action {
		case cloudagents.StreamSkip:
			continue
		case cloudagents.StreamPastRetention:
			// Past the vendor's retention a request would only answer 410:
			// the same gap is recorded without spending a stream slot.
			sr := &streamResult{sessionID: cd.sessionID, run: cd.run, prev: prev, cursor: cur}
			expireStream(sr, now)
			res.StreamGaps++
			out[streamScope(cd.sessionID, cd.run.ID)] = sr
			continue
		}
		if budget <= 0 {
			owed[cd.sessionID] = true
			continue
		}
		budget--
		last := ""
		if action == cloudagents.StreamResume {
			last = cur.LastEventID
		}
		sr := &streamResult{sessionID: cd.sessionID, run: cd.run, prev: prev, cursor: cur}
		err = s.readOneStream(ctx, c, key, sr, last, now)
		if cloudagents.ClassOf(err) == cloudagents.ErrStreamResumeRefused && last != "" {
			// A Last-Event-ID the vendor no longer honours: read the run
			// from its start once (ids deduplicate the replay).
			err = s.readOneStream(ctx, c, key, sr, "", now)
		}
		seen = max(seen, sr.retention)
		switch cloudagents.ClassOf(err) {
		case cloudagents.ErrNone:
		case cloudagents.ErrStreamExpired, cloudagents.ErrStreamResumeRefused:
			expireStream(sr, now)
			res.StreamGaps++
		default:
			if fatalForPass(err) {
				return owed, err
			}
			owed[cd.sessionID] = true
			continue // one unreadable stream does not fail the pass
		}
		if sr.cursor.State == cloudagents.StreamOpen {
			owed[cd.sessionID] = true
		}
		res.Streams++
		out[streamScope(cd.sessionID, cd.run.ID)] = sr
	}
	return owed, nil
}

// expireStream records a run whose stream cannot be read as a gap: from the
// last successful read (else the run's start) to the run's last update (else
// now), and marks the stream expired so it is never retried.
func expireStream(sr *streamResult, now time.Time) {
	from := sr.run.CreatedAt
	if !sr.prev.LastSuccessAt.IsZero() {
		from = sr.prev.LastSuccessAt
	}
	to := sr.run.UpdatedAt
	if to.IsZero() || to.Before(from) {
		to = now
	}
	if from.IsZero() {
		from = to
	}
	sr.gap = &store.CloudSyncGap{From: from, To: to}
	sr.cursor = cloudagents.StreamCursor{State: cloudagents.StreamExpired}
}

func (s *Service) readOneStream(ctx context.Context, c cloudagents.Connector, key string, sr *streamResult, last string, now time.Time) error {
	req, err := cloudagents.APIStreamRequest(c, sr.sessionID, sr.run.ID, last)
	if err != nil {
		return err
	}
	rs := &cloudagents.RunStream{RunID: sr.run.ID}
	var dec string
	end, err := s.api.Stream(ctx, req, key, c.StreamWindow, func(ev cloudagents.SSEEvent) bool {
		dec = ev.ID
		return rs.Add(ev, now)
	})
	if end.RetentionSeconds > sr.retention {
		sr.retention = end.RetentionSeconds // the vendor sends it on a refusal too
	}
	if err != nil {
		return err
	}
	sr.stream = rs
	id := dec
	if id == "" {
		id = last
	}
	sr.cursor = cloudagents.StreamCursor{LastEventID: id, State: cloudagents.StreamOpen}
	if rs.Done || end.Reason == cloudagents.StreamEndDone {
		sr.cursor.State = cloudagents.StreamDone
	}
	// Activity times: a call is placed at its first event's time, which the
	// event id carries (<epoch ms>-<seq>, live-verified 2026-11-01). Only a
	// call whose id did not parse falls back: to the run's last update when
	// that is earlier than the read (a replay of a finished run), else to
	// the read time.
	at := now
	if !sr.run.UpdatedAt.IsZero() && sr.run.UpdatedAt.Before(now) && sr.run.Lifecycle.Terminal() {
		at = sr.run.UpdatedAt
	}
	for i := range rs.Activity {
		if rs.Activity[i].At.IsZero() {
			rs.Activity[i].At = at
		}
	}
	return nil
}

// childScopePrefix scopes a pending parent-to-child link on the live
// stream: "child/<child session id>", cursor = the parent session id. It
// carries no gaps, so the account view's gap count never sees it.
const childScopePrefix = "child/"

// passLinks are the parent-to-child links this pass's vendor data reported:
// a Cursor run stream's create_agent results, and a listed session's own
// parent id (Devin parent_session_id, OpenHands parent_conversation_id).
// Nothing is guessed: only ids the vendor returned link.
func passLinks(p *apiPass) []cloudagents.ChildLink {
	var out []cloudagents.ChildLink
	for _, sr := range p.streamed {
		if sr.stream == nil {
			continue
		}
		for _, child := range sr.stream.Children {
			out = append(out, cloudagents.ChildLink{Parent: sr.sessionID, Child: child})
		}
	}
	for _, ss := range p.sessions {
		if ss.listed && ss.task.ParentID != "" {
			out = append(out, cloudagents.ChildLink{Parent: ss.task.ParentID, Child: ss.task.ID})
		}
		if ss.listed && ss.task.ForkedFromID != "" {
			out = append(out, cloudagents.ChildLink{Parent: ss.task.ForkedFromID, Child: ss.task.ID, Fork: true})
		}
	}
	return out
}

// apiLineage records the parent-to-child links this pass reported
// (passLinks) and stamps each child session's parent once both sessions
// exist (step 6b). The other end of a link is often listed in a later pass
// (a child created after its parent's run was read, a parent outside the
// window), so a link waits as a checkpoint until both have landed; one that
// never completes is dropped after OpenSessionTTL.
func (s *Service) apiLineage(ctx context.Context, p *apiPass) error {
	for _, l := range passLinks(p) {
		if _, ok := cloudagents.ChildLineage(l); !ok {
			continue
		}
		if p.skipped[l.Parent] || p.skipped[l.Child] {
			// A link to a session the account does not keep never waits
			// for it: lineage never brings a skipped session back.
			continue
		}
		scope := childScopePrefix + l.Child
		prev, found, err := s.st.LoadCloudSyncCheckpoint(ctx, p.a.ID, models.SyncStreamLive, scope)
		if err != nil {
			return err
		}
		first := p.now
		if found && !prev.LastAttemptAt.IsZero() {
			first = prev.LastAttemptAt
		}
		if err := s.st.SaveCloudSyncCheckpoint(ctx, store.CloudSyncCheckpoint{
			AccountPK: p.a.ID, Stream: models.SyncStreamLive, Scope: scope, Cursor: cloudagents.LinkCursor(l),
			LastAttemptAt: first, UpdatedAt: p.now,
		}); err != nil {
			return err
		}
	}
	live, err := s.st.ListCloudSyncCheckpoints(ctx, p.a.ID, models.SyncStreamLive)
	if err != nil {
		return err
	}
	for _, cp := range live {
		child, ok := strings.CutPrefix(cp.Scope, childScopePrefix)
		if !ok {
			continue
		}
		done, err := s.applyChildLink(ctx, cloudagents.LinkFromCursor(child, cp.Cursor))
		if err != nil {
			return err
		}
		if done || p.now.Sub(cp.LastAttemptAt) > OpenSessionTTL {
			if _, err := s.st.DeleteCloudSyncCheckpoint(ctx, p.a.ID, models.SyncStreamLive, cp.Scope); err != nil {
				return err
			}
		}
	}
	return nil
}

// applyChildLink stamps the child session's parent when both sessions
// exist; done is true when the link needs no further pass (stamped, or
// invalid).
func (s *Service) applyChildLink(ctx context.Context, l cloudagents.ChildLink) (bool, error) {
	lin, ok := cloudagents.ChildLineage(l)
	if !ok {
		return true, nil
	}
	for _, id := range []string{l.Child, l.Parent} {
		exists, err := s.st.SessionExists(ctx, id)
		if err != nil || !exists {
			return false, err
		}
	}
	if _, err := s.st.SetSessionLineage(ctx, lin); err != nil {
		return false, err
	}
	return true, nil
}

// saveSessionState writes or deletes a session's history checkpoint: kept
// while the session is live, its detail or a run stream is owed or its
// history is not drained; deleted once it is terminal and fully read.
// Untouched sessions keep their checkpoint as it was.
func (s *Service) saveSessionState(ctx context.Context, accountPK int64, ss *apiSession, now time.Time) error {
	if !ss.listed && !ss.hadCP {
		return nil
	}
	lastSeen := ss.lastSeen
	if ss.listed {
		lastSeen = now
		ss.state.Lifecycle = string(ss.task.Lifecycle)
		ss.state.Harness = ss.task.Harness
		// Only a session this pass worked on updates what it owes. An
		// unlisted one keeps its checkpoint's flags: its list snapshot, if
		// any, says nothing about what was read (it always reads "detail
		// pending", which used to flip a finished session back to owed on
		// every other pass).
		ss.state.DetailPending = ss.task.DetailPending
	}
	terminal := cloudagents.Lifecycle(ss.state.Lifecycle).Terminal()
	abandoned := !ss.listed && !lastSeen.IsZero() && now.Sub(lastSeen) > OpenSessionTTL
	if (terminal && !ss.state.Owed() && ss.drained) || abandoned {
		_, err := s.st.DeleteCloudSyncCheckpoint(ctx, accountPK, models.SyncStreamSessionHistory, ss.task.ID)
		return err
	}
	return s.st.SaveCloudSyncCheckpoint(ctx, store.CloudSyncCheckpoint{
		AccountPK: accountPK, Stream: models.SyncStreamSessionHistory, Scope: ss.task.ID,
		Cursor: cloudagents.EncodeHistoryCursor(ss.state), LastAttemptAt: now, LastSuccessAt: lastSeen,
	})
}
