package cloudagentssvc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudagents"
	"github.com/marmutapp/superbased-observer/internal/keystore"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// KeystoreService is the keychain service the connectors' secrets live
// under (CA-D5), distinct from every other Observer credential. The two CLI
// connectors store nothing: the vendor CLI's own login is the credential.
// The API connectors (lane CA-B2) keep one key per linked account here
// (SecretName), and nowhere else.
const KeystoreService = "sbo-cloudagents-v1"

// OpenSessionTTL is how long a live session that stopped appearing in the
// list keeps being re-read by id before its tracking is abandoned.
const OpenSessionTTL = 14 * 24 * time.Hour

// Store is the store seam the service uses (implemented by *store.Store).
type Store interface {
	ListCloudConnectorAccounts(ctx context.Context, connector string) ([]store.CloudConnectorAccount, error)
	UpsertCloudConnectorAccount(ctx context.Context, a store.CloudConnectorAccount) (int64, error)
	SetCloudConnectorAccountState(ctx context.Context, id int64, coverage, errorClass string) (bool, error)
	DeleteCloudConnectorAccount(ctx context.Context, id int64) (bool, error)
	LoadCloudSyncCheckpoint(ctx context.Context, accountPK int64, stream, scope string) (store.CloudSyncCheckpoint, bool, error)
	SaveCloudSyncCheckpoint(ctx context.Context, c store.CloudSyncCheckpoint) error
	ListCloudSyncCheckpoints(ctx context.Context, accountPK int64, stream string) ([]store.CloudSyncCheckpoint, error)
	DeleteCloudSyncCheckpoint(ctx context.Context, accountPK int64, stream, scope string) (bool, error)
	CommitCloudSyncPage(ctx context.Context, entries []store.CloudUsageEntry, cp store.CloudSyncCheckpoint) (int, error)
	// ListCloudUsage reads a session's stored ledger rows, so a revisable
	// figure supersedes its previous revision (resolveRevisions).
	ListCloudUsage(ctx context.Context, f store.CloudUsageFilter) ([]store.CloudUsageEntry, error)
	Ingest(ctx context.Context, events []models.ToolEvent, tokens []models.TokenEvent, opts store.IngestOptions) (store.IngestResult, error)
	ResolveRemoteProject(ctx context.Context, remote string) (int64, error)
	ProjectByRemote(ctx context.Context, remote string) (store.RemoteProject, bool, error)
	ProjectRootForSession(ctx context.Context, sessionID string) (string, error)
	SetSessionExecution(ctx context.Context, ex models.SessionExecution) (bool, error)
	SessionIDByVendorRef(ctx context.Context, tool, ref string) (string, bool, error)
	// SessionExists and SetSessionLineage stamp a child agent's session
	// with the parent that created it (apiLineage).
	SessionExists(ctx context.Context, id string) (bool, error)
	SetSessionLineage(ctx context.Context, lin models.SessionLineage) (bool, error)
	// RecordCloudSessionLinks stores the PRs and branches a task's vendor
	// reported (lane CA-C5, delivery credit).
	RecordCloudSessionLinks(ctx context.Context, links []store.CloudSessionLink, now time.Time) (int, error)
	// SetCloudConnectorVendorUser and MarkCloudConnectorVendorUserPurged
	// keep a member-scoped account's chosen vendor user and the state of
	// the removal of the other members' sessions (CLOUDAGENTS-6, owner.go).
	SetCloudConnectorVendorUser(ctx context.Context, id int64, userID string) (bool, error)
	MarkCloudConnectorVendorUserPurged(ctx context.Context, id int64, userID string) (bool, error)
	// PurgeToolSessions removes sessions another member started, with every
	// row the adapter purge's decision table assigns to them.
	PurgeToolSessions(ctx context.Context, tool string, sessionIDs []string) (store.PurgeResult, error)
	// DeleteSessionlessCloudUsage removes the ledger rows of the tasks of
	// another person or a service account that landed no session (a Warp oz
	// run): only the ledger holds them (CA-T8).
	DeleteSessionlessCloudUsage(ctx context.Context, connector string, sessionIDs []string) (int, error)
}

// Egress runs one connector request (internal/cloudagentsnet).
type Egress interface {
	Run(ctx context.Context, req cloudagents.Request) ([]byte, error)
}

// Options wire a Service.
type Options struct {
	Store Store
	Net   Egress
	// API is the HTTPS egress of the API connectors (the same
	// internal/cloudagentsnet client); nil leaves them unusable.
	API APIEgress
	// Keys is the keychain (opened lazily by the caller). The CLI
	// connectors never touch it.
	Keys   keystore.Store
	Logger *slog.Logger
	Now    func() time.Time
}

// Service is the cloud-agent connector service. Safe for concurrent use;
// one sync runs at a time.
type Service struct {
	st    Store
	net   Egress
	api   APIEgress
	keys  keystore.Store
	log   *slog.Logger
	now   func() time.Time
	runMu sync.Mutex

	backoffMu sync.Mutex
	backoff   map[int64]time.Time // account id -> no automatic sync before
	failures  map[int64]int
}

// New returns a Service.
func New(o Options) *Service {
	s := &Service{
		st: o.Store, net: o.Net, api: o.API, keys: o.Keys, log: o.Logger, now: o.Now,
		backoff: map[int64]time.Time{}, failures: map[int64]int{},
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s
}

// Errors the API and CLI map to a 4xx.
var (
	ErrInvalid  = errors.New("cloudagents: invalid request")
	ErrNotFound = errors.New("cloudagents: no such linked account")
)

// --- page model ----------------------------------------------------------------

// SignalCoverage is one signal's coverage on one account or connector.
type SignalCoverage struct {
	Signal cloudagents.Signal        `json:"signal"`
	State  cloudagents.CoverageState `json:"state"`
	Label  string                    `json:"label"`
}

// ConnectorInfo is one connector as the connect picker shows it.
type ConnectorInfo struct {
	ID           string                 `json:"id"`
	Label        string                 `json:"label"`
	Provider     string                 `json:"provider"`
	Tool         string                 `json:"tool"`
	Kind         cloudagents.SourceKind `json:"kind"`
	Command      string                 `json:"command,omitempty"`
	Experimental bool                   `json:"experimental"`
	// SurfaceHost is the surface host pulled sessions carry (CA-D15).
	SurfaceHost string `json:"surface_host,omitempty"`
	// Placeholder is the bucket project a task with no trusted repository
	// lands under, and PlaceholderNote its caption (CA-D16).
	Placeholder     string `json:"placeholder_project"`
	PlaceholderNote string `json:"placeholder_note"`
	// Signals is the best each signal can reach on this connector.
	Signals []SignalCoverage `json:"signals"`
	DocRef  string           `json:"doc_ref"`
	// NeedsKey is true for an API connector: connecting takes an API key
	// (KeyLabel names it), entered once and kept in the keychain only.
	NeedsKey bool   `json:"needs_key"`
	KeyLabel string `json:"key_label,omitempty"`
	// Params are the non-secret values connecting also asks for.
	Params []cloudagents.ParamSpec `json:"params"`
	// Hosts are the exact HTTPS hosts an API connector calls.
	Hosts []string `json:"hosts,omitempty"`
	// Grounding is the connector's coverage level (CA-D17): how well the
	// vendor surface it reads is established (cloudagents.GroundingLevels),
	// with its label, its rank (0 the best) and what it means for a user.
	Grounding        cloudagents.Grounding `json:"grounding"`
	GroundingLabel   string                `json:"grounding_label"`
	GroundingRank    int                   `json:"grounding_rank"`
	GroundingMeaning string                `json:"grounding_meaning"`
	// ChoosesUser is true for a member-scoped connector (Devin): the list
	// holds every member's sessions, so an account names its vendor user
	// (UserLabel) from the picker before anything is pulled.
	ChoosesUser bool   `json:"chooses_user"`
	UserLabel   string `json:"user_label,omitempty"`
}

// Gap is an uncovered interval: of discovery (Scope ""), or of one run's
// event stream that could not be resumed (Scope "run <agent>/<run>").
type Gap struct {
	From  time.Time `json:"from"`
	To    time.Time `json:"to"`
	Scope string    `json:"scope,omitempty"`
}

// AccountView is one linked account on the page.
type AccountView struct {
	ID          int64                     `json:"id"`
	Connector   string                    `json:"connector"`
	Label       string                    `json:"label"`
	Provider    string                    `json:"provider"`
	AccountID   string                    `json:"account_id"`
	Display     string                    `json:"display,omitempty"`
	Coverage    cloudagents.CoverageState `json:"coverage"`
	LastError   string                    `json:"last_error,omitempty"`
	LastAttempt *time.Time                `json:"last_attempt,omitempty"`
	LastSuccess *time.Time                `json:"last_success,omitempty"`
	Gaps        []Gap                     `json:"gaps"`
	// ActivityGaps counts the run streams that could not be resumed.
	ActivityGaps int `json:"activity_gaps"`
	// OpenTasks counts sessions still running (a running lifecycle, or one
	// not known); Waiting counts live sessions waiting for the user (not
	// running, not finished); Owed counts finished sessions kept only
	// because a read is still owed (detail, a run stream or history), which
	// the next pass re-reads. Neither counts a finished, fully read session.
	OpenTasks int              `json:"open_tasks"`
	Waiting   int              `json:"waiting"`
	Owed      int              `json:"owed"`
	Signals   []SignalCoverage `json:"signals"`
	LinkedAt  time.Time        `json:"linked_at"`
	// UserState is a member-scoped account's vendor user state
	// (vendor_user_not_chosen: nothing is pulled until one is chosen);
	// omitted for any other connector. VendorUser is the chosen user id,
	// and PurgePending is true while the removal of the sessions other
	// members started is still owed to the next pass.
	UserState    cloudagents.VendorUserState `json:"user_state,omitempty"`
	VendorUser   string                      `json:"vendor_user,omitempty"`
	PurgePending bool                        `json:"purge_pending,omitempty"`
}

// View is the Settings > Cloud agents page model.
type View struct {
	GeneratedAt time.Time       `json:"generated_at"`
	Connectors  []ConnectorInfo `json:"connectors"`
	Accounts    []AccountView   `json:"accounts"`
}

func signalsFor(c cloudagents.Connector, account cloudagents.CoverageState) []SignalCoverage {
	return signalsWithGaps(c, account, false)
}

// signalsWithGaps is signalsFor for an account whose activity history has
// recorded gaps (an expired stream): activity is at most Partial history.
func signalsWithGaps(c cloudagents.Connector, account cloudagents.CoverageState, activityGaps bool) []SignalCoverage {
	out := make([]SignalCoverage, 0, len(cloudagents.Signals()))
	for _, sig := range cloudagents.Signals() {
		st := c.CoverageFor(sig, account)
		if sig == cloudagents.SignalActivity && activityGaps && st == cloudagents.CoverageVerified {
			st = cloudagents.CoveragePartialHistory
		}
		out = append(out, SignalCoverage{Signal: sig, State: st, Label: st.Label()})
	}
	return out
}

// Catalog returns the connectors the connect picker offers.
func Catalog() []ConnectorInfo {
	out := make([]ConnectorInfo, 0, len(cloudagents.Connectors))
	for _, c := range cloudagents.Connectors {
		info := ConnectorInfo{
			ID: c.ID, Label: c.Label, Provider: c.Provider, Tool: c.Tool, Kind: c.Kind, Command: c.Command,
			Experimental: c.Experimental, SurfaceHost: c.SurfaceHost,
			Placeholder: cloudagents.PlaceholderRoot(c.ID), PlaceholderNote: cloudagents.NoteRepositoryNotReported,
			Signals: signalsFor(c, cloudagents.CoverageVerified), DocRef: c.DocRef,
			NeedsKey: c.Kind == cloudagents.SourceAPI, KeyLabel: c.KeyLabel,
			Params: append([]cloudagents.ParamSpec{}, c.Params...), Hosts: append([]string(nil), c.APIHosts...),
			ChoosesUser: c.MemberScoped(),
		}
		if c.MemberScoped() {
			info.UserLabel = c.MemberUsers.Label
		}
		g := c.Grounding()
		lvl, _ := cloudagents.LevelOf(g)
		info.Grounding, info.GroundingLabel, info.GroundingRank, info.GroundingMeaning = g, lvl.Label, g.Rank(), lvl.Meaning
		out = append(out, info)
	}
	return out
}

func optTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// Status returns the page model. It reads the database only.
func (s *Service) Status(ctx context.Context) (View, error) {
	v := View{GeneratedAt: s.now().UTC(), Connectors: Catalog(), Accounts: []AccountView{}}
	accts, err := s.st.ListCloudConnectorAccounts(ctx, "")
	if err != nil {
		return v, err
	}
	for _, a := range accts {
		av, err := s.accountView(ctx, a)
		if err != nil {
			return v, err
		}
		v.Accounts = append(v.Accounts, av)
	}
	return v, nil
}

func (s *Service) accountView(ctx context.Context, a store.CloudConnectorAccount) (AccountView, error) {
	c, ok := cloudagents.ConnectorByID(a.Connector)
	av := AccountView{
		ID: a.ID, Connector: a.Connector, Provider: a.Provider, AccountID: a.AccountID, Display: a.DisplayEmail,
		Coverage: cloudagents.CoverageState(a.CoverageState), LastError: a.LastErrorClass, LinkedAt: a.CreatedAt,
		Gaps: []Gap{},
	}
	if av.Coverage == "" {
		av.Coverage = cloudagents.CoverageNotEstablished
	}
	if !ok {
		// A row from a newer build's connector: shown, never synced.
		av.Label = a.Connector
		av.Signals = []SignalCoverage{}
		return av, nil
	}
	av.Label = c.Label
	av.Signals = signalsFor(c, av.Coverage)
	av.UserState = cloudagents.VendorUserStateOf(c, a.VendorUserID)
	if av.UserState == cloudagents.VendorUserChosen {
		av.VendorUser = a.VendorUserID
		av.PurgePending = a.VendorUserPurged != a.VendorUserID
	}
	cp, found, err := s.st.LoadCloudSyncCheckpoint(ctx, a.ID, models.SyncStreamDiscovery, "")
	if err != nil {
		return av, err
	}
	if found {
		av.LastAttempt, av.LastSuccess = optTime(cp.LastAttemptAt), optTime(cp.LastSuccessAt)
		for _, g := range cp.Gaps {
			av.Gaps = append(av.Gaps, Gap{From: g.From, To: g.To})
		}
	}
	open, err := s.st.ListCloudSyncCheckpoints(ctx, a.ID, models.SyncStreamSessionHistory)
	if err != nil {
		return av, err
	}
	av.OpenTasks, av.Waiting, av.Owed = checkpointCounts(open)
	live, err := s.st.ListCloudSyncCheckpoints(ctx, a.ID, models.SyncStreamLive)
	if err != nil {
		return av, err
	}
	for _, l := range live {
		for _, g := range l.Gaps {
			av.Gaps = append(av.Gaps, Gap{From: g.From, To: g.To, Scope: "run " + l.Scope})
			av.ActivityGaps++
		}
	}
	if av.ActivityGaps > 0 {
		av.Signals = signalsWithGaps(c, av.Coverage, true)
	}
	return av, nil
}

// --- connect / test / disconnect ---------------------------------------------

// ProbeResult is the outcome of a connection test.
type ProbeResult struct {
	Connector  string                    `json:"connector"`
	OK         bool                      `json:"ok"`
	AccountID  string                    `json:"account_id,omitempty"`
	Display    string                    `json:"display,omitempty"`
	Coverage   cloudagents.CoverageState `json:"coverage"`
	ErrorClass cloudagents.ErrorClass    `json:"error_class,omitempty"`
}

// Credentials are what connecting an API connector takes: the key (held in
// memory only until it is written to the keychain) and the non-secret
// parameters the row declares. The CLI connectors take none.
type Credentials struct {
	Key    string
	Params map[string]string
}

// String never prints the key.
func (c Credentials) String() string { return fmt.Sprintf("credentials(key set: %v)", c.Key != "") }

// GoString never prints the key.
func (c Credentials) GoString() string { return c.String() }

// Test runs a connector's identity probe and links nothing. It is a vendor
// call, so it runs only on an explicit user action.
func (s *Service) Test(ctx context.Context, connector string) (ProbeResult, error) {
	return s.TestWith(ctx, connector, Credentials{})
}

// TestWith is Test for a connector that takes credentials (an API key).
func (s *Service) TestWith(ctx context.Context, connector string, cred Credentials) (ProbeResult, error) {
	c, ok := cloudagents.ConnectorByID(connector)
	if !ok {
		return ProbeResult{}, fmt.Errorf("%w: unknown connector %q", ErrInvalid, connector)
	}
	if c.Kind == cloudagents.SourceAPI {
		return s.testAPI(ctx, c, cred)
	}
	res := ProbeResult{Connector: c.ID}
	req, err := c.IdentityRequest()
	if err != nil {
		return res, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	b, err := s.net.Run(ctx, req)
	if err == nil {
		var id cloudagents.Identity
		id, err = cloudagents.ParseIdentity(c.ID, b)
		res.AccountID, res.Display = id.AccountID, id.Display
	}
	res.ErrorClass = cloudagents.ClassOf(err)
	res.Coverage = cloudagents.CoverageAfter("", res.ErrorClass)
	res.OK = err == nil
	return res, nil
}

// Connect probes a connector and, when the probe succeeds, links the
// account (re-linking the same account updates its row). A failed probe
// links nothing and is returned as the result, not an error.
func (s *Service) Connect(ctx context.Context, connector string) (ProbeResult, *AccountView, error) {
	return s.ConnectWith(ctx, connector, Credentials{})
}

// ConnectWith is Connect for a connector that takes credentials: after a
// successful probe the key goes to the keychain (service
// sbo-cloudagents-v1, entry SecretName) and nowhere else; if the keychain
// refuses it, a new account is not linked and a re-connect of an account
// already linked leaves that account (its row and its previous key) as it
// was: the rollback only ever removes a row this call created.
func (s *Service) ConnectWith(ctx context.Context, connector string, cred Credentials) (ProbeResult, *AccountView, error) {
	res, err := s.TestWith(ctx, connector, cred)
	if err != nil || !res.OK {
		return res, nil, err
	}
	c, _ := cloudagents.ConnectorByID(connector)
	prior, existed, err := s.findAccount(ctx, c, res.AccountID)
	if err != nil {
		return res, nil, err
	}
	id, err := s.st.UpsertCloudConnectorAccount(ctx, store.CloudConnectorAccount{
		Connector: c.ID, Provider: c.Provider, Issuer: c.Issuer, AccountID: res.AccountID,
		DisplayEmail: res.Display, CoverageState: string(res.Coverage),
	})
	if err != nil {
		return res, nil, err
	}
	if c.Kind == cloudagents.SourceAPI {
		if err := s.storeKey(c, id, cred.Key); err != nil {
			if existed {
				// The working account and its previous key stay; only the
				// row fields this call rewrote are put back.
				prior.ID = 0
				_, _ = s.st.UpsertCloudConnectorAccount(ctx, prior)
			} else {
				_, _ = s.st.DeleteCloudConnectorAccount(ctx, id)
			}
			return res, nil, err
		}
	}
	s.clearBackoff(id)
	a, err := s.account(ctx, id)
	if err != nil {
		return res, nil, err
	}
	av, err := s.accountView(ctx, a)
	if err != nil {
		return res, nil, err
	}
	return res, &av, nil
}

// Disconnect unlinks an account: its checkpoints go with it (they are
// collection state); ingested sessions and ledger history stay. Any keychain
// entry the connector kept is deleted first: when the keychain refuses the
// delete, the account stays linked and ErrKeychainDelete is returned, so the
// live vendor key is never orphaned without a row to retry the disconnect
// from.
func (s *Service) Disconnect(ctx context.Context, id int64) error {
	a, err := s.account(ctx, id)
	if err != nil {
		return err
	}
	if c, ok := cloudagents.ConnectorByID(a.Connector); ok && c.Kind != cloudagents.SourceCLI && s.keys != nil {
		// API connectors (lane CA-B2) keep one secret per account.
		if err := s.keys.Delete(SecretName(a.Connector, a.ID)); err != nil && !errors.Is(err, keystore.ErrNotFound) {
			s.log.Info("cloud agents: keychain refused to delete the key; account kept", "connector", a.Connector)
			return ErrKeychainDelete
		}
	}
	if _, err := s.st.DeleteCloudConnectorAccount(ctx, id); err != nil {
		return err
	}
	s.clearBackoff(id)
	return nil
}

// SecretName is the keychain entry name of an API connector's account key.
func SecretName(connector string, accountPK int64) string {
	return fmt.Sprintf("%s.%d.key", connector, accountPK)
}

// findAccount returns the linked row for (connector, issuer, account id),
// the key UpsertCloudConnectorAccount conflicts on.
func (s *Service) findAccount(ctx context.Context, c cloudagents.Connector, accountID string) (store.CloudConnectorAccount, bool, error) {
	accts, err := s.st.ListCloudConnectorAccounts(ctx, c.ID)
	if err != nil {
		return store.CloudConnectorAccount{}, false, err
	}
	for _, a := range accts {
		if a.Connector == c.ID && a.Issuer == c.Issuer && a.AccountID == accountID {
			return a, true, nil
		}
	}
	return store.CloudConnectorAccount{}, false, nil
}

func (s *Service) account(ctx context.Context, id int64) (store.CloudConnectorAccount, error) {
	accts, err := s.st.ListCloudConnectorAccounts(ctx, "")
	if err != nil {
		return store.CloudConnectorAccount{}, err
	}
	for _, a := range accts {
		if a.ID == id {
			return a, nil
		}
	}
	return store.CloudConnectorAccount{}, ErrNotFound
}

// --- sync ----------------------------------------------------------------------

// SyncResult reports one account's sync.
type SyncResult struct {
	AccountID   int64                     `json:"account"`
	Connector   string                    `json:"connector"`
	Pages       int                       `json:"pages"`
	Tasks       int                       `json:"tasks"`
	Views       int                       `json:"views"`
	SessionsNew int                       `json:"sessions_touched"`
	ActionsNew  int                       `json:"actions_inserted"`
	LedgerNew   int                       `json:"ledger_inserted"`
	Partial     bool                      `json:"partial"`
	Coverage    cloudagents.CoverageState `json:"coverage"`
	ErrorClass  cloudagents.ErrorClass    `json:"error_class,omitempty"`
	// OpenTasks, Waiting and Owed are AccountView's, after the pass.
	OpenTasks     int `json:"open_tasks"`
	Waiting       int `json:"waiting"`
	Owed          int `json:"owed"`
	SkippedNoTime int `json:"skipped_no_time"`
	// Details, HistoryPages and Streams count an API connector's detail
	// calls, history pages and run streams read this pass; DetailPending
	// counts sessions whose detail or history read a later pass still owes
	// (over budget, or a transient vendor failure: a 5xx or a timeout);
	// StreamGaps counts streams that could not be resumed this pass.
	Details       int `json:"details"`
	DetailPending int `json:"detail_pending"`
	HistoryPages  int `json:"history_pages"`
	Streams       int `json:"streams"`
	StreamGaps    int `json:"stream_gaps"`
	// RepositoryNotReported counts tasks this pass filed under the
	// connector's placeholder project because no trusted repository was
	// reported (CA-D16; the "repository not reported" note).
	RepositoryNotReported int `json:"repository_not_reported"`
	// NoToolRows counts tasks whose harness names no tool (Warp's own oz
	// harness): only their native usage reached the ledger; no session,
	// action or token row was written (cloudagents.ForTask).
	NoToolRows int `json:"no_tool_rows,omitempty"`
	// UserState is a member-scoped account's vendor user state;
	// vendor_user_not_chosen means this pass made no call and pulled
	// nothing (choose the user first). Omitted for other connectors.
	UserState cloudagents.VendorUserState `json:"user_state,omitempty"`
	// SkippedOtherMember, SkippedServiceUser and SkippedNoUser count listed
	// sessions of a member-scoped account that were not landed because
	// another member, a service user or no one started them
	// (cloudagents.Ownership). Counts only: nothing of theirs is stored.
	SkippedOtherMember int `json:"skipped_other_member,omitempty"`
	SkippedServiceUser int `json:"skipped_service_user,omitempty"`
	SkippedNoUser      int `json:"skipped_no_user,omitempty"`
	// PurgedOtherMember counts sessions landed earlier that this pass removed
	// because the list says someone other than the chosen user started them
	// (the pass after a user is chosen or changed).
	PurgedOtherMember int `json:"purged_other_member,omitempty"`
	// PurgedLedgerOnly counts the ledger rows that pass removed of tasks
	// someone other than the chosen user started that landed no session (a
	// Warp run under a harness with no Observer tool: only its credits and
	// USD rows were on this node).
	PurgedLedgerOnly int `json:"purged_ledger_only,omitempty"`
}

// SyncAll syncs every linked account. With no account linked it returns
// nothing and makes no vendor call (zero egress).
func (s *Service) SyncAll(ctx context.Context) ([]SyncResult, error) {
	accts, err := s.st.ListCloudConnectorAccounts(ctx, "")
	if err != nil {
		return nil, err
	}
	var out []SyncResult
	for _, a := range accts {
		r, err := s.SyncAccount(ctx, a.ID)
		if err != nil && !IsCollectionError(err) {
			return out, err
		}
		out = append(out, r)
	}
	return out, nil
}

// collectionError marks a vendor-side failure already recorded on the
// account (its class is in the result); SyncAll carries on past it.
type collectionError struct{ err error }

func (e collectionError) Error() string { return e.err.Error() }
func (e collectionError) Unwrap() error { return e.err }

// IsCollectionError reports whether err is a vendor-side failure the
// service already recorded on the account (the SyncResult carries its
// class), as opposed to a local error.
func IsCollectionError(err error) bool {
	var ce collectionError
	return errors.As(err, &ce)
}

// SyncAccount runs one discovery pass for one linked account, lands what it
// found, and commits the checkpoint after the sessions are in (ingest is
// idempotent, so a crash between the two re-pulls the page: at-least-once).
func (s *Service) SyncAccount(ctx context.Context, id int64) (SyncResult, error) {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	a, err := s.account(ctx, id)
	if err != nil {
		return SyncResult{AccountID: id}, err
	}
	res := SyncResult{AccountID: a.ID, Connector: a.Connector}
	c, ok := cloudagents.ConnectorByID(a.Connector)
	if !ok {
		return res, fmt.Errorf("%w: connector %q is not known to this build", ErrInvalid, a.Connector)
	}
	if c.Kind == cloudagents.SourceAPI {
		return s.syncAPI(ctx, c, a, res)
	}
	return s.syncCLI(ctx, c, a, res)
}

// syncCLI is one pass of a CLI connector (lane CA-B1).
func (s *Service) syncCLI(ctx context.Context, c cloudagents.Connector, a store.CloudConnectorAccount, res SyncResult) (SyncResult, error) {
	now := s.now().UTC()
	prevStore, _, err := s.st.LoadCloudSyncCheckpoint(ctx, a.ID, models.SyncStreamDiscovery, "")
	if err != nil {
		return res, err
	}
	prev := fromStoreCheckpoint(prevStore)

	d := cloudagents.NewDiscovery(c, cloudagents.Since(prev))
	cursor := ""
	for {
		req, err := c.ListRequest(cursor)
		if err != nil {
			return s.fail(ctx, a, prevStore, now, res, err)
		}
		b, err := s.net.Run(ctx, req)
		if err != nil {
			return s.fail(ctx, a, prevStore, now, res, err)
		}
		page, err := cloudagents.ParsePage(c.ID, b)
		if err != nil {
			return s.fail(ctx, a, prevStore, now, res, err)
		}
		cursor = page.Cursor
		if !d.Add(page) {
			break
		}
	}
	res.Pages = d.Pages()

	var ledger []store.CloudUsageEntry
	landed := map[string]cloudagents.Task{}
	land := func(t cloudagents.Task) error {
		r, entries, err := s.landTask(ctx, c, a, t)
		if err != nil {
			return err
		}
		res.SessionsNew += r.SessionsTouched
		res.ActionsNew += r.ActionsInserted
		if r.skippedNoTime {
			res.SkippedNoTime++
		}
		if r.repoNotReported {
			res.RepositoryNotReported++
		}
		ledger = append(ledger, entries...)
		landed[t.ID] = t
		return nil
	}
	for _, t := range d.Tasks() {
		if err := land(t); err != nil {
			return res, err
		}
	}
	res.Tasks = len(d.Tasks())

	// Live sessions that fell off the list are re-read by id.
	open, err := s.st.ListCloudSyncCheckpoints(ctx, a.ID, models.SyncStreamSessionHistory)
	if err != nil {
		return res, err
	}
	openIDs := make([]string, 0, len(open))
	for _, o := range open {
		openIDs = append(openIDs, o.Scope)
	}
	seen := map[string]bool{}
	for id := range landed {
		seen[id] = true
	}
	for _, sid := range cloudagents.RefreshCandidates(c, openIDs, seen) {
		req, err := c.ViewRequest(sid)
		if err != nil {
			continue
		}
		b, err := s.net.Run(ctx, req)
		if err != nil {
			if cl := cloudagents.ClassOf(err); cl == cloudagents.ErrNotSignedIn || cl == cloudagents.ErrRateLimited {
				return s.fail(ctx, a, prevStore, now, res, err)
			}
			continue // one unreadable session does not fail the pass
		}
		res.Views++
		t, err := cloudagents.ParseCopilotView(b)
		if err != nil || t.ID != sid {
			continue
		}
		if err := land(t); err != nil {
			return res, err
		}
	}
	if err := s.trackOpen(ctx, a.ID, open, landed, now); err != nil {
		return res, err
	}

	next, partial := d.Next(prev, now)
	cp := toStoreCheckpoint(a.ID, next)
	cp.LastAttemptAt = now
	added, err := s.st.CommitCloudSyncPage(ctx, ledger, cp)
	if err != nil {
		return res, err
	}
	res.LedgerNew = added
	res.Partial = partial
	res.Coverage = cloudagents.CoverageVerified
	if partial {
		res.Coverage = cloudagents.CoveragePartialHistory
	}
	if _, err := s.st.SetCloudConnectorAccountState(ctx, a.ID, string(res.Coverage), ""); err != nil {
		return res, err
	}
	s.clearBackoff(a.ID)
	if remaining, err := s.st.ListCloudSyncCheckpoints(ctx, a.ID, models.SyncStreamSessionHistory); err == nil {
		res.OpenTasks, res.Waiting, res.Owed = checkpointCounts(remaining)
	}
	return res, nil
}

// fail records a failed pass: the attempt time on the checkpoint (cursor,
// mark and gaps untouched, so nothing is skipped), the coverage the error
// class implies, and a backoff for the automatic loop.
func (s *Service) fail(ctx context.Context, a store.CloudConnectorAccount, prev store.CloudSyncCheckpoint, now time.Time, res SyncResult, cause error) (SyncResult, error) {
	class := cloudagents.ClassOf(cause)
	if class == cloudagents.ErrNone {
		class = cloudagents.ErrFailed
	}
	res.ErrorClass = class
	res.Coverage = cloudagents.CoverageAfter(cloudagents.CoverageState(a.CoverageState), class)
	prev.AccountPK, prev.Stream, prev.Scope = a.ID, models.SyncStreamDiscovery, ""
	prev.LastAttemptAt = now
	if err := s.st.SaveCloudSyncCheckpoint(ctx, prev); err != nil {
		return res, err
	}
	if _, err := s.st.SetCloudConnectorAccountState(ctx, a.ID, string(res.Coverage), string(class)); err != nil {
		return res, err
	}
	s.recordFailure(a.ID, class, now)
	s.log.Info("cloud agents: sync failed", "connector", a.Connector, "class", string(class))
	return res, collectionError{cause}
}

// landedTask is what landing one task changed.
type landedTask struct {
	store.IngestResult
	skippedNoTime bool
	// repoNotReported is true when the task sits under the connector's
	// placeholder project (CA-D16).
	repoNotReported bool
	// noToolRows is true when the task's harness names no tool: only its
	// ledger rows were computed.
	noToolRows bool
}

// landTask files one task: the session row it merges into (CA-D12), its
// project (CA-D3, never moving a session another rail filed), the lifecycle
// actions and any token total through store.Ingest, then the
// execution_location stamp. It returns the task's ledger entries for the
// page commit.
func (s *Service) landTask(ctx context.Context, c cloudagents.Connector, a store.CloudConnectorAccount, t cloudagents.Task, acts ...cloudagents.Activity) (landedTask, []store.CloudUsageEntry, error) {
	c, attributed := cloudagents.ForTask(c, t)
	if !attributed {
		// No tool for this harness: no session row can exist (sessions.tool
		// is required), so the run's native usage lands in the ledger alone,
		// scoped to its run id.
		entries, err := s.ledgerEntries(ctx, c, t.ID, cloudagents.MapLedger(c, t, t.ID, a.AccountID))
		return landedTask{noToolRows: true}, entries, err
	}
	var lookupErr error
	byRef := func(ref string) (string, bool) {
		id, ok, err := s.st.SessionIDByVendorRef(ctx, c.Tool, ref)
		if err != nil {
			lookupErr = err
		}
		return id, ok
	}
	sessionID, _ := cloudagents.ResolveSessionID(t, byRef)
	if lookupErr != nil {
		return landedTask{}, nil, lookupErr
	}
	if sessionID == "" {
		return landedTask{}, nil, nil
	}
	resolved, err := s.resolveRoot(ctx, c, t)
	if err != nil {
		return landedTask{}, nil, err
	}
	existing, err := s.st.ProjectRootForSession(ctx, sessionID)
	if err != nil {
		return landedTask{}, nil, err
	}
	root := cloudagents.ChooseProjectRoot(existing, resolved)
	events := cloudagents.MapEvents(c, t, sessionID, root)
	if len(events) == 0 {
		return landedTask{skippedNoTime: true}, nil, nil
	}
	events = append(events, cloudagents.MapActivity(c, sessionID, root, acts)...)
	tokens := cloudagents.MapTokens(c, t, sessionID, root)
	r, err := s.st.Ingest(ctx, events, tokens, store.IngestOptions{
		SessionSurfaces: cloudagents.Surface(c, sessionID),
		OutcomeUpdates:  cloudagents.MapOutcomes(c, sessionID, acts),
	})
	if err != nil {
		return landedTask{}, nil, err
	}
	if _, err := s.st.SetSessionExecution(ctx, cloudagents.Execution(sessionID, t)); err != nil {
		return landedTask{}, nil, err
	}
	if err := s.recordLinks(ctx, c, sessionID, t); err != nil {
		return landedTask{}, nil, err
	}
	entries, err := s.ledgerEntries(ctx, c, sessionID, cloudagents.MapLedger(c, t, sessionID, a.AccountID))
	if err != nil {
		return landedTask{}, nil, err
	}
	return landedTask{IngestResult: r, repoNotReported: cloudagents.IsPlaceholderRoot(root)}, entries, nil
}

// ledgerEntries numbers a task's revisable ledger entries and copies them
// onto the store's row type.
func (s *Service) ledgerEntries(ctx context.Context, c cloudagents.Connector, sessionID string, in []cloudagents.LedgerEntry) ([]store.CloudUsageEntry, error) {
	ledger, err := s.resolveRevisions(ctx, c, sessionID, in)
	if err != nil {
		return nil, err
	}
	var entries []store.CloudUsageEntry
	for _, l := range ledger {
		entries = append(entries, store.CloudUsageEntry{
			Connector: l.Connector, SourceRecordID: l.SourceRecordID, MeasurementSource: l.MeasurementSource,
			ValueType: l.ValueType, Unit: l.Unit, Value: l.Value, MonetaryStatus: l.MonetaryStatus,
			ScopeRun: l.ScopeRun, ScopeSession: l.ScopeSession, ScopeAccount: l.ScopeAccount, ScopeModel: l.ScopeModel,
			IntervalStart: l.IntervalStart, IntervalEnd: l.IntervalEnd, IncludesChildren: l.IncludesChildren,
			ReportedAt: l.ReportedAt, SupersedesID: l.SupersedesID,
		})
	}
	return entries, nil
}

// recordLinks stores the pull requests and branches the vendor said the
// task produced (cloudagents.DeliveryLinks), so the Projects and Delivery
// attribution can credit their commits to this cloud session.
func (s *Service) recordLinks(ctx context.Context, c cloudagents.Connector, sessionID string, t cloudagents.Task) error {
	dl := cloudagents.DeliveryLinks(t)
	if len(dl) == 0 {
		return nil
	}
	links := make([]store.CloudSessionLink, 0, len(dl))
	for _, l := range dl {
		links = append(links, store.CloudSessionLink{
			SessionID: sessionID, Connector: c.ID, Remote: l.Remote, PRNumber: l.PRNumber, Branch: l.Branch,
		})
	}
	_, err := s.st.RecordCloudSessionLinks(ctx, links, s.now().UTC())
	return err
}

// resolveRevisions numbers a task's revisable ledger entries against the
// session's stored rows (cloudagents.ResolveRevisions). Only a task that
// carries one reads the ledger.
func (s *Service) resolveRevisions(ctx context.Context, c cloudagents.Connector, sessionID string, ledger []cloudagents.LedgerEntry) ([]cloudagents.LedgerEntry, error) {
	revisable := false
	for _, l := range ledger {
		revisable = revisable || l.Revisable
	}
	if !revisable {
		return ledger, nil
	}
	stored, err := s.st.ListCloudUsage(ctx, store.CloudUsageFilter{Connector: c.ID, ScopeSession: sessionID})
	if err != nil {
		return nil, err
	}
	prior := make([]cloudagents.PriorLedgerRow, 0, len(stored))
	for _, e := range stored {
		prior = append(prior, cloudagents.PriorLedgerRow{ID: e.ID, SourceRecordID: e.SourceRecordID, Value: e.Value})
	}
	return cloudagents.ResolveRevisions(ledger, prior), nil
}

// resolveRoot returns the project root a task resolves to now. The rule
// table asks whether an inferred remote is already a known project's remote
// (CA-D16) through Store.ProjectByRemote, which never creates a project.
func (s *Service) resolveRoot(ctx context.Context, c cloudagents.Connector, t cloudagents.Task) (string, error) {
	var lookupErr error
	known := func(remote string) bool {
		p, ok, err := s.st.ProjectByRemote(ctx, remote)
		if err != nil {
			lookupErr = err
			return false
		}
		return ok && p.RootPath != ""
	}
	ref := cloudagents.ResolveProject(c, t, known)
	if lookupErr != nil {
		return "", lookupErr
	}
	if ref.Remote == "" {
		return ref.Placeholder, nil
	}
	if _, err := s.st.ResolveRemoteProject(ctx, ref.Remote); err != nil {
		// A remote the store refuses (not a hosted repository) is filed
		// under the placeholder, never guessed.
		return cloudagents.PlaceholderRoot(c.ID), nil
	}
	p, ok, err := s.st.ProjectByRemote(ctx, ref.Remote)
	if err != nil {
		return "", err
	}
	if !ok || p.RootPath == "" {
		return cloudagents.PlaceholderRoot(c.ID), nil
	}
	return p.RootPath, nil
}

// trackOpen keeps one session_history checkpoint per task that was live at
// its last observation, deletes it once the task is terminal, and abandons
// one that has not been seen for OpenSessionTTL.
func (s *Service) trackOpen(ctx context.Context, accountPK int64, open []store.CloudSyncCheckpoint, landed map[string]cloudagents.Task, now time.Time) error {
	ids := make([]string, 0, len(landed))
	for id := range landed {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		t := landed[id]
		if t.Lifecycle.Terminal() {
			if _, err := s.st.DeleteCloudSyncCheckpoint(ctx, accountPK, models.SyncStreamSessionHistory, id); err != nil {
				return err
			}
			continue
		}
		if err := s.st.SaveCloudSyncCheckpoint(ctx, store.CloudSyncCheckpoint{
			AccountPK: accountPK, Stream: models.SyncStreamSessionHistory, Scope: id,
			Cursor: string(t.Lifecycle), LastAttemptAt: now, LastSuccessAt: now,
		}); err != nil {
			return err
		}
	}
	for _, o := range open {
		if _, ok := landed[o.Scope]; ok {
			continue
		}
		if !o.LastSuccessAt.IsZero() && now.Sub(o.LastSuccessAt) > OpenSessionTTL {
			if _, err := s.st.DeleteCloudSyncCheckpoint(ctx, accountPK, models.SyncStreamSessionHistory, o.Scope); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkpointCounts splits session_history checkpoints into sessions still
// running (a running or unknown lifecycle), sessions waiting for the user
// (alive, but idle until someone answers: a Devin "running" session whose
// status_detail is waiting_for_user) and finished sessions kept only
// because a read is still owed. A finished session is never "still
// running", whatever it owes.
func checkpointCounts(cps []store.CloudSyncCheckpoint) (open, waiting, owed int) {
	for _, cp := range cps {
		switch l := cloudagents.CheckpointLifecycle(cp.Cursor); {
		case l.Terminal():
			owed++
		case l == cloudagents.LifecycleWaiting:
			waiting++
		default:
			open++
		}
	}
	return open, waiting, owed
}

func fromStoreCheckpoint(c store.CloudSyncCheckpoint) cloudagents.Checkpoint {
	cp := cloudagents.Checkpoint{
		HighWater:   cloudagents.DecodeHighWater(c.Cursor),
		Overlap:     time.Duration(c.OverlapSeconds) * time.Second,
		LastSuccess: c.LastSuccessAt,
	}
	for _, g := range c.Gaps {
		cp.Gaps = append(cp.Gaps, cloudagents.Gap{From: g.From, To: g.To})
	}
	return cp
}

func toStoreCheckpoint(accountPK int64, cp cloudagents.Checkpoint) store.CloudSyncCheckpoint {
	out := store.CloudSyncCheckpoint{
		AccountPK: accountPK, Stream: models.SyncStreamDiscovery,
		Cursor:         cloudagents.EncodeHighWater(cp.HighWater),
		OverlapSeconds: int64(cp.Overlap / time.Second),
		LastSuccessAt:  cp.LastSuccess,
		Gaps:           []store.CloudSyncGap{},
	}
	for _, g := range cp.Gaps {
		out.Gaps = append(out.Gaps, store.CloudSyncGap{From: g.From, To: g.To})
	}
	return out
}
