package planlimitssvc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/keystore"
	"github.com/marmutapp/superbased-observer/internal/planlimits"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// KeystoreService is the keychain service name the module's secrets live
// under, distinct from every other Observer credential.
const KeystoreService = "sbo-plans-v1"

// PassiveLookback bounds how far back passive readings are read.
const PassiveLookback = 8 * 24 * time.Hour

// HistoryRetention is how long snapshot and run history is kept (the newest
// snapshot of every account is always kept).
const HistoryRetention = 90 * 24 * time.Hour

// Store is the store seam the service uses (implemented by *store.Store).
type Store interface {
	PlanAccounts(ctx context.Context) ([]store.PlanAccountRow, error)
	PlanAccount(ctx context.Context, id string) (store.PlanAccountRow, error)
	InsertPlanAccount(ctx context.Context, a store.PlanAccountRow) error
	UpdatePlanAccount(ctx context.Context, a store.PlanAccountRow) error
	UpdatePlanAccountState(ctx context.Context, id string, st planlimits.RunState, ranAt time.Time) error
	DeletePlanAccount(ctx context.Context, id string) error
	InsertPlanSnapshot(ctx context.Context, accountID, sessionID string, snap planlimits.Snapshot) error
	LatestPlanSnapshots(ctx context.Context) (map[string]planlimits.Snapshot, error)
	PlanSnapshotHistory(ctx context.Context, accountID string, since time.Time, limit int) ([]planlimits.Snapshot, error)
	InsertPlanRun(ctx context.Context, r store.PlanRunRow) error
	RecentPlanRuns(ctx context.Context, accountID string, limit int) ([]store.PlanRunRow, error)
	PlanOptIns(ctx context.Context) (map[string]bool, error)
	SetPlanOptIn(ctx context.Context, provider string, on bool) error
	PrunePlanHistory(ctx context.Context, before time.Time) (int64, error)
	LoadPlanPassiveSignals(ctx context.Context, since time.Time) (store.PlanPassiveSignals, error)
	ObservedToolSpendSince(ctx context.Context, tools []string, since time.Time) (float64, error)
}

// Egress performs network calls and vendor processes (internal/planlimitsnet).
type Egress interface {
	Do(ctx context.Context, src planlimits.SourceDef, reqs []planlimits.Request) map[string]planlimits.Response
	Converse(ctx context.Context, src planlimits.SourceDef, d planlimits.Driver, in planlimits.PlanInput) (planlimits.Snapshot, error)
}

// LocalReader reads a vendor app's own local files (internal/planlimitslocal).
type LocalReader interface {
	Read(ctx context.Context, specs []planlimits.LocalSpec) (map[string][]byte, error)
}

// Options wire a Service.
type Options struct {
	Store  Store
	Keys   keystore.Store
	Net    Egress
	Local  LocalReader
	Logger *slog.Logger
	Now    func() time.Time
}

// Service is the Plans & limits service. Safe for concurrent use.
type Service struct {
	st     Store
	keys   keystore.Store
	net    Egress
	local  LocalReader
	log    *slog.Logger
	now    func() time.Time
	scrub  *scrub.Scrubber
	runMu  sync.Mutex // one refresh batch at a time
	heldMu sync.Mutex
	held   map[string]planlimits.Snapshot // suspicious readings awaiting confirmation
	seen   atomic.Int64                   // unix time the page was last open
	slMu   sync.Mutex
	slLast map[string]string // session id -> last status line body stored
}

// New returns a Service.
func New(o Options) *Service {
	s := &Service{
		st: o.Store, keys: o.Keys, net: o.Net, local: o.Local, log: o.Logger, now: o.Now,
		scrub: scrub.New(), held: map[string]planlimits.Snapshot{}, slLast: map[string]string{},
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
	ErrInvalid       = errors.New("planlimits: invalid request")
	ErrNeedsOptIn    = errors.New("planlimits: turn on the experimental switch for this provider first")
	ErrNotFound      = store.ErrPlanAccountNotFound
	ErrKeychainFails = errors.New("planlimits: the system keychain is not available")
)

// MarkPageOpen records that the Plans & limits page is open, which shortens
// the poll cadence for a few minutes.
func (s *Service) MarkPageOpen() { s.seen.Store(s.now().Unix()) }

func (s *Service) pageOpen() bool {
	return s.now().Unix()-s.seen.Load() < int64((5 * time.Minute).Seconds())
}

// --- The page model -------------------------------------------------------------

// View is the Plans & limits page model.
type View struct {
	GeneratedAt time.Time                `json:"generated_at"`
	Cards       []planlimits.Card        `json:"cards"`
	Accounts    []planlimits.AccountInfo `json:"accounts"`
	OptIns      []string                 `json:"opt_ins"`
	Keychain    string                   `json:"keychain"` // the active credential backend
}

// accountInfo projects a stored account.
func accountInfo(a store.PlanAccountRow) planlimits.AccountInfo {
	params := map[string]string{}
	for k, v := range a.Params {
		if !strings.HasPrefix(k, "_") {
			params[k] = v
		}
	}
	return planlimits.AccountInfo{
		ID: a.ID, Provider: a.Provider, Source: a.Source, Label: a.Label, Params: params,
		Secrets: append([]string(nil), a.SecretKeys...), Enabled: a.Enabled, State: a.State, CreatedAt: a.CreatedAt,
	}
}

// Status builds the page model.
func (s *Service) Status(ctx context.Context) (View, error) {
	now := s.now().UTC()
	in, rows, err := s.viewInput(ctx, now)
	if err != nil {
		return View{}, err
	}
	v := View{GeneratedAt: now, Cards: planlimits.BuildView(in), OptIns: []string{}}
	for _, a := range rows {
		v.Accounts = append(v.Accounts, accountInfo(a))
	}
	for p, on := range in.OptIns {
		if on {
			v.OptIns = append(v.OptIns, p)
		}
	}
	sort.Strings(v.OptIns)
	if s.keys != nil {
		v.Keychain = s.keys.Backend()
	}
	if v.Cards == nil {
		v.Cards = []planlimits.Card{}
	}
	if v.Accounts == nil {
		v.Accounts = []planlimits.AccountInfo{}
	}
	return v, nil
}

func (s *Service) viewInput(ctx context.Context, now time.Time) (planlimits.ViewInput, []store.PlanAccountRow, error) {
	rows, err := s.st.PlanAccounts(ctx)
	if err != nil {
		return planlimits.ViewInput{}, nil, err
	}
	latest, err := s.st.LatestPlanSnapshots(ctx)
	if err != nil {
		return planlimits.ViewInput{}, nil, err
	}
	sig, err := s.st.LoadPlanPassiveSignals(ctx, now.Add(-PassiveLookback))
	if err != nil {
		return planlimits.ViewInput{}, nil, err
	}
	opt, err := s.st.PlanOptIns(ctx)
	if err != nil {
		return planlimits.ViewInput{}, nil, err
	}
	in := planlimits.ViewInput{
		Now: now, Latest: latest, OptIns: opt,
		Passive: planlimits.BindPassive(sig.Limits, sig.Logs, sig.StatusLine, sig.Accounts),
	}
	for _, a := range rows {
		in.Accounts = append(in.Accounts, accountInfo(a))
	}
	return in, rows, nil
}

// officialFreshAt returns the newest rung-1 reading of a provider across the
// passive signals and the other accounts' latest snapshots.
func officialFreshAt(provider string, in planlimits.ViewInput) time.Time {
	var t time.Time
	consider := func(s planlimits.Snapshot) {
		if s.Provider == provider && s.Rung == planlimits.RungOfficial && s.Kind != planlimits.KindManual && s.ObservedAt.After(t) {
			t = s.ObservedAt
		}
	}
	for _, p := range in.Passive {
		consider(p.Snapshot)
	}
	for _, s := range in.Latest {
		consider(s)
	}
	return t
}

// --- Accounts -----------------------------------------------------------------

// AddRequest is one new account. Secrets go to the keychain only.
type AddRequest struct {
	Provider string            `json:"provider"`
	Source   string            `json:"source"`
	Label    string            `json:"label"`
	Params   map[string]string `json:"params"`
	Secrets  map[string]string `json:"secrets"`
}

func newID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(b)
}

// secretName is the keychain item name of one account secret.
func secretName(accountID, key string) string { return "account." + accountID + "." + key }

const (
	maxLabel = 64
	maxParam = 256
)

// validate checks params and secrets against the source row. Params outside
// the row are refused, so the account never carries a field nothing reads.
func validate(src planlimits.SourceDef, params, secrets map[string]string, requireSecrets bool) error {
	known := map[string]planlimits.ParamSpec{}
	for _, p := range src.Params {
		known[p.Key] = p
	}
	for k, v := range params {
		spec, ok := known[k]
		if !ok {
			return fmt.Errorf("%w: unknown setting %q", ErrInvalid, k)
		}
		if len(v) > maxParam || strings.ContainsAny(v, "\r\n\x00") {
			return fmt.Errorf("%w: %s is too long or has control characters", ErrInvalid, k)
		}
		if v == "" {
			continue
		}
		if spec.Numeric {
			f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
			if err != nil || f < 0 {
				return fmt.Errorf("%w: %s must be a number", ErrInvalid, k)
			}
		}
		if len(spec.Choices) > 0 && !contains(spec.Choices, v) {
			return fmt.Errorf("%w: %s must be one of %s", ErrInvalid, k, strings.Join(spec.Choices, ", "))
		}
	}
	for _, p := range src.Params {
		if p.Required && strings.TrimSpace(params[p.Key]) == "" {
			return fmt.Errorf("%w: %s is required", ErrInvalid, p.Key)
		}
	}
	// A self-hosted gateway's base URL is checked by the same policy the
	// egress package applies to every request (ledger SUBS-5), so an account
	// that could never be polled is never saved.
	if src.UserBaseURL {
		if _, err := planlimits.CheckBaseURL(params[planlimits.ParamBaseURL]); err != nil {
			return fmt.Errorf("%w: %s", ErrInvalid, err.Error())
		}
	}
	allowed := map[string]bool{}
	for _, sp := range src.Secrets {
		allowed[sp.Key] = true
		if requireSecrets && sp.Required && strings.TrimSpace(secrets[sp.Key]) == "" {
			return fmt.Errorf("%w: %s is required", ErrInvalid, sp.Key)
		}
	}
	for k, v := range secrets {
		if !allowed[k] {
			return fmt.Errorf("%w: unknown secret %q", ErrInvalid, k)
		}
		if len(v) > 4096 || strings.ContainsAny(v, "\r\n\x00") {
			return fmt.Errorf("%w: %s is not a valid key", ErrInvalid, k)
		}
	}
	return nil
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// AddAccount validates and stores a new account; secrets go to the keychain.
// An experimental source needs the provider's switch on first.
func (s *Service) AddAccount(ctx context.Context, req AddRequest) (planlimits.AccountInfo, error) {
	req.Label = planlimits.SanitizeLabel(req.Label)
	if len(req.Label) > maxLabel {
		req.Label = req.Label[:maxLabel]
	}
	if !planlimits.AccountSourceAllowed(req.Provider, req.Source) {
		return planlimits.AccountInfo{}, fmt.Errorf("%w: this provider cannot use that source", ErrInvalid)
	}
	src, _ := planlimits.SourceByID(req.Source)
	if req.Params == nil {
		req.Params = map[string]string{}
	}
	if err := validate(src, req.Params, req.Secrets, true); err != nil {
		return planlimits.AccountInfo{}, err
	}
	if src.Experimental() {
		opt, err := s.st.PlanOptIns(ctx)
		if err != nil {
			return planlimits.AccountInfo{}, err
		}
		if !opt[req.Provider] {
			return planlimits.AccountInfo{}, ErrNeedsOptIn
		}
	}
	id := newID()
	var stored []string
	for _, sp := range src.Secrets {
		v := strings.TrimSpace(req.Secrets[sp.Key])
		if v == "" {
			continue
		}
		if s.keys == nil {
			return planlimits.AccountInfo{}, ErrKeychainFails
		}
		if err := s.keys.Set(secretName(id, sp.Key), v); err != nil {
			s.dropSecrets(id, stored)
			return planlimits.AccountInfo{}, fmt.Errorf("%w: %s", ErrKeychainFails, err.Error())
		}
		stored = append(stored, sp.Key)
	}
	row := store.PlanAccountRow{
		ID: id, Provider: req.Provider, Source: req.Source, Label: req.Label,
		Params: req.Params, SecretKeys: stored, Enabled: true,
	}
	if err := s.st.InsertPlanAccount(ctx, row); err != nil {
		s.dropSecrets(id, stored)
		return planlimits.AccountInfo{}, err
	}
	row.CreatedAt = s.now().UTC()
	return accountInfo(row), nil
}

// UpdateRequest changes an account. A nil field is left alone; a secret set
// to "" is removed.
type UpdateRequest struct {
	Label   *string           `json:"label,omitempty"`
	Params  map[string]string `json:"params,omitempty"`
	Secrets map[string]string `json:"secrets,omitempty"`
	Enabled *bool             `json:"enabled,omitempty"`
}

// UpdateAccount edits an account and clears a paused poll.
func (s *Service) UpdateAccount(ctx context.Context, id string, req UpdateRequest) (planlimits.AccountInfo, error) {
	a, err := s.st.PlanAccount(ctx, id)
	if err != nil {
		return planlimits.AccountInfo{}, err
	}
	src, ok := planlimits.SourceByID(a.Source)
	if !ok {
		return planlimits.AccountInfo{}, fmt.Errorf("%w: unknown source", ErrInvalid)
	}
	params := map[string]string{}
	for k, v := range a.Params {
		params[k] = v
	}
	for k, v := range req.Params {
		params[k] = v
	}
	if err := validate(src, params, req.Secrets, false); err != nil {
		return planlimits.AccountInfo{}, err
	}
	have := map[string]bool{}
	for _, k := range a.SecretKeys {
		have[k] = true
	}
	for k, v := range req.Secrets {
		v = strings.TrimSpace(v)
		if s.keys == nil {
			return planlimits.AccountInfo{}, ErrKeychainFails
		}
		if v == "" {
			if err := s.keys.Delete(secretName(id, k)); err != nil {
				return planlimits.AccountInfo{}, fmt.Errorf("%w: %s", ErrKeychainFails, err.Error())
			}
			delete(have, k)
			continue
		}
		if err := s.keys.Set(secretName(id, k), v); err != nil {
			return planlimits.AccountInfo{}, fmt.Errorf("%w: %s", ErrKeychainFails, err.Error())
		}
		have[k] = true
	}
	a.SecretKeys = a.SecretKeys[:0]
	for _, sp := range src.Secrets {
		if have[sp.Key] {
			a.SecretKeys = append(a.SecretKeys, sp.Key)
		}
	}
	a.Params = params
	if req.Label != nil {
		a.Label = planlimits.SanitizeLabel(*req.Label)
	}
	if req.Enabled != nil {
		a.Enabled = *req.Enabled
	}
	if err := s.st.UpdatePlanAccount(ctx, a); err != nil {
		return planlimits.AccountInfo{}, err
	}
	a.State = planlimits.RunState{}
	return accountInfo(a), nil
}

// RemoveAccount deletes the account's keychain secrets, then its rows.
func (s *Service) RemoveAccount(ctx context.Context, id string) error {
	a, err := s.st.PlanAccount(ctx, id)
	if err != nil {
		return err
	}
	if s.keys != nil {
		for _, k := range a.SecretKeys {
			if err := s.keys.Delete(secretName(id, k)); err != nil {
				return fmt.Errorf("%w: %s", ErrKeychainFails, err.Error())
			}
		}
	}
	s.heldMu.Lock()
	delete(s.held, id)
	s.heldMu.Unlock()
	return s.st.DeletePlanAccount(ctx, id)
}

func (s *Service) dropSecrets(id string, keys []string) {
	for _, k := range keys {
		_ = s.keys.Delete(secretName(id, k))
	}
}

// HasExperimental reports whether a provider has any experimental source.
func HasExperimental(provider string) bool {
	for _, src := range planlimits.SourcesFor(provider) {
		if src.Provider == provider && src.Experimental() {
			return true
		}
	}
	return false
}

// SetOptIn turns a provider's experimental switch on or off. Turning it off
// stops its experimental accounts on the next tick (the ladder refuses them).
func (s *Service) SetOptIn(ctx context.Context, provider string, on bool) error {
	if !HasExperimental(provider) {
		return fmt.Errorf("%w: this provider has no experimental source", ErrInvalid)
	}
	return s.st.SetPlanOptIn(ctx, provider, on)
}

// History returns an account's recent snapshots and runs.
func (s *Service) History(ctx context.Context, id string, days int) ([]planlimits.Snapshot, []store.PlanRunRow, error) {
	if _, err := s.st.PlanAccount(ctx, id); err != nil {
		return nil, nil, err
	}
	if days <= 0 || days > 90 {
		days = 7
	}
	snaps, err := s.st.PlanSnapshotHistory(ctx, id, s.now().Add(-time.Duration(days)*24*time.Hour), 500)
	if err != nil {
		return nil, nil, err
	}
	runs, err := s.st.RecentPlanRuns(ctx, id, 20)
	return snaps, runs, err
}

// --- Status line ingest ---------------------------------------------------------

// IngestStatusLine stores one forwarded status line reading (numbers only)
// into the module's own table, never into limit_snapshots. An unchanged
// reading for the same session is dropped.
func (s *Service) IngestStatusLine(ctx context.Context, f planlimits.StatusLineForward) error {
	if f.ObservedAt <= 0 {
		f.ObservedAt = s.now().Unix()
	}
	if t := time.Unix(f.ObservedAt, 0); t.After(s.now().Add(time.Minute)) {
		f.ObservedAt = s.now().Unix() // never trust a future clock
	}
	snap, err := planlimits.FromStatusLine(f)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInvalid, err.Error())
	}
	if err := planlimits.Validate(snap); err != nil {
		return fmt.Errorf("%w: %s", ErrInvalid, err.Error())
	}
	key := snapKey(snap)
	s.slMu.Lock()
	if s.slLast[f.SessionID] == key {
		s.slMu.Unlock()
		return nil
	}
	if len(s.slLast) > 4096 {
		s.slLast = map[string]string{}
	}
	s.slLast[f.SessionID] = key
	s.slMu.Unlock()
	return s.st.InsertPlanSnapshot(ctx, "", f.SessionID, snap)
}

// snapKey is a change key over a snapshot's numbers.
func snapKey(s planlimits.Snapshot) string {
	var b strings.Builder
	for _, w := range s.Windows {
		fmt.Fprintf(&b, "%s|", w.Key)
		if w.UsedFrac != nil {
			fmt.Fprintf(&b, "%.4f", *w.UsedFrac)
		}
		if w.ResetsAt != nil {
			fmt.Fprintf(&b, "|%d", w.ResetsAt.Unix())
		}
		if w.Used != nil {
			fmt.Fprintf(&b, "|%.0f", *w.Used)
		}
		b.WriteString(";")
	}
	return b.String()
}
