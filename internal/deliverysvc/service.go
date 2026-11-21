package deliverysvc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/delivery"
	"github.com/marmutapp/superbased-observer/internal/deliverynet"
	"github.com/marmutapp/superbased-observer/internal/keystore"
)

// KeystoreService is the OS keychain service every delivery token lives
// under (plan 7.3).
const KeystoreService = "sbo-delivery-v1"

// Defaults.
const (
	DefaultPollEvery     = 10 * time.Minute
	DefaultTick          = time.Minute
	DefaultCommitsPerRun = 25
	DefaultLookback      = 90 * 24 * time.Hour
	maxTokenBytes        = 4096
)

// Store is the narrow slice of internal/store this service needs. The names
// and signatures are the delivery store seam's (internal/store/delivery.go),
// so *store.Store satisfies it.
type Store interface {
	ListDeliveryRepos(ctx context.Context) ([]delivery.Remote, error)
	LoadProjectRemotes(ctx context.Context, projectID int64) ([]delivery.Remote, error)
	LoadDeliveryCommits(ctx context.Context, projectID int64, since time.Time) ([]delivery.Commit, error)
	LoadProjectLandings(ctx context.Context, projectID int64, since, until time.Time) ([]delivery.Landing, error)
	ListProviderLinks(ctx context.Context) ([]delivery.ProviderLink, error)
	CreateProviderLink(ctx context.Context, l delivery.ProviderLink) (int64, error)
	UpdateProviderLinkStatus(ctx context.Context, id int64, status, errKind, errMsg string, okAt, nextRun time.Time, failures int) error
	DeleteProviderLink(ctx context.Context, id int64) error
	UpsertPullRequest(ctx context.Context, pr delivery.PullRequest, commits []delivery.PRCommit) (int64, error)
	FindPullRequestsForSHA(ctx context.Context, sha string) ([]delivery.PullRequest, error)
	// ListCloudPRClaims / FindPullRequestByNumber feed the cloud-claim pass
	// (lane CA-C5): the PRs and branches cloud sessions claimed on a
	// repository, and whether a claimed PR is already stored.
	ListCloudPRClaims(ctx context.Context, remote string, since time.Time, limit int) ([]delivery.CloudPRClaim, error)
	FindPullRequestByNumber(ctx context.Context, host, slug string, number int64) (delivery.PullRequest, bool, error)
	UpsertDeliveryMirror(ctx context.Context, m delivery.Mirror) (int64, error)
	ListDeliveryMirrors(ctx context.Context) ([]delivery.Mirror, error)
	DeleteDeliveryMirror(ctx context.Context, id int64) error
	GetDeliveryProjectSettings(ctx context.Context, projectID int64) (delivery.ProjectSettings, error)
	ListDeliveryProjectSettings(ctx context.Context) ([]delivery.ProjectSettings, error)
}

// Net is the slice of *deliverynet.Client this service uses (a fake in
// tests).
type Net interface {
	User(ctx context.Context, auth deliverynet.Auth) (deliverynet.Account, error)
	CommitPulls(ctx context.Context, auth deliverynet.Auth, slug, sha string) ([]delivery.PullRequest, bool, error)
	PullRequest(ctx context.Context, auth deliverynet.Auth, slug string, number int64) (delivery.PullRequest, error)
	PullCommits(ctx context.Context, auth deliverynet.Auth, slug string, number int64) ([]delivery.PRCommit, error)
	PullsForHead(ctx context.Context, auth deliverynet.Auth, slug, branch string) ([]delivery.PullRequest, error)
	MirrorDir(rawURL string) (string, error)
	SanitizeRemoteURL(raw string) (string, error)
	Clone(ctx context.Context, rawURL, dir string) error
	LsRemote(ctx context.Context, rawURL, ref string) (string, error)
	Refresh(ctx context.Context, dir, defaultBranch string) error
	HeadBranch(ctx context.Context, dir string) (string, error)
	LocalTip(ctx context.Context, dir, branch string) (string, error)
	Size(dir string) (int64, error)
	RemoveMirror(dir string) error
}

// KeyStore is the slice of keystore.Store this service uses.
type KeyStore interface {
	Get(name string) (string, error)
	Set(name, value string) error
	Delete(name string) error
	Backend() string
}

// Options configure a Service.
type Options struct {
	Store Store
	Net   Net
	// OpenKeys opens the keychain store lazily (cmd/observer wires
	// keystore.Open(KeystoreService, ...)). It is called only when a token
	// link is connected, tested, polled or removed; nil means no keychain.
	OpenKeys func() KeyStore
	// Reevaluate re-runs the landing rule table for one project after new
	// provider or mirror evidence landed (internal/landingscan owns the
	// local evidence and the delivery.Evaluate call). Nil skips it.
	Reevaluate func(ctx context.Context, projectID int64) error
	// PollEvery is the provider cadence ([delivery].poll_minutes).
	PollEvery time.Duration
	// MirrorCapBytes is the total mirror disk cap ([delivery].mirror_cap_mb);
	// 0 means no cap.
	MirrorCapBytes int64
	// CommitsPerRun bounds the commits asked about per repository per pass.
	CommitsPerRun int
	// Lookback bounds how old an unlanded AI commit may be to be asked about.
	Lookback time.Duration
	// Tick is how often Run looks for due work.
	Tick time.Duration
	// Now overrides the clock (tests).
	Now func() time.Time
	// Logger receives one line per failed pass; never a secret.
	Logger *slog.Logger
}

// Service is the delivery poll loop.
type Service struct {
	o    Options
	mu   sync.Mutex // serialises Run passes and CheckProject
	kmu  sync.Mutex
	keys KeyStore
}

// New returns a Service with defaults filled in.
func New(o Options) *Service {
	if o.PollEvery <= 0 {
		o.PollEvery = DefaultPollEvery
	}
	if o.Tick <= 0 {
		o.Tick = DefaultTick
	}
	if o.CommitsPerRun <= 0 {
		o.CommitsPerRun = DefaultCommitsPerRun
	}
	if o.Lookback <= 0 {
		o.Lookback = DefaultLookback
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Service{o: o}
}

// Errors the service API returns besides deliverynet's typed errors.
var (
	// ErrNoKeychain: a token cannot be stored because no secure keychain
	// is available on this machine (keystore fail-closed semantics).
	ErrNoKeychain = errors.New("deliverysvc: no secure keychain is available to hold the token")
	// ErrUnsupported: the provider or auth mode has no connection in this
	// release.
	ErrUnsupported = errors.New("deliverysvc: unsupported provider or auth mode")
	// ErrInvalid: a request field failed validation.
	ErrInvalid = errors.New("deliverysvc: invalid request")
	// ErrNotFound: no link or mirror with that id.
	ErrNotFound = errors.New("deliverysvc: not found")
	// ErrOverCap: a new mirror would exceed the mirror disk cap.
	ErrOverCap = errors.New("deliverysvc: the mirror disk cap is reached")
)

// Result is what one CheckProject pass did, per remote.
type Result struct {
	ProjectID int64
	CheckedAt time.Time
	Repos     []RepoResult
	// Reevaluated is true when the landing evaluation ran after the pass.
	Reevaluated bool
}

// RepoResult is one remote's outcome in a pass.
type RepoResult struct {
	RemoteName string
	RepoSlug   string
	Source     delivery.EvidenceSource
	// Status: ok | unchanged | refreshed | cloned | skipped | over_cap or a
	// deliverynet.Kind string.
	Status         string
	Detail         string
	CommitsChecked int
	PRsUpserted    int
}

// ConnectRequest is one "connect a code host" request.
type ConnectRequest struct {
	Provider delivery.Provider
	Host     string
	AuthMode string
	// Token is the secret for AuthMode "token"; it goes straight to the
	// keychain and is never stored in the database or logged.
	Token string
}

// --- Run loop ------------------------------------------------------------

// Run polls due links and scheduled mirrors until ctx is done. It makes no
// call at all while nothing is connected or opted in.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(s.o.Tick)
	defer t.Stop()
	for {
		s.pass(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RunOnce performs one Run pass (tests and a manual trigger).
func (s *Service) RunOnce(ctx context.Context) { s.pass(ctx) }

func (s *Service) pass(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.o.Now()
	links, err := s.o.Store.ListProviderLinks(ctx)
	if err != nil {
		s.o.Logger.Warn("delivery: list links", "err", err)
		return
	}
	var repos []delivery.Remote
	touched := map[int64]bool{}
	for _, l := range links {
		if stoppedStatuses[l.Status] || l.NextRunAt.After(now) || ctx.Err() != nil {
			continue
		}
		if repos == nil {
			if repos, err = s.o.Store.ListDeliveryRepos(ctx); err != nil {
				s.o.Logger.Warn("delivery: list repos", "err", err)
				return
			}
		}
		out := s.syncLink(ctx, l, repos, touched)
		s.recordLink(ctx, l, out)
	}
	s.scheduledMirrors(ctx, now, touched)
	for pid := range touched {
		s.reevaluate(ctx, pid)
	}
}

// syncLink asks the code host about every repository of this link's host.
func (s *Service) syncLink(ctx context.Context, l delivery.ProviderLink, repos []delivery.Remote, touched map[int64]bool) Outcome {
	auth, err := s.authFor(l)
	if err != nil {
		return Outcome{Kind: deliverynet.KindOf(err)}
	}
	seen := map[string]bool{}
	var worst Outcome
	for _, r := range repos {
		if !delivery.LinkServes(l, r) {
			continue
		}
		rr, err := s.syncRepo(ctx, l, auth, r, seen)
		if rr.PRsUpserted > 0 || err == nil {
			touched[r.ProjectID] = true
		}
		if err != nil {
			worst = worse(worst, Outcome{Kind: deliverynet.KindOf(err), ResetAt: deliverynet.ResetOf(err)})
			if stopsLink(err) {
				break
			}
		}
	}
	return worst
}

// stopsLink reports whether an error ends the link's pass (every other
// repository would fail the same way).
func stopsLink(err error) bool {
	switch deliverynet.KindOf(err) {
	case deliverynet.KindAuthFailed, deliverynet.KindRateLimited, deliverynet.KindHostNotAllowed, deliverynet.KindUnavailable:
		return true
	}
	return false
}

// syncRepo asks about the repository's unlanded AI commits, most recent
// first, and upserts every PR that holds one. seen dedupes PRs and commits
// across projects that share a repository within one pass.
func (s *Service) syncRepo(ctx context.Context, l delivery.ProviderLink, auth deliverynet.Auth, r delivery.Remote, seen map[string]bool) (RepoResult, error) {
	rr := RepoResult{RemoteName: r.Name, RepoSlug: r.RepoSlug, Source: delivery.SourceProvider, Status: StatusOK}
	now := s.o.Now()
	since := now.Add(-s.o.Lookback)
	commits, err := s.o.Store.LoadDeliveryCommits(ctx, r.ProjectID, since)
	if err != nil {
		return rr, fmt.Errorf("deliverysvc.syncRepo: %w", err)
	}
	landings, err := s.o.Store.LoadProjectLandings(ctx, r.ProjectID, since, now)
	if err != nil {
		return rr, fmt.Errorf("deliverysvc.syncRepo: %w", err)
	}
	landed := map[int64]bool{}
	for _, ln := range landings {
		if ln.Status == delivery.StatusLanded {
			landed[ln.CommitID] = true
		}
	}
	todo := make([]delivery.Commit, 0, len(commits))
	for _, c := range commits {
		if c.IsMerge || c.ForeignAuthor || !c.AIContributor || landed[c.ID] || !deliverynet.ValidSHA(c.SHA) {
			continue
		}
		todo = append(todo, c)
	}
	sort.SliceStable(todo, func(i, j int) bool { return todo[i].CommittedAt.After(todo[j].CommittedAt) })
	if len(todo) > s.o.CommitsPerRun {
		todo = todo[:s.o.CommitsPerRun]
	}
	for _, c := range todo {
		key := strings.ToLower(r.Host) + "|" + r.RepoSlug + "|" + c.SHA
		if seen[key] {
			continue
		}
		seen[key] = true
		if terminalPR(ctx, s.o.Store, c.SHA) {
			continue
		}
		rr.CommitsChecked++
		prs, inRepo, err := s.o.Net.CommitPulls(ctx, auth, r.RepoSlug, c.SHA)
		if err != nil {
			return s.failRepo(rr, err)
		}
		if !inRepo {
			continue
		}
		for _, pr := range prs {
			prKey := strings.ToLower(r.Host) + "|" + r.RepoSlug + "|#" + fmt.Sprint(pr.Number)
			if seen[prKey] {
				continue
			}
			seen[prKey] = true
			if pr.State == delivery.PROpen || pr.State == delivery.PRDraft {
				if pr, err = s.o.Net.PullRequest(ctx, auth, r.RepoSlug, pr.Number); err != nil {
					return s.failRepo(rr, err)
				}
			}
			pc, err := s.o.Net.PullCommits(ctx, auth, r.RepoSlug, pr.Number)
			if err != nil {
				return s.failRepo(rr, err)
			}
			pr.LinkID = l.ID
			if _, err := s.o.Store.UpsertPullRequest(ctx, pr, pc); err != nil {
				return rr, fmt.Errorf("deliverysvc.syncRepo: %w", err)
			}
			rr.PRsUpserted++
		}
	}
	return s.syncCloudClaims(ctx, l, auth, r, since, seen, rr)
}

// syncCloudClaims fetches the PRs cloud sessions claimed on this repository
// (lane CA-C5): a claimed PR number is read directly, a branch-only claim
// (a Cursor run) through its head branch. A claimed PR already stored as
// merged or closed is final and is not asked about again, so a repository
// whose claimed PRs all ended makes no further call for them. The PR rows
// land through the same UpsertPullRequest as every other PR; credit itself
// is decided at read time by internal/projectroi.CreditCloud.
func (s *Service) syncCloudClaims(ctx context.Context, l delivery.ProviderLink, auth deliverynet.Auth, r delivery.Remote, since time.Time, seen map[string]bool, rr RepoResult) (RepoResult, error) {
	claims, err := s.o.Store.ListCloudPRClaims(ctx, r.Host+"/"+r.RepoSlug, since, s.o.CommitsPerRun)
	if err != nil {
		return rr, fmt.Errorf("deliverysvc.syncCloudClaims: %w", err)
	}
	repoKey := strings.ToLower(r.Host) + "|" + r.RepoSlug
	upsert := func(pr delivery.PullRequest) error {
		prKey := repoKey + "|#" + fmt.Sprint(pr.Number)
		if seen[prKey] {
			return nil
		}
		seen[prKey] = true
		pc, err := s.o.Net.PullCommits(ctx, auth, r.RepoSlug, pr.Number)
		if err != nil {
			return err
		}
		pr.LinkID = l.ID
		if _, err := s.o.Store.UpsertPullRequest(ctx, pr, pc); err != nil {
			return fmt.Errorf("deliverysvc.syncCloudClaims: %w", err)
		}
		rr.PRsUpserted++
		return nil
	}
	for _, c := range claims {
		switch {
		case c.PRNumber > 0:
			if seen[repoKey+"|#"+fmt.Sprint(c.PRNumber)] {
				continue
			}
			stored, ok, err := s.o.Store.FindPullRequestByNumber(ctx, r.Host, r.RepoSlug, c.PRNumber)
			if err != nil {
				return rr, fmt.Errorf("deliverysvc.syncCloudClaims: %w", err)
			}
			if ok && (stored.State == delivery.PRMerged || stored.State == delivery.PRClosedUnmerged) {
				continue
			}
			pr, err := s.o.Net.PullRequest(ctx, auth, r.RepoSlug, c.PRNumber)
			if err != nil {
				return s.failRepo(rr, err)
			}
			if err := upsert(pr); err != nil {
				return s.failRepo(rr, err)
			}
		case c.Branch != "" && deliverynet.ValidBranch(c.Branch):
			key := repoKey + "|branch:" + c.Branch
			if seen[key] {
				continue
			}
			seen[key] = true
			prs, err := s.o.Net.PullsForHead(ctx, auth, r.RepoSlug, c.Branch)
			if err != nil {
				return s.failRepo(rr, err)
			}
			for _, pr := range prs {
				if pr.State == delivery.PROpen || pr.State == delivery.PRDraft {
					if pr, err = s.o.Net.PullRequest(ctx, auth, r.RepoSlug, pr.Number); err != nil {
						return s.failRepo(rr, err)
					}
				}
				if err := upsert(pr); err != nil {
					return s.failRepo(rr, err)
				}
			}
		}
	}
	return rr, nil
}

func (s *Service) failRepo(rr RepoResult, err error) (RepoResult, error) {
	rr.Status = string(deliverynet.KindOf(err))
	rr.Detail = safeDetail(err)
	return rr, err
}

// terminalPR reports whether sha already sits in a stored MERGED PR: the
// commit's provider evidence can no longer change, so it is not asked
// about again.
func terminalPR(ctx context.Context, st Store, sha string) bool {
	prs, err := st.FindPullRequestsForSHA(ctx, sha)
	if err != nil {
		return false
	}
	for _, p := range prs {
		if p.State == delivery.PRMerged {
			return true
		}
	}
	return false
}

// recordLink folds a pass outcome into the link row.
func (s *Service) recordLink(ctx context.Context, l delivery.ProviderLink, out Outcome) {
	now := s.o.Now()
	next := NextRun(RunState{Status: l.Status, Failures: l.ConsecutiveFailures}, out, now, s.o.PollEvery)
	okAt := l.LastOKAt
	if out.Kind == "" {
		okAt = now
	}
	msg := ""
	if out.Kind != "" {
		msg = kindMessage(out.Kind)
	}
	if err := s.o.Store.UpdateProviderLinkStatus(ctx, l.ID, next.Status, string(out.Kind), msg, okAt, next.NextRun, next.Failures); err != nil {
		s.o.Logger.Warn("delivery: update link", "link", l.ID, "err", err)
	}
}

// kindMessage is the plain sentence shown for a link status.
func kindMessage(k deliverynet.Kind) string {
	switch k {
	case deliverynet.KindAuthFailed:
		return "The code host refused the credential. Reconnect to resume."
	case deliverynet.KindRateLimited:
		return "Rate limited by the code host; waiting for the reset."
	case deliverynet.KindRepoMoved:
		return "A repository moved. Update the remote URL in your clone."
	case deliverynet.KindWrongShape:
		return "The code host answered in an unexpected shape."
	case deliverynet.KindHostNotAllowed:
		return "This host is not on the allowed list."
	case deliverynet.KindUnavailable:
		return "The gh command is not available."
	}
	return "The code host could not be reached."
}

// safeDetail is an error's text when it is one of ours (never a secret).
func safeDetail(err error) string {
	var e *deliverynet.Error
	if errors.As(err, &e) {
		return e.Error()
	}
	return string(deliverynet.KindOf(err))
}

func (s *Service) reevaluate(ctx context.Context, projectID int64) bool {
	if s.o.Reevaluate == nil {
		return false
	}
	if err := s.o.Reevaluate(ctx, projectID); err != nil {
		s.o.Logger.Warn("delivery: reevaluate", "project", projectID, "err", err)
		return false
	}
	return true
}

// --- Check now -----------------------------------------------------------

// CheckProject runs one forced pass for one project: provider calls for
// GitHub remotes with a usable link, a mirror refresh for every other
// remote when the project opted into mirrors, then the landing evaluation.
func (s *Service) CheckProject(ctx context.Context, projectID int64) (Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res := Result{ProjectID: projectID, CheckedAt: s.o.Now()}
	remotes, err := s.o.Store.LoadProjectRemotes(ctx, projectID)
	if err != nil {
		return res, fmt.Errorf("deliverysvc.CheckProject: %w", err)
	}
	links, err := s.o.Store.ListProviderLinks(ctx)
	if err != nil {
		return res, fmt.Errorf("deliverysvc.CheckProject: %w", err)
	}
	settings, err := s.o.Store.GetDeliveryProjectSettings(ctx, projectID)
	if err != nil {
		return res, fmt.Errorf("deliverysvc.CheckProject: %w", err)
	}
	seen := map[string]bool{}
	for _, r := range remotes {
		if l, ok := usableLink(links, r); ok {
			auth, aerr := s.authFor(l)
			if aerr != nil {
				s.recordLink(ctx, l, Outcome{Kind: deliverynet.KindOf(aerr)})
				res.Repos = append(res.Repos, RepoResult{RemoteName: r.Name, RepoSlug: r.RepoSlug, Source: delivery.SourceProvider, Status: string(deliverynet.KindOf(aerr)), Detail: safeDetail(aerr)})
				continue
			}
			rr, rerr := s.syncRepo(ctx, l, auth, r, seen)
			out := Outcome{}
			if rerr != nil {
				out = Outcome{Kind: deliverynet.KindOf(rerr), ResetAt: deliverynet.ResetOf(rerr)}
			}
			s.recordLink(ctx, l, out)
			res.Repos = append(res.Repos, rr)
			continue
		}
		if !settings.MirrorEnabled {
			res.Repos = append(res.Repos, RepoResult{RemoteName: r.Name, RepoSlug: r.RepoSlug, Source: delivery.SourceUserRefs, Status: "skipped", Detail: "no code host connection and no mirror for this project"})
			continue
		}
		res.Repos = append(res.Repos, s.syncMirror(ctx, r))
	}
	res.Reevaluated = s.reevaluate(ctx, projectID)
	return res, nil
}

// usableLink returns the link that serves r and is not stopped.
func usableLink(links []delivery.ProviderLink, r delivery.Remote) (delivery.ProviderLink, bool) {
	for _, l := range links {
		if delivery.LinkServes(l, r) && !stoppedStatuses[l.Status] {
			return l, true
		}
	}
	return delivery.ProviderLink{}, false
}

// --- Links ---------------------------------------------------------------

// keyStore opens the keychain once, lazily.
func (s *Service) keyStore() (KeyStore, error) {
	s.kmu.Lock()
	defer s.kmu.Unlock()
	if s.keys == nil && s.o.OpenKeys != nil {
		s.keys = s.o.OpenKeys()
	}
	if s.keys == nil || s.keys.Backend() == "unavailable" {
		return nil, ErrNoKeychain
	}
	return s.keys, nil
}

// authFor builds the request auth for a link (reading a token link's secret
// from the keychain).
func (s *Service) authFor(l delivery.ProviderLink) (deliverynet.Auth, error) {
	a := deliverynet.Auth{Mode: l.AuthMode, Host: l.Host}
	switch l.AuthMode {
	case deliverynet.AuthGHCLI:
		return a, nil
	case deliverynet.AuthToken:
		ks, err := s.keyStore()
		if err != nil {
			return a, &deliverynet.Error{Kind: deliverynet.KindAuthFailed, Msg: "no keychain"}
		}
		tok, err := ks.Get(l.KeyName)
		if err != nil || strings.TrimSpace(tok) == "" {
			return a, &deliverynet.Error{Kind: deliverynet.KindAuthFailed, Msg: "token missing from the keychain"}
		}
		a.Token = tok
		return a, nil
	}
	return a, &deliverynet.Error{Kind: deliverynet.KindHostNotAllowed, Msg: "unknown auth mode"}
}

// normaliseHost lowercases a web host and refuses anything that is not a
// bare host name.
func normaliseHost(h string) (string, bool) {
	h = strings.ToLower(strings.TrimSpace(h))
	if h == "" {
		h = deliverynet.GitHubDotCom
	}
	if len(h) > 253 {
		return "", false
	}
	for _, c := range h {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
			return "", false
		}
	}
	return h, true
}

// validToken refuses an empty, oversized or multi-line token.
func validToken(t string) bool {
	if t == "" || len(t) > maxTokenBytes {
		return false
	}
	for _, c := range t {
		if c <= ' ' || c == 0x7f {
			return false
		}
	}
	return true
}

func randomName() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "link." + hex.EncodeToString(b[:]) + ".token", nil
}

// Connect validates a connection request, proves the credential with
// GET /user BEFORE anything is stored, puts a token into the keychain
// (failing closed when there is no secure keychain), and creates the link.
func (s *Service) Connect(ctx context.Context, req ConnectRequest) (delivery.ProviderLink, error) {
	if req.Provider != delivery.ProviderGitHub {
		return delivery.ProviderLink{}, ErrUnsupported
	}
	host, ok := normaliseHost(req.Host)
	if !ok {
		return delivery.ProviderLink{}, fmt.Errorf("%w: host", ErrInvalid)
	}
	auth := deliverynet.Auth{Mode: req.AuthMode, Host: host}
	var ks KeyStore
	switch req.AuthMode {
	case deliverynet.AuthToken:
		tok := strings.TrimSpace(req.Token)
		if !validToken(tok) {
			return delivery.ProviderLink{}, fmt.Errorf("%w: token", ErrInvalid)
		}
		k, err := s.keyStore()
		if err != nil {
			return delivery.ProviderLink{}, err
		}
		ks, auth.Token = k, tok
	case deliverynet.AuthGHCLI:
		if req.Token != "" {
			return delivery.ProviderLink{}, fmt.Errorf("%w: gh mode takes no token", ErrInvalid)
		}
	default:
		return delivery.ProviderLink{}, ErrUnsupported
	}
	acct, err := s.o.Net.User(ctx, auth)
	if err != nil {
		return delivery.ProviderLink{}, err
	}
	now := s.o.Now()
	l := delivery.ProviderLink{
		Provider: delivery.ProviderGitHub, Host: host, AuthMode: req.AuthMode,
		AccountLogin: acct.Login, ScopesSeen: acct.Scopes, Status: StatusOK,
		LastOKAt: now, NextRunAt: now, CreatedAt: now,
	}
	if ks != nil {
		name, err := randomName()
		if err != nil {
			return delivery.ProviderLink{}, fmt.Errorf("deliverysvc.Connect: %w", err)
		}
		if err := ks.Set(name, auth.Token); err != nil {
			if errors.Is(err, keystore.ErrInsecureFallbackUnavailable) {
				return delivery.ProviderLink{}, ErrNoKeychain
			}
			return delivery.ProviderLink{}, fmt.Errorf("deliverysvc.Connect: keychain: %w", err)
		}
		l.KeyName = name
	}
	id, err := s.o.Store.CreateProviderLink(ctx, l)
	if err != nil {
		if ks != nil {
			_ = ks.Delete(l.KeyName)
		}
		return delivery.ProviderLink{}, fmt.Errorf("deliverysvc.Connect: %w", err)
	}
	l.ID = id
	return l, nil
}

func (s *Service) findLink(ctx context.Context, id int64) (delivery.ProviderLink, error) {
	links, err := s.o.Store.ListProviderLinks(ctx)
	if err != nil {
		return delivery.ProviderLink{}, fmt.Errorf("deliverysvc.findLink: %w", err)
	}
	for _, l := range links {
		if l.ID == id {
			return l, nil
		}
	}
	return delivery.ProviderLink{}, ErrNotFound
}

// TestLink calls GET /user for a link, records the outcome (an ok test
// restarts a stopped link) and returns the updated link.
func (s *Service) TestLink(ctx context.Context, linkID int64) (delivery.ProviderLink, error) {
	l, err := s.findLink(ctx, linkID)
	if err != nil {
		return l, err
	}
	auth, err := s.authFor(l)
	if err == nil {
		_, err = s.o.Net.User(ctx, auth)
	}
	out := Outcome{Kind: deliverynet.KindOf(err), ResetAt: deliverynet.ResetOf(err)}
	if out.Kind != "" {
		s.recordLink(ctx, l, out)
		return s.findLink(ctx, linkID)
	}
	// A successful test restarts the link and makes it due now.
	now := s.o.Now()
	if err := s.o.Store.UpdateProviderLinkStatus(ctx, l.ID, StatusOK, "", "", now, now, 0); err != nil {
		return l, fmt.Errorf("deliverysvc.TestLink: %w", err)
	}
	return s.findLink(ctx, linkID)
}

// Disconnect deletes a link's keychain entry, then the link (and its PRs,
// through the store).
func (s *Service) Disconnect(ctx context.Context, linkID int64) error {
	l, err := s.findLink(ctx, linkID)
	if err != nil {
		return err
	}
	if l.AuthMode == deliverynet.AuthToken && l.KeyName != "" {
		ks, kerr := s.keyStore()
		if kerr == nil {
			if derr := ks.Delete(l.KeyName); derr != nil && !errors.Is(derr, keystore.ErrNotFound) {
				return fmt.Errorf("deliverysvc.Disconnect: keychain: %w", derr)
			}
		}
	}
	if err := s.o.Store.DeleteProviderLink(ctx, linkID); err != nil {
		return fmt.Errorf("deliverysvc.Disconnect: %w", err)
	}
	return nil
}
