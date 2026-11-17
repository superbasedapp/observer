package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/entitlementwork"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/hostapi"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/hostapi/hostclient"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/signerd"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	"github.com/marmutapp/superbased-observer/internal/entitlements"
	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// This file wires the host-API client (managed-SaaS plan 07 M6.4) and the
// worker side of signed entitlements (M6.3) into `worker`. Both are OFF
// unless SBCI_HOSTAPI_HOSTS_FILE is set; unset (and with no other
// SBCI_HOSTAPI_* variable), the worker starts no extra loop, reads no extra
// file and logs nothing extra, exactly as before.
//
// Environment (worker):
//
//	SBCI_HOSTAPI_HOSTS_FILE        the switch: the tenant hosts file, JSON
//	                               (hostclient.HostsFile: the hosts, their
//	                               private https origins, their pinned
//	                               response keys and the placement host)
//	SBCI_HOSTAPI_CA_FILE           the platform CA (PEM); the ONLY root the
//	                               client trusts for a host
//	SBCI_HOSTAPI_CLIENT_CERT_FILE  the control plane's client certificate (PEM)
//	SBCI_HOSTAPI_CLIENT_KEY_FILE   its private key (PEM)
//	SBCI_DOC_SIGNER_SOCKET         the document signer's unix socket (default
//	                               /run/observer-cloud-docsigner/signer.sock,
//	                               the same variable the signer reads)
//
// The three TLS files are required once the switch is set, and any of them
// set without the switch refuses to start (a half-configured client is a
// mistake, never a quiet off). A document signer that is down at start does
// not stop the worker: the host-API loops wait for its keys and retry every
// minute, while the inference loops run as before.
//
// What runs once it is on (each loop stops with the worker):
//   - the entitlements issuer (entitlementwork): every minute, each org whose
//     stored document does not carry its plan gets a new one, composed from
//     the catalog, signed by the document signer, verified against the
//     signer's published keys, stored with its set_entitlements intent;
//   - the outbox dispatcher (every 5 s) and the reconciler (hourly), signing
//     each request through the document signer's host-API key and verifying
//     each answer against the host's pinned response key; each reconcile
//     pass also pulls every placed host's signed daily usage report into
//     org_usage_days (M6.0 Q11).
//
// Each org's plan (entitlementwork.SubscriptionPlans, W14-D3 / W14-D1a): its
// live org-scoped Paddle subscription when the store can read one
// (orgPlanReaderFor), else its launch plan for the launch window after its
// tenant was created, else the floor of its kind. A past_due subscription
// counts for SBCI_PADDLE_PAST_DUE_GRACE_DAYS (default 14) days from when it
// entered past_due (W16-D5); a waitlisted create is sent again no sooner
// than SBCI_WAITLIST_RETRY_FLOOR (default 15m). Right after a create is
// acked the dispatcher has the issuer issue the org's launch document, so a
// new team org is never left on its lapsed floor (QUOTA-1).
//
// A create_tenant request carries the owner's WorkOS subject (the host binds
// by it) and address as a display hint marked unverified, both through the
// cloud 0093 lookups that answer for one org still being created
// (entitlementwork.StoreOwners, W14-D2), and the org's slug and kind (0092).
// A missing subject or address keeps the create in the outbox with a typed
// error class ("not_sent:resolve:<reason>").

// Host-API worker environment variables.
const (
	envHostAPIHostsFile  = "SBCI_HOSTAPI_HOSTS_FILE"
	envHostAPICAFile     = "SBCI_HOSTAPI_CA_FILE"
	envHostAPICertFile   = "SBCI_HOSTAPI_CLIENT_CERT_FILE"
	envHostAPIKeyFile    = "SBCI_HOSTAPI_CLIENT_KEY_FILE" //nolint:gosec // G101: an env var NAME, not a credential
	envDocSignerSocket   = "SBCI_DOC_SIGNER_SOCKET"
	maxHostAPIConfigFile = 1 << 20
	// envPastDueGraceDays is how many days a past_due org subscription
	// still carries its plan after it entered past_due (W16-D5, L-124;
	// default entitlementwork.DefaultPastDueGrace, 14 days).
	envPastDueGraceDays = "SBCI_PADDLE_PAST_DUE_GRACE_DAYS"
	// envWaitlistRetryFloor is the least delay before a waitlisted create
	// is sent again, a Go duration (W16-D5, C2.tenant-cloud-5; default
	// hostapi.WaitlistMinDelay, 15m).
	envWaitlistRetryFloor = "SBCI_WAITLIST_RETRY_FLOOR"
	// maxPastDueGraceDays bounds the dunning window a deploy may configure.
	maxPastDueGraceDays = 90
)

// Host-API worker cadences.
const (
	// entitlementIssueEvery is the issuer's pass interval (plus once at
	// start).
	entitlementIssueEvery = time.Minute
	// hostAPISignerRetryEvery is how often the worker retries reading the
	// document signer's keys when the signer is unreachable at start.
	hostAPISignerRetryEvery = time.Minute
)

// hostAPIWorkerConfig is the resolved host-API worker configuration.
type hostAPIWorkerConfig struct {
	hostsFile, caFile, certFile, keyFile string
	signerSocket                         string
	// pastDueGrace is the dunning window (0: the default).
	pastDueGrace time.Duration
	// waitlistFloor is the waitlist retry floor (0: the default).
	waitlistFloor time.Duration
}

// resolveBillingTimings reads the two W16-D5 timings: the past_due grace in
// whole days (1 to maxPastDueGraceDays) and the waitlist retry floor (a Go
// duration within hostapi.CheckWaitlistFloor's range). Unset is the default
// (zero here).
func resolveBillingTimings(get func(string) string) (grace, floor time.Duration, err error) {
	if v := get(envPastDueGraceDays); v != "" {
		days, perr := strconv.Atoi(v)
		if perr != nil || days < 1 || days > maxPastDueGraceDays {
			return 0, 0, fmt.Errorf("observer-cloud: %s=%q must be a whole number of days from 1 to %d", envPastDueGraceDays, v, maxPastDueGraceDays)
		}
		grace = time.Duration(days) * 24 * time.Hour
	}
	if v := get(envWaitlistRetryFloor); v != "" {
		d, perr := time.ParseDuration(v)
		if perr != nil {
			return 0, 0, fmt.Errorf("observer-cloud: %s=%q is not a duration (e.g. 15m): %w", envWaitlistRetryFloor, v, perr)
		}
		if cerr := hostapi.CheckWaitlistFloor(d); cerr != nil {
			return 0, 0, fmt.Errorf("observer-cloud: %s: %w", envWaitlistRetryFloor, cerr)
		}
		floor = d
	}
	return grace, floor, nil
}

// resolveHostAPIWorkerConfig reads the environment. enabled is false (and
// the configuration empty) when no SBCI_HOSTAPI_* variable is set.
func resolveHostAPIWorkerConfig(getenv func(string) string) (cfg hostAPIWorkerConfig, enabled bool, err error) {
	get := func(name string) string { return strings.TrimSpace(getenv(name)) }
	cfg = hostAPIWorkerConfig{
		hostsFile: get(envHostAPIHostsFile), caFile: get(envHostAPICAFile),
		certFile: get(envHostAPICertFile), keyFile: get(envHostAPIKeyFile),
		signerSocket: get(envDocSignerSocket),
	}
	if cfg.hostsFile == "" {
		for _, name := range []string{envHostAPICAFile, envHostAPICertFile, envHostAPIKeyFile} {
			if get(name) != "" {
				return hostAPIWorkerConfig{}, false, fmt.Errorf("observer-cloud: %s is set but %s is not; set both to run the host-API client, or neither", name, envHostAPIHostsFile)
			}
		}
		return hostAPIWorkerConfig{}, false, nil
	}
	for _, req := range []struct{ name, v string }{
		{envHostAPICAFile, cfg.caFile}, {envHostAPICertFile, cfg.certFile}, {envHostAPIKeyFile, cfg.keyFile},
	} {
		if req.v == "" {
			return hostAPIWorkerConfig{}, false, fmt.Errorf("observer-cloud: %s is required when %s is set (the host API runs over mTLS only)", req.name, envHostAPIHostsFile)
		}
	}
	if cfg.signerSocket == "" {
		cfg.signerSocket = defaultDocSignerSocket
	}
	if cfg.pastDueGrace, cfg.waitlistFloor, err = resolveBillingTimings(get); err != nil {
		return hostAPIWorkerConfig{}, false, err
	}
	return cfg, true, nil
}

// readBounded reads a configuration file of at most maxHostAPIConfigFile
// bytes.
func readBounded(readFile func(string) ([]byte, error), name, path string) ([]byte, error) {
	b, err := readFile(path)
	if err != nil {
		return nil, fmt.Errorf("observer-cloud: %s: %w", name, err)
	}
	if len(b) > maxHostAPIConfigFile {
		return nil, fmt.Errorf("observer-cloud: %s: the file is larger than %d bytes", name, maxHostAPIConfigFile)
	}
	return b, nil
}

// loadHostAPIFiles builds the mTLS configuration and the host directory.
func loadHostAPIFiles(cfg hostAPIWorkerConfig, readFile func(string) ([]byte, error)) (*tls.Config, *hostclient.StaticDirectory, error) {
	files := map[string][]byte{}
	for _, f := range []struct{ name, path string }{
		{envHostAPIHostsFile, cfg.hostsFile},
		{envHostAPICAFile, cfg.caFile},
		{envHostAPICertFile, cfg.certFile},
		{envHostAPIKeyFile, cfg.keyFile},
	} {
		b, err := readBounded(readFile, f.name, f.path)
		if err != nil {
			return nil, nil, err
		}
		files[f.name] = b
	}
	tlsc, err := hostclient.ClientTLSConfig(files[envHostAPICAFile], files[envHostAPICertFile], files[envHostAPIKeyFile])
	if err != nil {
		return nil, nil, fmt.Errorf("observer-cloud: %w", err)
	}
	dir, err := hostclient.ParseHostsFile(files[envHostAPIHostsFile])
	if err != nil {
		return nil, nil, fmt.Errorf("observer-cloud: %s: %w", envHostAPIHostsFile, err)
	}
	return tlsc, dir, nil
}

// docSignerClient is what the worker asks the document signer
// (*signerd.DocumentClient).
type docSignerClient interface {
	PublicKeys(ctx context.Context) ([]signerd.PublishedKey, error)
	SignDocument(ctx context.Context, kind pc.DocumentKind, scope string, version int64, body []byte) (signerd.SignedDocument, error)
	SignRequest(ctx context.Context, method, target, nonce, bodyDigest string, timestamp int64) (pc.Envelope, error)
}

// signerKeySet is the document signer's published keys the worker uses.
type signerKeySet struct {
	hostKeyID    string
	hostPub      ed25519.PublicKey
	entitlements pc.KeySet
}

// readSignerKeys reads the signer's published keys: its signing host-API key
// (required: without it no request can be signed) and every entitlements key
// (the set each signed document is verified against before it is stored).
// When the binary has an entitlements verification key compiled in
// (entitlements.CompiledKeys), the signer's signing entitlements key must be
// one of them, or every host would refuse what this worker issues.
func readSignerKeys(ctx context.Context, sc docSignerClient, compiled pc.KeySet) (signerKeySet, error) {
	keys, err := sc.PublicKeys(ctx)
	if err != nil {
		return signerKeySet{}, fmt.Errorf("document signer keys: %w", err)
	}
	var out signerKeySet
	var signingEnt string
	for _, k := range keys {
		if len(k.Public) != ed25519.PublicKeySize || pc.DocumentKeyID(k.Public) != k.KeyID {
			return signerKeySet{}, fmt.Errorf("document signer key %q: the id is not the key's derived id", k.KeyID)
		}
		switch {
		case k.Purpose == signerd.PurposeHostAPI && k.Signing:
			out.hostKeyID, out.hostPub = k.KeyID, ed25519.PublicKey(k.Public)
		case k.Purpose == signerd.PurposeEntitlements:
			out.entitlements = append(out.entitlements, pc.NewDocumentKey(ed25519.PublicKey(k.Public)))
			if k.Signing {
				signingEnt = k.KeyID
			}
		}
	}
	switch {
	case out.hostKeyID == "":
		return signerKeySet{}, errors.New("the document signer holds no host-API key (SBCI_DOC_SIGNER_HOST_API_KEY)")
	case signingEnt == "":
		return signerKeySet{}, errors.New("the document signer holds no signing entitlements key")
	}
	if len(compiled) > 0 {
		if _, ok := compiled.Lookup(signingEnt); !ok {
			return signerKeySet{}, fmt.Errorf("the document signer's entitlements key %s is not compiled into this build; hosts would refuse every document", signingEnt)
		}
	}
	return out, nil
}

// hostAPIWorkerDeps is everything newHostAPIWorker composes.
type hostAPIWorkerDeps struct {
	store  *store.Store
	signer docSignerClient
	tls    *tls.Config
	hosts  hostclient.Directory
	// compiled is the binary's compiled entitlements key set (empty: no
	// check, ENTL-1).
	compiled pc.KeySet
	// owners resolves a create's owner identity (nil: StoreOwners over the
	// store, the 0093 lookups).
	owners entitlementwork.OwnerSource
	// plans chooses each org's plan (nil: SubscriptionPlans over
	// orgPlanReaderFor(store), the launch table and the floor).
	plans entitlementwork.PlanSource
	// pastDueGrace is the plan source's dunning window (0: the default;
	// used only when plans is nil).
	pastDueGrace time.Duration
	// waitlistFloor is the dispatcher's waitlist retry floor (0: the
	// default).
	waitlistFloor time.Duration
	// now is the clock (nil: time.Now).
	now func() time.Time
	// allowAddress filters every dialled host address (nil: private
	// addresses only). Tests allow loopback.
	allowAddress func(netip.Addr) bool
}

// hostAPIWorker is the composed host-API worker.
type hostAPIWorker struct {
	issuer     *entitlementwork.Issuer
	dispatcher *hostclient.Dispatcher
	reconciler *hostclient.Reconciler
}

// newHostAPIWorker reads the signer's keys and composes the issuer, the
// dispatcher and the reconciler. It starts nothing.
func newHostAPIWorker(ctx context.Context, d hostAPIWorkerDeps) (*hostAPIWorker, error) {
	keys, err := readSignerKeys(ctx, d.signer, d.compiled)
	if err != nil {
		return nil, err
	}
	rs, err := hostclient.EnvelopeRequestSigner(keys.hostKeyID, keys.hostPub, d.signer.SignRequest)
	if err != nil {
		return nil, err
	}
	sender, err := hostclient.NewSender(hostclient.SenderConfig{TLS: d.tls, Signer: rs, Now: d.now, AllowAddress: d.allowAddress})
	if err != nil {
		return nil, err
	}
	owners := d.owners
	if owners == nil {
		owners = entitlementwork.StoreOwners{Store: d.store}
	}
	plans := d.plans
	if plans == nil {
		plans = entitlementwork.SubscriptionPlans{Subs: orgPlanReaderFor(d.store), PastDueGrace: d.pastDueGrace, Now: d.now}
	}
	sign := entitlementwork.SignerFunc(func(ctx context.Context, orgID string, version int64, body []byte) ([]byte, string, error) {
		sd, err := d.signer.SignDocument(ctx, pc.KindEntitlements, orgID, version, body)
		return sd.Signature, sd.KeyID, err
	})
	iss, err := entitlementwork.New(entitlementwork.Config{
		Store: d.store, Signer: sign, Keys: keys.entitlements, Plans: plans, Now: d.now,
	})
	if err != nil {
		return nil, err
	}
	disp, err := hostclient.NewDispatcher(hostclient.DispatcherConfig{
		Store: d.store, Transport: sender, Hosts: d.hosts, Now: d.now, WaitlistRetryFloor: d.waitlistFloor,
		Resolver: entitlementwork.CreateResolver{Docs: d.store, Owners: owners, Facts: d.store},
		// W14-D1a: the launch document right after the create is acked.
		AfterCreate: func(ctx context.Context, orgID string) error {
			_, err := iss.EnsureOrg(ctx, orgID)
			return err
		},
	})
	if err != nil {
		return nil, err
	}
	rec, err := hostclient.NewReconciler(hostclient.ReconcilerConfig{
		Store: d.store, Transport: sender, Hosts: d.hosts, Now: d.now, Usage: d.store,
	})
	if err != nil {
		return nil, err
	}
	return &hostAPIWorker{issuer: iss, dispatcher: disp, reconciler: rec}, nil
}

// orgPlanReaderFor is the org-scoped subscription reader the issuer's plan
// source uses: the store itself once it implements
// entitlementwork.OrgPlanReader (the front-door lane's
// store.OrgSubscription, lead decision W14-D3), else nil, which reads as "no
// org has a subscription" (every team org then runs on its launch plan and
// then its floor). The type assertion makes the wiring take effect at merge
// with no edit here; TestOrgPlanReaderWiring reports which applies.
func orgPlanReaderFor(s *store.Store) entitlementwork.OrgPlanReader {
	if r, ok := any(s).(entitlementwork.OrgPlanReader); ok && s != nil {
		return r
	}
	return nil
}

// run drives the issuer (once now, then every entitlementIssueEvery) and the
// dispatcher and reconciler (hostclient.Client) until ctx ends.
func (w *hostAPIWorker) run(ctx context.Context, log *slog.Logger) {
	go func() {
		issue := func() {
			st, err := w.issuer.IssueOnce(ctx)
			if err != nil && ctx.Err() == nil {
				log.Warn("observer-cloud: entitlements issuer pass failed for some orgs", "err", err, "failed", st.Failed)
			}
			if st.Issued > 0 {
				log.Info("observer-cloud: entitlements documents issued", "issued", st.Issued, "orgs", st.Orgs)
			}
		}
		issue()
		t := time.NewTicker(entitlementIssueEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				issue()
			}
		}
	}()
	c, err := hostclient.New(hostclient.Config{
		Dispatcher: w.dispatcher, Reconciler: w.reconciler,
		OnError: func(err error) { log.Warn("observer-cloud: host-API client pass failed", "err", err) },
	})
	if err != nil {
		log.Error("observer-cloud: host-API client not started", "err", err)
		return
	}
	_ = c.Run(ctx)
}

// startHostAPIWorker wires the host-API client into the worker when
// SBCI_HOSTAPI_HOSTS_FILE is set. It returns started=false and does nothing
// at all otherwise. Configuration errors fail the worker's start; an
// unreachable document signer does not (the loops wait for it).
func startHostAPIWorker(ctx context.Context, log *slog.Logger, s *store.Store, getenv func(string) string, readFile func(string) ([]byte, error)) (bool, error) {
	cfg, enabled, err := resolveHostAPIWorkerConfig(getenv)
	if err != nil || !enabled {
		return false, err
	}
	tlsc, dir, err := loadHostAPIFiles(cfg, readFile)
	if err != nil {
		return false, err
	}
	compiled, err := entitlements.CompiledKeys()
	if err != nil {
		return false, fmt.Errorf("observer-cloud: compiled entitlements keys: %w", err)
	}
	deps := hostAPIWorkerDeps{
		store: s, signer: signerd.NewDocumentUnixClient(cfg.signerSocket), tls: tlsc, hosts: dir, compiled: compiled,
		pastDueGrace: cfg.pastDueGrace, waitlistFloor: cfg.waitlistFloor,
	}
	log.Info("observer-cloud: host-API client ON", "hosts_file", cfg.hostsFile, "signer_socket", cfg.signerSocket,
		"org_subscriptions_read", orgPlanReaderFor(s) != nil)
	go func() {
		for {
			w, err := newHostAPIWorker(ctx, deps)
			if err == nil {
				w.run(ctx, log)
				return
			}
			log.Warn("observer-cloud: host-API client waiting for the document signer; retrying every minute", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(hostAPISignerRetryEvery):
			}
		}
	}()
	return true, nil
}

// startWorkerHostAPI is the worker command's one call: the process
// environment and file system.
func startWorkerHostAPI(ctx context.Context, log *slog.Logger, s *store.Store) error {
	_, err := startHostAPIWorker(ctx, log, s, os.Getenv, os.ReadFile)
	return err
}
