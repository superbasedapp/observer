package invariant

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudcred"
	"github.com/marmutapp/superbased-observer/internal/cloudgateway"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// cloud_egress_test.go pins the egress invariants for the cloud-intelligence
// spine. It has TWO halves:
//
//   - IMPORT-GRAPH guards (TestCloudDaemonPathsCannotReachCloudClient,
//     TestCloudClientIsolatedToConsentGateway): the always-on daemon paths cannot
//     link the network lane at all, and the network lane is reachable only from
//     the consent-gated egress seam.
//   - ZERO-REQUEST guards (TestGatewayMakesNoRequestBeforeConsent and friends):
//     an import graph cannot check consent at RUNTIME, so these drive the seam
//     against an httptest server that fails the test on any inbound request.
//
// # Why the allow-list narrowed (divergence-remediation plan rev 4.1 §2 R2)
//
// The original posture was "manual-CLI-only": nothing wired into the daemon
// loop, and cmd/observer allow-listed to import the network lane. Operator
// ruling R2 replaced the governing principle with "no egress without prior
// explicit consent; after consent, egress for the consented purposes is
// unrestricted in mechanism" — which legitimizes background sync, dashboard
// buttons, and page-load reads, and therefore makes "only a typed CLI command
// may send" the wrong thing to pin.
//
// Its F11 disposition names the replacement mechanism and this file's job:
// "the cloud_egress import pin evolves to enforce a consent-checked seam rather
// than a CLI-only seam ... `cmd/observer` drops its direct `cloudclient` /
// `cloudcred` entitlement in favor of the gateway". So the allow-list below
// grants internal/cloudgateway — and ONLY it — the right to import the network
// lane. cmd/observer now reaches the network exclusively through that seam,
// which resolves live consent fail-closed before any request. A future
// background path gets the same treatment for free: it cannot obtain a network
// client without passing the gateway's check.
//
// Both import guards remain robust to a cloud package not existing: a package
// that does not exist appears in no dependency closure.

// cloudNetworkPackages are the network/credential cloud packages the daemon
// must never link. Matched as a package OR any subpackage.
var cloudNetworkPackages = []string{
	"internal/cloudclient",
	"internal/cloudpop",
	"internal/cloudcred",
}

// cloudDaemonEntryPackages are the always-on daemon surfaces (plan §7.1: the
// observer/watcher make no network calls with cloud disabled, and even when
// enabled only explicit `observer cloud` commands touch the network). None may
// TRANSITIVELY import any cloudNetworkPackages.
var cloudDaemonEntryPackages = []string{
	"internal/watcher",
	"internal/proxy",
	"internal/store",
	"internal/hook",
}

// cloudClientAllowedImporterPrefixes is the explicit, easy-to-extend set of
// packages permitted to import the cloud network packages.
//
// The ONLY node-side importer is internal/cloudgateway — the consent-gated
// egress seam (R2 disposition F11). cmd/observer is deliberately NOT here any
// more: it composes the gateway instead, so no command, and no future
// background path inside that binary, can obtain a network client without
// passing a live-grant check. The cloud packages themselves may import one
// another. The HOSTED service (internal/cloudserver + cmd/observer-cloud,
// CI-P3) is additionally allowed to import internal/cloudpop ONLY — the pure
// proof-format package both sides share for verification — never the node's
// cloudclient or cloudcred (a server importing the node's credential store or
// outbound client would be a plane-separation smell).
//
// Extend this map only with a package that ENFORCES consent, or that has no
// business enforcing it (a pure format package). Adding a caller here to skip
// the gateway would re-open exactly the hole F11 closed.
var cloudClientAllowedImporterPrefixes = map[string][]string{
	"internal/cloudgateway": {"internal/cloudclient", "internal/cloudpop", "internal/cloudcred"},
	"internal/cloudclient":  {"internal/cloudclient", "internal/cloudpop", "internal/cloudcred"},
	"internal/cloudpop":     {"internal/cloudpop"},
	"internal/cloudcred":    {"internal/cloudcred", "internal/cloudpop"},
	"cmd/observer-cloud":    {"internal/cloudpop"},
	"internal/cloudserver":  {"internal/cloudpop"},
}

// matchesCloudPkg reports whether module-relative rel is one of pkgs or a
// subpackage of one.
func matchesCloudPkg(rel string, pkgs []string) (string, bool) {
	for _, p := range pkgs {
		if rel == p || strings.HasPrefix(rel, p+"/") {
			return p, true
		}
	}
	return "", false
}

// allowedCloudTargetsFor returns the cloud network packages the importer
// (module-relative, possibly a subpackage of an allow-listed prefix) may
// import, per cloudClientAllowedImporterPrefixes.
func allowedCloudTargetsFor(importerRel string) ([]string, bool) {
	for prefix, targets := range cloudClientAllowedImporterPrefixes {
		if importerRel == prefix || strings.HasPrefix(importerRel, prefix+"/") {
			return targets, true
		}
	}
	return nil, false
}

// TestCloudDaemonPathsCannotReachCloudClient is the PRIMARY zero-egress guard:
// the full transitive dependency closure of each always-on daemon package must
// contain NONE of the cloud network packages. Catches a transitive linkage a
// source-only scan would miss (e.g. a daemon package gaining a dep on a new
// helper that itself imports cloudclient).
func TestCloudDaemonPathsCannotReachCloudClient(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	for _, entry := range cloudDaemonEntryPackages {
		entry := entry
		t.Run(entry, func(t *testing.T) {
			cmd := exec.Command("go", "list", "-deps", "./"+entry)
			cmd.Dir = repoRoot
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("go list -deps ./%s failed: %v\n%s", entry, err, out)
			}
			// Non-vacuous: the closure must be non-empty and include the entry
			// package itself, so a typo'd/absent daemon package can't make this
			// pass silently.
			var sawSelf bool
			var count int
			for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				pkg := strings.TrimSpace(line)
				if !strings.HasPrefix(pkg, modulePath) {
					continue // std lib / third-party
				}
				count++
				rel := strings.TrimPrefix(pkg, modulePath)
				if rel == entry {
					sawSelf = true
				}
				if bad, hit := matchesCloudPkg(rel, cloudNetworkPackages); hit {
					t.Errorf("daemon package %q transitively imports %q — the always-on daemon "+
						"paths must never reach the network cloud client (plan §7.1 zero-egress; "+
						"§4e manual-CLI-only)", entry, bad)
				}
			}
			if count == 0 || !sawSelf {
				t.Fatalf("go list -deps ./%s returned an unexpectedly empty/self-less module closure "+
					"(count=%d sawSelf=%v) — the guard would be vacuous", entry, count, sawSelf)
			}
		})
	}
}

// TestCloudClientIsolatedToConsentGateway is the isolation guard: no package in
// the module may import a cloud network package EXCEPT the allow-listed
// importers (internal/cloudgateway, and the cloud packages themselves).
//
// It uses DIRECT imports (.Imports excludes test-only imports), so a package's
// own tests importing the network lane are correctly not flagged — a test may
// construct a raw client to prove something about the client itself; what must
// not exist is a PRODUCTION path that reaches the network without the gateway.
// Robust to the cloud packages not existing: with none present, nothing imports
// them and the guard passes, arming automatically when they land.
func TestCloudClientIsolatedToConsentGateway(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	// -e tolerates packages that fail to load (e.g. a sibling lane mid-build).
	cmd := exec.Command("go", "list", "-e", "-f", "{{.ImportPath}}{{range .Imports}} {{.}}{{end}}", "./...")
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list ./... failed: %v\n%s", err, out)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 0 {
			continue
		}
		importer := fields[0]
		if !strings.HasPrefix(importer, modulePath) {
			continue
		}
		importerRel := strings.TrimPrefix(importer, modulePath)
		for _, imp := range fields[1:] {
			if !strings.HasPrefix(imp, modulePath) {
				continue
			}
			impRel := strings.TrimPrefix(imp, modulePath)
			bad, hit := matchesCloudPkg(impRel, cloudNetworkPackages)
			if !hit {
				continue
			}
			if allowedTargets, ok := allowedCloudTargetsFor(importerRel); ok {
				if _, targetOK := matchesCloudPkg(impRel, allowedTargets); targetOK {
					continue
				}
			}
			t.Errorf("package %q imports cloud network package %q — only the consent-gated egress "+
				"seam (internal/cloudgateway), the cloud packages themselves, and the hosted service "+
				"(cloudpop only) may import it (plan rev 4.1 §2 R2 disposition F11). Compose "+
				"internal/cloudgateway instead: it resolves the live consent grant fail-closed before "+
				"any network attempt. If this really is a new legitimate importer, extend "+
				"cloudClientAllowedImporterPrefixes deliberately.",
				importerRel, bad)
		}
	}
}

// --- runtime zero-request guards --------------------------------------------
//
// The import guards above prove the network lane is UNREACHABLE except through
// the consent seam. These prove the seam actually refuses: with no live grant,
// with a revoked one, and — the case the R2 disposition names explicitly — on a
// page-load-shaped read before the user has consented to anything.
//
// The method is not an assertion about behaviour but a measurement of it: the
// gateway is pointed at an httptest server that FAILS THE TEST on any inbound
// request. If a single byte leaves, the test says so.

// fakeCloudGrants is an in-memory GrantStore.
type fakeCloudGrants struct {
	receipts []store.CloudConsentReceipt
}

func (f *fakeCloudGrants) ListLiveCloudConsentReceipts(_ context.Context, purpose string) ([]store.CloudConsentReceipt, error) {
	var out []store.CloudConsentReceipt
	for _, r := range f.receipts {
		if r.InvalidatedAt != nil {
			continue // the real store filters these in SQL
		}
		if purpose != "" && r.Purpose != purpose {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

// memCloudCred is an in-memory credential store. Tests MUST NOT use
// cloudcred.Open, which probes (and on success writes to) the host's real OS
// keychain.
type memCloudCred struct {
	device   ed25519.PrivateKey
	deviceOK bool
	token    string
	refresh  string
}

func (m *memCloudCred) SaveWorkOSRefresh(r string) error { m.refresh = r; return nil }

func (m *memCloudCred) LoadWorkOSRefresh() (string, error) {
	if m.refresh == "" {
		return "", cloudcred.ErrNotFound
	}
	return m.refresh, nil
}

func (m *memCloudCred) SaveDeviceKey(k ed25519.PrivateKey) error {
	m.device, m.deviceOK = k, true
	return nil
}

func (m *memCloudCred) LoadDeviceKey() (ed25519.PrivateKey, error) {
	if !m.deviceOK {
		return nil, cloudcred.ErrNotFound
	}
	return m.device, nil
}

func (m *memCloudCred) SaveAPIToken(t string) error { m.token = t; return nil }

func (m *memCloudCred) LoadAPIToken() (string, error) {
	if m.token == "" {
		return "", cloudcred.ErrNotFound
	}
	return m.token, nil
}

func (m *memCloudCred) Clear() error {
	m.device, m.deviceOK, m.token, m.refresh = nil, false, "", ""
	return nil
}

func (m *memCloudCred) Backend() string            { return "memory" }
func (m *memCloudCred) SecurityDiagnostic() string { return "" }

// cloudTripwireServer fails the test on ANY inbound request.
func cloudTripwireServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Errorf("EGRESS WITHOUT CONSENT: a %s %s request left the process with no live grant "+
			"authorizing it (plan rev 4.1 §2 R2: no egress without prior explicit consent)",
			r.Method, r.URL.Path)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newTripwireGateway(t *testing.T, grants cloudgateway.GrantStore, baseURL string) *cloudgateway.Gateway {
	t.Helper()
	gw, err := cloudgateway.Open(cloudgateway.Options{
		Grants:     grants,
		Cred:       &memCloudCred{},
		BaseURL:    baseURL,
		MaxRetries: 0,
		Backoff:    func(int) time.Duration { return 0 },
		Now:        func() time.Time { return time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("open gateway: %v", err)
	}
	return gw
}

// TestGatewayMakesNoRequestBeforeConsent is the pre-consent zero-request guard:
// a node that has granted nothing sends nothing, on every feature entry point —
// including the page-load-shaped read (FeatureFetch), which the R2 disposition
// calls out by name.
func TestGatewayMakesNoRequestBeforeConsent(t *testing.T) {
	srv := cloudTripwireServer(t)
	gw := newTripwireGateway(t, &fakeCloudGrants{}, srv.URL)
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"upload (FeatureSend)", func() error {
			return gw.FeatureSend(ctx, cloudcontract.PurposeStructuralInsights, func(s cloudgateway.UploadSession) error {
				_, err := s.Upload(ctx, cloudgateway.UploadRequest{
					CloudSessionID: "cs-x", Feature: "session_enrichment", Envelope: []byte(`{"x":1}`),
					PreAttempt: func() error { return nil },
				})
				return err
			})
		}},
		{"structural (StandingSend)", func() error {
			return gw.StandingSend(ctx, cloudcontract.PurposeStructuralInsights, func(s cloudgateway.StructuralSession) error {
				_, err := s.UploadStructural(ctx, cloudgateway.StructuralUploadRequest{
					Payload: []byte(`{"x":1}`), Period: "2026-08-31", PeriodRuleVersion: 1,
					SchemaVersion: cloudcontract.StructuralSnapshotSchemaVersion, Revision: 1, Digest: "sha256:x",
					PreAttempt: func() error { return nil },
				})
				return err
			})
		}},
		{"page-load read (FeatureFetch)", func() error {
			return gw.FeatureFetch(ctx, func(s cloudgateway.ReadSession) error {
				_, err := s.Results(ctx, "")
				return err
			})
		}},
	} {
		if err := tc.call(); !errors.Is(err, cloudgateway.ErrNoLiveGrant) {
			t.Errorf("%s: want ErrNoLiveGrant, got %v", tc.name, err)
		}
	}
}

// TestGatewayMakesNoRequestAfterRevocation is the revoked-grant guard: consent
// that has been revoked authorizes nothing, and no request is attempted.
func TestGatewayMakesNoRequestAfterRevocation(t *testing.T) {
	srv := cloudTripwireServer(t)
	revokedAt := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	grants := &fakeCloudGrants{receipts: []store.CloudConsentReceipt{{
		ID:            "rcpt_revoked",
		Purpose:       string(cloudcontract.PurposeStructuralInsights),
		GrantMode:     store.CloudGrantStanding,
		CreatedAt:     time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
		InvalidatedAt: &revokedAt,
	}}}
	gw := newTripwireGateway(t, grants, srv.URL)

	err := gw.StandingSend(context.Background(), cloudcontract.PurposeStructuralInsights,
		func(s cloudgateway.StructuralSession) error {
			_, uerr := s.UploadStructural(context.Background(), cloudgateway.StructuralUploadRequest{
				Payload: []byte(`{"x":1}`), Period: "2026-08-31", PeriodRuleVersion: 1,
				SchemaVersion: cloudcontract.StructuralSnapshotSchemaVersion, Revision: 1, Digest: "sha256:x",
				PreAttempt: func() error { return nil },
			})
			return uerr
		})
	if !errors.Is(err, cloudgateway.ErrNoLiveGrant) {
		t.Fatalf("want ErrNoLiveGrant for a revoked grant, got %v", err)
	}
}

// TestGatewayBootstrapLaneWorksWithoutGrants is the other half of the invariant,
// and it must be pinned too: the sign-in lane is NOT consent-gated (R2
// disposition F10 — the user's own sign-in action authorizes account/device
// bootstrap egress). If this ever started failing closed, `observer cloud login`
// would be impossible and the plane would be unusable rather than private.
func TestGatewayBootstrapLaneWorksWithoutGrants(t *testing.T) {
	var logouts int
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/logout", func(w http.ResponseWriter, _ *http.Request) {
		logouts++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"signed_out"}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cred := &memCloudCred{}
	gw, err := cloudgateway.Open(cloudgateway.Options{
		Grants:     &fakeCloudGrants{}, // zero grants, deliberately
		Cred:       cred,
		BaseURL:    srv.URL,
		MaxRetries: 0,
		Backoff:    func(int) time.Duration { return 0 },
	})
	if err != nil {
		t.Fatalf("open gateway: %v", err)
	}
	if err := cred.SaveAPIToken("tok-1"); err != nil {
		t.Fatalf("seed token: %v", err)
	}
	if err := gw.BootstrapLogout(context.Background()); err != nil {
		t.Fatalf("BootstrapLogout must work without any consent grant: %v", err)
	}
	if logouts != 1 {
		t.Fatalf("bootstrap logout reached the server %d time(s), want 1", logouts)
	}
}
