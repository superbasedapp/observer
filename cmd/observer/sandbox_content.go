//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// sandbox_content.go is the node's fetch and install of the sandbox content
// kinds (sandbox plan v2 section 12.3, lane SBX-P3D): sandbox.image (the
// container driver's default image descriptor and SBOM) and
// sandbox.native_files (the Windows driver's signed MXC file manifest), into
// the store the drivers already read (<observer dir>/sandbox-content).
//
// The opt-in decision, one rule per row of orgclient.SandboxContentKinds:
// a kind is fetched only while its consuming driver is active (the driver
// component selected, [terminal.sandbox] on and the driver's backend in
// [terminal.sandbox].backends), and only on a user action (`observer
// sandbox content fetch`) or, in the daemon, the first resolve that needs
// it. A managed enrolment fetches from its org server's mirror
// (orgclient.InstallSecurityContent, the one mirror fetch path) and falls
// back to the vendor feed only on the server's typed refusals
// (orgclient.SandboxContentFeedFallback: 404 not_supported, which is also
// what the default relay mode off answers, and 403 managed_only), never on a
// network error, a 5xx or a kind the org's own mirror does not hold, so an
// org that runs a mirror is never bypassed (SBX-P3D audit finding 2). An
// individual enrolment, which the mirror route never serves, and a node
// that is not enrolled fetch from the vendor feed (the security.online
// lane's client, present only in builds with security.deps). A failed fetch
// keeps the last-known-good and is recorded beside the store; the status
// line shows it, never a clean state.

// sandboxContentDir is the store root under the observer directory; it is
// the container driver's sandboxImageContentDir (pinned equal by a test).
const sandboxContentDir = "sandbox-content"

// sandboxContentFetchFile records each kind's last fetch beside the store.
const sandboxContentFetchFile = "sandbox-content-fetch.json"

// sandboxContentMaxArtifact caps one artifact fetched from the vendor feed:
// the largest sandbox entry the org mirror accepts (secrelay's caps).
const sandboxContentMaxArtifact = 4<<20 + 64<<10

// sandboxFeedClient is the vendor feed's one call this file uses.
type sandboxFeedClient interface {
	FetchFeedFile(ctx context.Context, kind, file string) ([]byte, error)
}

// sandboxContentFeed is the vendor feed client; nil in a build without the
// security.online lane (no security.deps), where a node that is not
// enrolled has no source and says so.
var sandboxContentFeed func() sandboxFeedClient

// sandboxContentVendorKeys is the vendor key set (set from
// sandbox_content_keys.go in a build with the update module; none verifies
// nothing).
var sandboxContentVendorKeys = func() []ed25519.PublicKey { return nil }

// sandboxMirrorInstaller is the org client's mirror fetch.
type sandboxMirrorInstaller interface {
	InstallSecurityContent(ctx context.Context, st contentchan.Store, kind content.Kind, tr contentchan.Trust) (orgclient.SecurityContentResult, error)
}

// sandboxContentStore is the node's sandbox content store.
func sandboxContentStore(observerDir string) contentchan.Store {
	return contentchan.Store{Root: filepath.Join(observerDir, sandboxContentDir)}
}

// sandboxContentEnv is one fetch's seams.
type sandboxContentEnv struct {
	store contentchan.Store
	trust contentchan.Trust
	// enrolled reports whether the node is enrolled with an org server; an
	// error fetches nothing (never a guess between the two sources).
	enrolled func(context.Context) (bool, error)
	org      func(context.Context) (sandboxMirrorInstaller, func(), error)
	feed     func() sandboxFeedClient
	active   func(content.Kind) bool
}

// The fetch sources, as recorded.
const (
	sandboxSourceOrg  = "org_mirror"
	sandboxSourceFeed = "vendor_feed"
)

// sandboxContentOutcome is one kind's fetch.
type sandboxContentOutcome struct {
	Kind content.Kind
	// Source is where the bytes came from ("" when nothing was fetched).
	Source string
	// Skipped says why nothing was fetched (the driver is inactive).
	Skipped string
	// Fallback says why an enrolled node fetched from the vendor feed (the
	// org server's typed refusal, or an individual enrolment).
	Fallback string
	State    content.State
}

// sandboxMirrorManaged reports whether the org client's enrolment is a
// managed one. A client that cannot say is treated as managed, so it keeps
// to its org (the conservative side: no feed fallback without a refusal).
func sandboxMirrorManaged(ctx context.Context, c sandboxMirrorInstaller) (bool, error) {
	if m, ok := c.(interface {
		EnrolmentManaged(context.Context) (bool, error)
	}); ok {
		return m.EnrolmentManaged(ctx)
	}
	return true, nil
}

// errSandboxContentNoFeed is a node that is not enrolled in a build with no
// vendor feed client.
var errSandboxContentNoFeed = errors.New("this build carries no vendor feed client (security.deps is not compiled in); enrol with an org server or install the kind by hand")

// fetch installs kind from the one source the node's enrolment allows.
func (e sandboxContentEnv) fetch(ctx context.Context, kind content.Kind) (sandboxContentOutcome, error) {
	out := sandboxContentOutcome{Kind: kind}
	row, ok := orgclient.LookupSandboxContentKind(kind)
	if !ok {
		return out, fmt.Errorf("sandbox content: %q is not a sandbox content kind", kind)
	}
	if e.active == nil || !e.active(kind) {
		out.Skipped = "its consuming driver (" + row.Component + ") is not active"
		return out, nil
	}
	enrolled, err := e.enrolled(ctx)
	if err != nil {
		err = fmt.Errorf("enrolment unreadable, nothing fetched: %w", err)
		e.record(kind, "", err)
		return out, err
	}
	if enrolled {
		c, cleanup, err := e.org(ctx)
		if err != nil {
			out.Source = sandboxSourceOrg
			e.record(kind, out.Source, err)
			return out, fmt.Errorf("sandbox content: %s from the org mirror: %w", kind, err)
		}
		defer cleanup()
		managed, err := sandboxMirrorManaged(ctx, c)
		if err != nil {
			err = fmt.Errorf("enrolment tenancy unreadable, nothing fetched: %w", err)
			e.record(kind, "", err)
			return out, err
		}
		if !managed {
			out.Fallback = "an individual enrolment: the org mirror serves managed enrolments only"
		} else {
			out.Source = sandboxSourceOrg
			res, err := c.InstallSecurityContent(ctx, e.store, kind, e.trust)
			out.State = res.State
			if err == nil {
				e.record(kind, out.Source, nil)
				return out, nil
			}
			if !orgclient.SandboxContentFeedFallback(err) {
				e.record(kind, out.Source, err)
				return out, fmt.Errorf("sandbox content: %s from the org mirror: %w", kind, err)
			}
			out.Fallback = "the org server refused the mirror route (" + err.Error() + ")"
		}
	}
	out.Source = sandboxSourceFeed
	var feed sandboxFeedClient
	if e.feed != nil {
		feed = e.feed()
	}
	if feed == nil {
		e.recordNote(kind, out.Source, out.Fallback, errSandboxContentNoFeed)
		return out, fmt.Errorf("sandbox content: %s: %w", kind, errSandboxContentNoFeed)
	}
	st, err := fetchSandboxFromFeed(ctx, feed, e.store, kind, e.trust)
	out.State = st
	e.recordNote(kind, out.Source, out.Fallback, err)
	if err != nil {
		return out, fmt.Errorf("sandbox content: %s from the vendor feed: %w", kind, err)
	}
	return out, nil
}

// fetchSandboxFromFeed downloads kind's envelope, then exactly the
// artifacts it lists for this platform, and installs them through the
// content channel; any failure keeps the last-known-good (a refused
// envelope is recorded in the kind's state).
func fetchSandboxFromFeed(ctx context.Context, feed sandboxFeedClient, st contentchan.Store, kind content.Kind, tr contentchan.Trust) (content.State, error) {
	prev, err := st.State(kind)
	if err != nil {
		return prev, err
	}
	env, err := feed.FetchFeedFile(ctx, string(kind), contentchan.ManifestFile)
	if err != nil {
		return prev, err
	}
	v, err := content.Verify(content.VerifyInput{
		Envelope: env, Kind: kind, VendorKeys: tr.VendorKeys, Accepted: prev.Accepted, Now: time.Now(),
	})
	if err != nil {
		next, _ := st.Install(kind, env, nil, tr) // records the refusal; keeps last-known-good
		return next, err
	}
	if prev.Accepted != nil && v.Hash == prev.Accepted.ManifestHash {
		return prev, nil
	}
	goos, goarch := st.GOOS, st.GOARCH
	if goos == "" {
		goos = runtime.GOOS
	}
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	arts := map[string][]byte{}
	for _, en := range v.Manifest.Entries {
		if (en.OS != "" && en.OS != goos) || (en.Arch != "" && en.Arch != goarch) || content.IsRevoked(v.Manifest, en.SHA256) {
			continue
		}
		if en.SizeBytes > sandboxContentMaxArtifact {
			return prev, fmt.Errorf("%s is %d bytes, over the %d-byte cap of a sandbox artifact", en.Name, en.SizeBytes, sandboxContentMaxArtifact)
		}
		b, err := feed.FetchFeedFile(ctx, string(kind), en.Name)
		if err != nil {
			return prev, fmt.Errorf("artifact %s: %w", en.Name, err)
		}
		arts[en.Name] = b
	}
	return st.Install(kind, env, arts, tr)
}

// sandboxContentFetch is one kind's last fetch.
type sandboxContentFetch struct {
	At     time.Time `json:"at"`
	Source string    `json:"source,omitempty"`
	// Note says why an enrolled node used the vendor feed.
	Note  string `json:"note,omitempty"`
	Error string `json:"error,omitempty"`
}

var sandboxContentRecordMu sync.Mutex

func sandboxContentFetchPath(st contentchan.Store) string {
	return filepath.Join(filepath.Dir(st.Root), sandboxContentFetchFile)
}

// readSandboxContentFetches reads the fetch record (capped; a missing or
// unreadable record is empty).
func readSandboxContentFetches(st contentchan.Store) map[string]sandboxContentFetch {
	out := map[string]sandboxContentFetch{}
	f, err := os.Open(sandboxContentFetchPath(st))
	if err != nil {
		return out
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, 16<<10))
	if err == nil {
		_ = json.Unmarshal(b, &out)
	}
	return out
}

// record writes kind's last fetch.
func (e sandboxContentEnv) record(kind content.Kind, source string, err error) {
	e.recordNote(kind, source, "", err)
}

// recordNote writes kind's last fetch with a note (why the feed was used).
func (e sandboxContentEnv) recordNote(kind content.Kind, source, note string, err error) {
	sandboxContentRecordMu.Lock()
	defer sandboxContentRecordMu.Unlock()
	m := readSandboxContentFetches(e.store)
	f := sandboxContentFetch{At: time.Now().UTC(), Source: source, Note: note}
	if err != nil {
		f.Error = err.Error()
	}
	m[string(kind)] = f
	b, merr := json.Marshal(m)
	if merr != nil {
		return
	}
	p := sandboxContentFetchPath(e.store)
	if os.MkdirAll(filepath.Dir(p), 0o700) != nil {
		return
	}
	if os.WriteFile(p+".tmp", b, 0o600) == nil {
		_ = os.Rename(p+".tmp", p)
	}
}

// sandboxContentStatusLine is one kind's status: what is installed, its
// freshness and the last fetch. A failed last fetch is always named.
func sandboxContentStatusLine(st contentchan.Store, tr contentchan.Trust, kind content.Kind) string {
	line := string(kind) + ": "
	l, err := st.Load(kind, tr, 0)
	switch {
	case errors.Is(err, contentchan.ErrNotInstalled):
		line += "not installed"
	case err != nil:
		// A driver's judge may still verify the set another way (a debug
		// image set under its imported debug key, R-016).
		if judge := sandboxContentSetJudges[kind]; judge != nil {
			if note := judge(st, tr); note != "" {
				line += strings.TrimPrefix(note, "; ")
				break
			}
		}
		line += "installed but refused on load (" + string(content.ReasonOf(err)) + "): unknown"
	default:
		line += fmt.Sprintf("version %d, %s (expires %s)", l.Manifest.ManifestVersion, l.Freshness, l.Manifest.ExpiresAt)
		if judge := sandboxContentSetJudges[kind]; judge != nil {
			line += judge(st, tr)
		}
	}
	if f, ok := readSandboxContentFetches(st)[string(kind)]; ok {
		src := sourceOr(f.Source)
		if f.Note != "" {
			src += " (" + f.Note + ")"
		}
		if f.Error != "" {
			line += fmt.Sprintf("; last fetch FAILED at %s from %s: %s (the last-known-good, if any, stays in use)", f.At.Format(time.RFC3339), src, f.Error)
		} else {
			line += fmt.Sprintf("; last fetch ok at %s from %s", f.At.Format(time.RFC3339), src)
		}
	}
	return line
}

// sandboxContentSetJudges add, per kind, what the driver's own trust check
// says about the installed set beyond the manifest's signature and age:
// today a revoked set, named with its revoking manifest, so a revoked set
// never reads as available (R-015). A driver file registers its kinds from
// init; a kind with no judge prints the manifest line alone.
var sandboxContentSetJudges = map[content.Kind]func(st contentchan.Store, tr contentchan.Trust) string{}

func sourceOr(s string) string {
	if s == "" {
		return "no source"
	}
	return s
}

// sandboxContentActiveFor is the opt-in rule: kind's consuming driver is
// registered (compiled in), selected by the node's [components] block, the
// effective sandbox is on and the driver's backend is enabled.
func sandboxContentActiveFor(cfg config.Config) func(content.Kind) bool {
	snap := componentSnapshotForConfig(cfg)
	sb := effectiveSandboxConfig(cfg)
	backends := sandboxEnabledBackends(sb)
	return func(kind content.Kind) bool {
		row, ok := orgclient.LookupSandboxContentKind(kind)
		if !ok || !sb.Enabled {
			return false
		}
		for _, reg := range sandboxDriverRegs {
			if reg.component == row.Component && sandboxDriverSelected(snap, reg.component) && slices.Contains(backends, reg.backend) {
				return true
			}
		}
		return false
	}
}

// sandboxContentEnvFor wires the real seams for configPath (resolved).
func sandboxContentEnvFor(cfg config.Config, configPath string) sandboxContentEnv {
	observerDir := filepath.Dir(cfg.Observer.DBPath)
	return sandboxContentEnv{
		store:    sandboxContentStore(observerDir),
		trust:    contentchan.Trust{VendorKeys: sandboxContentVendorKeys()},
		enrolled: func(context.Context) (bool, error) { return cfg.OrgClient.Enabled, nil },
		org: func(ctx context.Context) (sandboxMirrorInstaller, func(), error) {
			c, cleanup, enabled, err := buildOrgClient(ctx, configPath)
			if err != nil {
				return nil, nil, err
			}
			if !enabled {
				cleanup()
				return nil, nil, errors.New("not enrolled with an org server")
			}
			return c, cleanup, nil
		},
		feed:   sandboxContentFeed,
		active: sandboxContentActiveFor(cfg),
	}
}

// sandboxContentAuto is the daemon's first-use fetch state, owned here:
// when the next attempt per kind may start and which attempt is running.
// Only the daemon process fetches on its own (it records its config path at
// start); a CLI process or a test never does.
var sandboxContentAuto = struct {
	mu       sync.Mutex
	next     map[content.Kind]time.Time
	inflight map[content.Kind]bool
}{next: map[content.Kind]time.Time{}, inflight: map[content.Kind]bool{}}

// The first-use fetch's retry intervals: an hour after a failure, a day
// after the source said it does not publish the kind (SBX-P3D audit finding
// 3: a kind no feed publishes yet is not polled hourly).
const (
	sandboxContentRetry          = time.Hour
	sandboxContentRetryNotPublic = 24 * time.Hour
	// sandboxContentFetchTimeout bounds one background attempt.
	sandboxContentFetchTimeout = 20 * time.Second
)

// sandboxContentNotPublished reports whether a fetch error says the source
// does not publish the kind: the org mirror's not_mirrored here, and the
// vendor feed's 404 where the feed client is compiled in
// (sandbox_content_feed.go adds it).
var sandboxContentNotPublished = []func(error) bool{
	func(err error) bool { return errors.Is(err, orgclient.ErrSecurityContentNotMirrored) },
}

func sandboxContentRetryAfter(err error) time.Duration {
	for _, f := range sandboxContentNotPublished {
		if f(err) {
			return sandboxContentRetryNotPublic
		}
	}
	return sandboxContentRetry
}

// sandboxContentEnsureFn starts the first-use fetch of kind (see
// sandboxContentEnsure). A variable so a test can observe or replace it.
var sandboxContentEnsureFn = sandboxContentEnsure

// sandboxContentEnsureFetch is one background attempt; a variable so a test
// can make it slow or failing.
var sandboxContentEnsureFetch = sandboxContentEnsureOnce

// sandboxContentEnsure starts, in the background, one fetch of kind when
// nothing is installed yet, the process is the daemon, no attempt for kind
// is running and its retry time has come. It never blocks its caller: the
// availability probe and the image resolve call it and then read only what
// is installed (SBX-P3D audit finding 3). The attempt is bounded
// (sandboxContentFetchTimeout), recorded beside the store and logged; the
// explicit `observer sandbox content fetch` verb is the way to fetch now.
func sandboxContentEnsure(kind content.Kind, observerDir string) {
	sandboxContentStart(kind, observerDir, false)
}

// sandboxContentRefreshFn starts a background refresh of an installed kind
// that is past its age floor (the MXC driver's signed manifest; SBX-P3D
// audit finding 4). A variable so a test can observe it.
var sandboxContentRefreshFn = sandboxContentRefresh

// sandboxContentRefresh is sandboxContentEnsure for an installed kind: the
// same daemon-only, never-blocking, rate-limited background attempt.
func sandboxContentRefresh(kind content.Kind, observerDir string) {
	sandboxContentStart(kind, observerDir, true)
}

// sandboxContentStart is the one starter of the background attempt;
// refresh also fetches over an installed kind.
func sandboxContentStart(kind content.Kind, observerDir string, refresh bool) {
	if daemonConfigPathSetting.Load() == nil {
		return // not the daemon
	}
	st := sandboxContentStore(observerDir)
	if s, err := st.State(kind); err != nil || (s.Accepted != nil && !refresh) {
		return
	}
	now := time.Now()
	sandboxContentAuto.mu.Lock()
	if sandboxContentAuto.inflight[kind] || now.Before(sandboxContentAuto.next[kind]) {
		sandboxContentAuto.mu.Unlock()
		return
	}
	sandboxContentAuto.inflight[kind] = true
	sandboxContentAuto.next[kind] = now.Add(sandboxContentRetry)
	sandboxContentAuto.mu.Unlock()
	// Read the seam on the caller's goroutine: a test that swaps it back at
	// cleanup must not race the attempt still running in the background.
	fetch := sandboxContentEnsureFetch
	go func() {
		err := fetch(kind, observerDir)
		sandboxContentAuto.mu.Lock()
		if err != nil {
			sandboxContentAuto.next[kind] = time.Now().Add(sandboxContentRetryAfter(err))
		}
		sandboxContentAuto.inflight[kind] = false
		sandboxContentAuto.mu.Unlock()
		if err != nil {
			slog.Default().Info("sandbox content: first-use fetch failed; the next attempt waits", "kind", string(kind), "retry_after", sandboxContentRetryAfter(err).String(), "err", err)
		} else {
			slog.Default().Info("sandbox content: first-use fetch done", "kind", string(kind))
		}
	}()
}

// sandboxContentEnsureOnce is the real attempt: the daemon's config, the
// node's one allowed source, bounded by sandboxContentFetchTimeout.
func sandboxContentEnsureOnce(kind content.Kind, observerDir string) error {
	path, err := config.ResolveGlobalPath(daemonConfigPath())
	if err != nil {
		return err
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: path})
	if err != nil {
		return err
	}
	env := sandboxContentEnvFor(cfg, path)
	env.store = sandboxContentStore(observerDir)
	ctx, cancel := context.WithTimeout(context.Background(), sandboxContentFetchTimeout)
	defer cancel()
	out, err := env.fetch(ctx, kind) // recorded; the status line shows a failure
	if err == nil && out.Skipped != "" {
		return nil
	}
	return err
}

func init() { sandboxSubcommands = append(sandboxSubcommands, newSandboxContentCmd) }

// newSandboxContentCmd is `observer sandbox content status|fetch`.
func newSandboxContentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "content",
		Short: "Signed sandbox content: the default image's descriptor and the MXC file manifest",
		Long: "The sandbox kinds of the signed content channel (sandbox plan 12.3):\n" +
			"sandbox.image (the container driver's default image) and sandbox.native_files\n" +
			"(the Windows driver's MXC file manifest). A kind is fetched only while its\n" +
			"driver is active; a managed enrolment fetches from its org server's mirror\n" +
			"(the vendor feed only when the server refuses the route: relay mode off or\n" +
			"managed enrolments only, never on a network error), any other node from\n" +
			"the vendor feed.",
	}
	cmd.AddCommand(newSandboxContentStatusCmd(), newSandboxContentFetchCmd(), newSandboxContentImportCmd())
	return cmd
}

func sandboxContentLoad(cfgPath string) (config.Config, string, error) {
	path, err := config.ResolveGlobalPath(cfgPath)
	if err != nil {
		return config.Config{}, "", err
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: path})
	if err != nil {
		return config.Config{}, "", fmt.Errorf("load config: %w", err)
	}
	return cfg, path, nil
}

func newSandboxContentStatusCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "What is installed for each sandbox kind, its freshness and the last fetch",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, path, err := sandboxContentLoad(cfgPath)
			if err != nil {
				return err
			}
			env := sandboxContentEnvFor(cfg, path)
			for _, r := range orgclient.SandboxContentKinds {
				line := sandboxContentStatusLine(env.store, env.trust, r.Kind)
				if !env.active(r.Kind) {
					line += " (not fetched: " + r.Component + " is not active)"
				}
				fmt.Fprintln(cmd.OutOrStdout(), line)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "", "path to config.toml")
	return cmd
}

func newSandboxContentFetchCmd() *cobra.Command {
	var cfgPath, kind string
	cmd := &cobra.Command{
		Use:   "fetch",
		Short: "Fetch and install the sandbox kinds whose driver is active",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, path, err := sandboxContentLoad(cfgPath)
			if err != nil {
				return err
			}
			env := sandboxContentEnvFor(cfg, path)
			var errs []error
			for _, r := range orgclient.SandboxContentKinds {
				if kind != "" && string(r.Kind) != kind {
					continue
				}
				out, err := env.fetch(cmd.Context(), r.Kind)
				switch {
				case err != nil:
					errs = append(errs, err)
				case out.Skipped != "":
					fmt.Fprintf(cmd.OutOrStdout(), "%s: not fetched: %s\n", r.Kind, out.Skipped)
				default:
					fmt.Fprintf(cmd.OutOrStdout(), "%s: from %s\n", r.Kind, out.Source)
				}
				fmt.Fprintln(cmd.OutOrStdout(), "  "+sandboxContentStatusLine(env.store, env.trust, r.Kind))
			}
			if kind != "" {
				if _, ok := orgclient.LookupSandboxContentKind(content.Kind(kind)); !ok {
					return fmt.Errorf("sandbox content fetch: unknown kind %q", kind)
				}
			}
			return errors.Join(errs...)
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "", "path to config.toml")
	cmd.Flags().StringVar(&kind, "kind", "", "fetch only this kind (sandbox.image or sandbox.native_files)")
	return cmd
}
