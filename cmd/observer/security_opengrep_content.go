//go:build !sbo_omit_security && !sbo_omit_security_scan_opengrep

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/secengine"
	"github.com/marmutapp/superbased-observer/internal/secrulepack"
	"github.com/marmutapp/superbased-observer/internal/secscan/opengrep/opengrepnet"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// security_opengrep_content.go brings the code rules' two content kinds,
// security.rule_pack and security.engine, from the vendor's signed feed (an
// individual node) or the org mirror (a managed node whose managed pull
// names it) into the code rules' content store, through the signed content
// channel with its signature, rollback, epoch and expiry rules unchanged
// (security pillar plan section 8.5, lane SEC-G2 milestone 2). The newest
// verified pack wins over the embedded floor (loadCodePack); an outage
// keeps the last-known-good, which every surface then shows with its
// freshness and the failed fetch, never as current.
//
// An engine manifest pins a binary, and the channel installs a manifest
// only with the bytes of its entry for this platform. So a feed engine
// manifest whose pin is the installed binary is installed at once (with a
// copy of that binary); one that pins a binary not installed yet is kept
// as PENDING, re-verified on every read, and shown by the install plan; it
// is installed together with the binary, after the developer's consent for
// that pin (acceptPendingEngine).

// codeEnginePendingFile holds a verified, not yet installed engine envelope
// beside the content store's kind directories.
const codeEnginePendingFile = "security.engine.pending.json"

// codeFetchFile records each kind's last fetch (security directory).
const codeFetchFile = "code-content-fetch.json"

// codeFeedClient is the feed download of the egress lane (a test seam).
type codeFeedClient interface {
	FetchFeedFile(ctx context.Context, kind, file string, limit int64) ([]byte, error)
}

// codeFeedNet returns the feed client; tests swap it.
var codeFeedNet = func() codeFeedClient { return opengrepnet.New(opengrepnet.Options{}) }

// codeContentEngineInstalled reports whether an engine is installed, the
// feed fetch's precondition (P-061); tests swap it.
var codeContentEngineInstalled = codeEngineInstalled

// codeFetch is one kind's last fetch.
type codeFetch struct {
	At     time.Time `json:"at"`
	Source string    `json:"source"`
	Error  string    `json:"error,omitempty"`
}

func codeFetchPath(secDir string) string { return filepath.Join(secDir, codeFetchFile) }

// readCodeFetch reads the fetch record; missing or unreadable is empty.
func readCodeFetch(secDir string) map[string]codeFetch {
	out := map[string]codeFetch{}
	if b, err := readCappedFile(codeFetchPath(secDir), 16<<10); err == nil {
		_ = json.Unmarshal(b, &out)
	}
	return out
}

// recordCodeFetch records the outcome of each kind's fetch from source.
func recordCodeFetch(secDir string, kinds []content.Kind, source string, err error) {
	m := readCodeFetch(secDir)
	for _, k := range kinds {
		f := codeFetch{At: time.Now().UTC(), Source: source}
		if err != nil {
			f.Error = err.Error()
			if len(f.Error) > 300 {
				f.Error = f.Error[:300]
			}
		}
		m[string(k)] = f
	}
	if b, merr := json.Marshal(m); merr == nil {
		_ = writeCodeFile(codeFetchPath(secDir), b)
	}
}

// pendingPath is the pending engine envelope's path.
func (e *codeEnv) pendingPath() string {
	return filepath.Join(e.secDir, codeRulesContentDir, codeEnginePendingFile)
}

// pendingEnvelope returns the pending envelope re-verified now against the
// accepted high-water mark, nil when there is none, it does not verify, or
// this is a managed node (the public feed never reaches one).
func (e *codeEnv) pendingEnvelope() ([]byte, *content.Manifest) {
	if e.managed {
		return nil, nil
	}
	env, err := readCappedFile(e.pendingPath(), content.MaxEnvelopeBytes)
	if err != nil {
		return nil, nil
	}
	cs := codeRulesStore(e.resolved)
	st, err := cs.State(content.Engine)
	if err != nil {
		return nil, nil
	}
	res, err := content.Verify(content.VerifyInput{
		Envelope: env, Kind: content.Engine, VendorKeys: codeRulesTrust().VendorKeys,
		Accepted: st.Accepted, Now: time.Now(),
	})
	if err != nil || (st.Accepted != nil && res.Hash == st.Accepted.ManifestHash) {
		return nil, nil
	}
	return env, &res.Manifest
}

// pendingEngine is the pending manifest's pins, nil when none.
func (e *codeEnv) pendingEngine() *secengine.ManifestPins {
	_, m := e.pendingEnvelope()
	if m == nil {
		return nil
	}
	mp, err := secengine.FromManifest(*m)
	if err != nil {
		return nil
	}
	return &mp
}

// acceptPendingEngine installs the pending engine manifest together with
// the downloaded binary (file) its entry pins, when the plan's pin came
// from it; the channel checks the bytes against the entry again.
func (e *codeEnv) acceptPendingEngine(plan secengine.InstallPlan, file string) error {
	if plan.PinFrom != secengine.PinFromPending {
		return nil
	}
	env, _ := e.pendingEnvelope()
	if env == nil {
		return errors.New("the pending engine manifest no longer verifies; nothing was installed")
	}
	cs := codeRulesStore(e.resolved)
	if err := os.MkdirAll(cs.Root, 0o700); err != nil {
		return err
	}
	cp, _, _, err := copyHashed(file, cs.Root, plan.CapBytes)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(cp) }()
	if _, err := cs.InstallFiles(content.Engine, env, map[string]string{plan.Pin.Asset: cp}, codeRulesTrust()); err != nil {
		return fmt.Errorf("the engine manifest was refused: %w", err)
	}
	_ = os.Remove(e.pendingPath())
	e.manifest = loadEngineManifest(cs, codeRulesTrust())
	return nil
}

// codeRefreshReport is one content refresh.
type codeRefreshReport struct {
	Source string
	// Pack and Engine are each kind's outcome in plain words.
	Pack, Engine string
	Err          error
}

// refreshCodeContent fetches both kinds from the source this node may use:
// the org mirror on a managed node whose managed pull names it, the vendor
// feed on an individual node whose [security.scan.opengrep] feed is on and
// that has an engine installed (P-061), nothing otherwise. Any failure
// keeps the last-known-good.
func (e *codeEnv) refreshCodeContent(ctx context.Context) codeRefreshReport {
	cs := codeRulesStore(e.resolved)
	if e.managed {
		rep := codeRefreshReport{Source: "org_mirror"}
		if e.st == nil || !codeMirrorNamedFor(ctx, e.cfg, e.st) {
			rep.Pack, rep.Engine = "not fetched: the managed pull does not name the org mirror", "not fetched"
			return rep
		}
		kinds := []content.Kind{content.RulePack}
		// The engine kind carries the binary itself: fetch it only once an
		// engine is installed (an update or a revocation), never unasked.
		if _, ok := readCodeInstallState(e.secDir); ok {
			kinds = append(kinds, content.Engine)
		}
		rep.Err = e.fetchMirror(ctx, cs, kinds)
		e.reloadContent(cs)
		rep.Pack, rep.Engine = "fetched from the org mirror", "fetched from the org mirror"
		if len(kinds) == 1 {
			rep.Engine = "not fetched: no engine is installed"
		}
		if rep.Err == nil && len(kinds) == 2 {
			// A new pin from the mirror replaces the installed engine; a
			// managed node asks no consent.
			if p := secengine.PlanInstall(e.installInput(ctx)); p.Blocked == "" && !p.Installed {
				if _, err := e.installFromMirror(ctx); err != nil {
					rep.Err = err
				} else {
					rep.Engine = "updated from the org mirror to " + p.Pin.Version
				}
			}
		}
		return rep
	}
	rep := codeRefreshReport{Source: "vendor_feed"}
	if !e.cfg.Security.Scan.Opengrep.Feed {
		rep.Pack, rep.Engine = "not fetched: the feed is off", "not fetched: the feed is off"
		return rep
	}
	// Plans decision log P-061: the feed fetch runs only while an engine is
	// installed; with none, nothing is fetched, whatever feed says (the
	// guided install then uses the compiled pins).
	if !codeContentEngineInstalled(ctx, e) {
		rep.Pack, rep.Engine = "not fetched: no Opengrep engine is installed (P-061)", "not fetched: no Opengrep engine is installed (P-061)"
		return rep
	}
	feed := codeFeedNet()
	perr := e.fetchFeedPack(ctx, feed, cs)
	recordCodeFetch(e.secDir, []content.Kind{content.RulePack}, "vendor_feed", perr)
	words, eerr := e.fetchFeedEngine(ctx, feed, cs)
	recordCodeFetch(e.secDir, []content.Kind{content.Engine}, "vendor_feed", eerr)
	e.reloadContent(cs)
	rep.Pack, rep.Engine, rep.Err = "fetched from the vendor feed", words, errors.Join(perr, eerr)
	if perr != nil {
		rep.Pack = "fetch failed; the installed pack stays in use"
	}
	return rep
}

// reloadContent re-reads the pack and the engine manifest after a fetch.
func (e *codeEnv) reloadContent(cs contentchan.Store) {
	if p, err := loadCodePack(cs, codeRulesTrust()); err == nil {
		e.pack = p
	}
	e.manifest = loadEngineManifest(cs, codeRulesTrust())
}

// errCodeNotPublished reads a kind the feed does not publish yet as no
// change, not a fault.
func feedNotPublished(err error) bool { return errors.Is(err, opengrepnet.ErrNotPublished) }

// fetchFeedPack fetches the rule pack's envelope and bundle and installs
// them; a pack that would be set aside at load is refused before install.
func (e *codeEnv) fetchFeedPack(ctx context.Context, feed codeFeedClient, cs contentchan.Store) error {
	env, err := feed.FetchFeedFile(ctx, string(content.RulePack), contentchan.ManifestFile, content.MaxEnvelopeBytes)
	if feedNotPublished(err) {
		return nil
	}
	if err != nil {
		return err
	}
	st, err := cs.State(content.RulePack)
	if err != nil {
		return err
	}
	res, err := content.Verify(content.VerifyInput{Envelope: env, Kind: content.RulePack, VendorKeys: codeRulesTrust().VendorKeys, FeedKeys: codeRulesTrust().FeedKeys, Accepted: st.Accepted, Now: time.Now()})
	if err != nil {
		_, _ = cs.Install(content.RulePack, env, nil, codeRulesTrust()) // records the refusal; keeps last-known-good
		return err
	}
	if st.Accepted != nil && res.Hash == st.Accepted.ManifestHash {
		return nil
	}
	raw, err := feed.FetchFeedFile(ctx, string(content.RulePack), secrulepack.BundleName, secrulepack.MaxBundleBytes)
	if err != nil {
		return err
	}
	if _, err := secrulepack.DecodeBundle(raw); err != nil {
		return err
	}
	_, err = cs.Install(content.RulePack, env, map[string][]byte{secrulepack.BundleName: raw}, codeRulesTrust())
	return err
}

// fetchFeedEngine fetches the engine envelope: installed at once when it
// asks for no bytes on this platform or pins the installed binary, else
// kept pending for the install plan.
func (e *codeEnv) fetchFeedEngine(ctx context.Context, feed codeFeedClient, cs contentchan.Store) (string, error) {
	env, err := feed.FetchFeedFile(ctx, string(content.Engine), contentchan.ManifestFile, content.MaxEnvelopeBytes)
	if feedNotPublished(err) {
		return "not published on the feed yet", nil
	}
	if err != nil {
		return "fetch failed; the installed manifest (or the compiled pins) stay in use", err
	}
	st, err := cs.State(content.Engine)
	if err != nil {
		return "content store unreadable", err
	}
	res, err := content.Verify(content.VerifyInput{Envelope: env, Kind: content.Engine, VendorKeys: codeRulesTrust().VendorKeys, Accepted: st.Accepted, Now: time.Now()})
	if err != nil {
		_, _ = cs.InstallFiles(content.Engine, env, nil, codeRulesTrust()) // records the refusal
		return "refused (" + string(content.ReasonOf(err)) + ")", err
	}
	if st.Accepted != nil && res.Hash == st.Accepted.ManifestHash {
		return "current", nil
	}
	if _, err := secengine.FromManifest(res.Manifest); err != nil {
		return "refused: an entry was not verified the way the pins require", err
	}
	need := platformEntries(res.Manifest)
	files := map[string]string{}
	defer func() {
		for _, cp := range files {
			_ = os.Remove(cp)
		}
	}()
	installed := codeInstalledPath()
	sum := ""
	if installed != "" {
		sum, _, _ = hashRegularFile(installed, secengine.MaxDownloadBytes)
	}
	for _, en := range need {
		if sum == "" || !strings.EqualFold(en.SHA256, sum) {
			// Bytes this node does not hold: keep it pending for the plan.
			if err := writeCodeFile(e.pendingPath(), env); err != nil {
				return "could not keep the manifest", err
			}
			return "a new pin " + en.Version + " waits for your install consent", nil
		}
		if err := os.MkdirAll(cs.Root, 0o700); err != nil {
			return "content store unwritable", err
		}
		cp, _, _, err := copyHashed(installed, cs.Root, en.SizeBytes)
		if err != nil {
			return "could not copy the installed engine", err
		}
		files[en.Name] = cp
	}
	if _, err := cs.InstallFiles(content.Engine, env, files, codeRulesTrust()); err != nil {
		return "refused (" + string(content.ReasonOf(err)) + ")", err
	}
	_ = os.Remove(e.pendingPath())
	return "installed (manifest version " + fmt.Sprint(res.Manifest.ManifestVersion) + ")", nil
}

// platformEntries are the manifest's entries the channel needs bytes for
// on this platform (not revoked).
func platformEntries(m content.Manifest) []content.Entry {
	var out []content.Entry
	for _, en := range m.Entries {
		if (en.OS != "" && en.OS != runtime.GOOS) || (en.Arch != "" && en.Arch != runtime.GOARCH) || content.IsRevoked(m, en.SHA256) {
			continue
		}
		out = append(out, en)
	}
	return out
}
