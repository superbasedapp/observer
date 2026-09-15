package orgclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/update"
)

// updateRail names this rail in a cross-rail key-identity refusal, beside
// routingPolicyRail and announcementRail in orgpin.go. One org has ONE
// distribution identity; naming the rail is the one thing an operator needs
// in order to act on a disagreement.
const updateRail = "update"

// agentTooOldMessage renders a 426 refusal for the node's own operator.
//
// The server sends orgcontract.AgentTooOldBody, a SUPERSET of the standard
// {error, message} shape, so this reads the typed fields when they are there
// and falls back to serverError's generic rendering when they are not — a
// server that answers 426 for some other reason still produces a usable line
// rather than an empty one.
//
// The message names BOTH versions on purpose: the developer reading it in
// `observer status` or on the dashboard banner is not the admin who set the
// floor, and "426" tells them nothing they can act on.
// AgentTooOldRefusal is the last 426 this client received, if any.
//
// IN-MEMORY on purpose, the updateCache posture: it describes a live condition
// (the org's floor versus the running binary), and a restart re-learns it on
// the very next push cycle. Persisting it would risk showing a stale "you are
// too old" banner on a node that has since been updated.
type AgentTooOldRefusal struct {
	// Message is the operator-facing line, naming both versions.
	Message string
	// MinVersion is what the org requires; YourVersion is what this node
	// reported. Both are echoed so a surface can render them separately.
	MinVersion  string
	YourVersion string
	At          time.Time
}

// noteAgentTooOld records a 426 refusal.
func (c *Client) noteAgentTooOld(body []byte, status int) string {
	msg := agentTooOldMessage(body, status)
	var b orgcontract.AgentTooOldBody
	_ = json.Unmarshal(body, &b)
	c.updates.mu.Lock()
	c.updates.refusal = &AgentTooOldRefusal{
		Message:     msg,
		MinVersion:  strings.TrimSpace(b.MinVersion),
		YourVersion: strings.TrimSpace(b.YourVersion),
		At:          time.Now().UTC(),
	}
	c.updates.mu.Unlock()
	return msg
}

// clearAgentTooOld forgets a refusal. Called on every ACCEPTED push, so the
// banner disappears the moment the node is updated rather than needing a
// restart or a dismissal.
func (c *Client) clearAgentTooOld() {
	c.updates.mu.Lock()
	c.updates.refusal = nil
	c.updates.mu.Unlock()
}

// AgentTooOld reports the last min-version refusal, or nil.
func (c *Client) AgentTooOld() *AgentTooOldRefusal {
	if c == nil {
		return nil
	}
	c.updates.mu.Lock()
	defer c.updates.mu.Unlock()
	return c.updates.refusal
}

func agentTooOldMessage(body []byte, status int) string {
	var b orgcontract.AgentTooOldBody
	if err := json.Unmarshal(body, &b); err == nil && b.Reason == update.RefusalReasonAgentTooOld {
		your := strings.TrimSpace(b.YourVersion)
		if your == "" {
			your = "unknown"
		}
		msg := fmt.Sprintf("your org requires observer %s or newer; this node reports %s",
			strings.TrimSpace(b.MinVersion), your)
		if m := strings.TrimSpace(b.Message); m != "" {
			return msg + " (" + m + ")"
		}
		return msg
	}
	return serverError(body, status)
}

// markUpdateChannelPendingAfterRefusal arms a manifest fetch after a 426.
//
// THE STRANDING THIS CLOSES. Under [server].min_agent_version_action =
// "refuse", a node below the floor is answered 426 and NOTHING else happens on
// that cycle: no nudge is read, no manifest is fetched, no update is applied.
// The one mechanism that could lift the node over the floor was gated behind
// the push the floor refuses, so a binary-installed auto-apply node re-POSTed
// forever and never updated itself. That is the opposite of what refusal is
// for.
//
// Marking the channel pending costs one small authenticated GET per push
// cycle on a refused node — and only on a refused node — while the fetch's own
// "already current" check makes it a no-op the moment there is nothing new.
// The server's own half (update_versions on the 426 body) is the better
// signal; this is the half that works even against a server too old to send
// it.
func (c *Client) markUpdateChannelPendingAfterRefusal(ctx context.Context) {
	ch := update.ChannelStable
	if row, err := c.store.LoadUpdateState(ctx); err == nil && update.KnownChannel(row.Channel) {
		ch = row.Channel
	}
	c.updates.mu.Lock()
	defer c.updates.mu.Unlock()
	if c.updates.pending == nil {
		c.updates.pending = map[update.Channel]struct{}{}
	}
	c.updates.pending[ch] = struct{}{}
}

// updateCache is the node's memory of the manifest rail, held on the Client.
//
// It is IN-MEMORY in W2 and that is a deliberate, bounded gap. The durable
// home is agent migration 105's update_state (W3); until it exists, a daemon
// restart resets LastManifestVersion to 0. That is SAFE, not merely tolerable:
// rule 6 (replay) is the only rule that reads it, so a reset can at worst make
// the node re-accept the manifest it already holds. It can never accept an
// OLDER version, because rule 7 compares the manifest's version against the
// INSTALLED binary, which no restart changes.
type updateCache struct {
	mu sync.Mutex
	// lastAccepted is the highest manifest_version accepted, per channel.
	lastAccepted map[string]int64
	// pending is the set of channels the last push acknowledgment reported
	// the server AHEAD on. PushOnce computes it (it is the only place that
	// holds the response body); PushLoop drains it. Keeping the computation
	// and the fetch on opposite sides of this field is what keeps PushOnce
	// free of an outbound call of its own.
	pending map[update.Channel]struct{}
	// refusal is the last 426 the push rail received (W5 skew enforcement),
	// or nil. Cleared on every accepted push, so the node dashboard's banner
	// disappears the moment an update fixes the condition.
	refusal *AgentTooOldRefusal
	// manifest is the most recently verified manifest, for `observer update
	// status` and the dashboard card to read.
	manifest update.Manifest
	// artifact is the row selected for this platform on that manifest.
	artifact update.Artifact
	// state is the posture the last verification produced.
	state  update.State
	reason update.Reason
	// keyID is the org distribution key this rail has seen, so a CHANGED key
	// is refused rather than TOFU-accepted on a later fetch.
	keyID string
}

// FetchOrgUpdateManifest pulls the org's signed update manifest over the
// enrolment credential and verifies it with internal/update's own nine-rule
// table (§3.2), then caches the outcome node-side.
//
// The discipline mirrors FetchOrgAnnouncement by design, down to the refusal
// wording, because it is the same rail shape: a signed document, fetched on
// the push cycle the node ALREADY runs, on the connection it already makes,
// to the server it is already enrolled with. That is the whole reason this
// costs no new egress class (§2.1, acceptance 3) — a new timer or a new host
// would not be.
//
// What is verified, and by whom: EVERY trust decision is made by
// update.Verify, which is pure and lives on the node. This function does
// transport and caching only. In particular the SIGNED bytes decide the
// signing message's manifest_version, so an envelope field an attacker could
// edit independently is never load-bearing.
//
// Nothing is sent about the node: this is a GET, and there is no
// acknowledgment wire. The node's own posture rides the push envelope
// (orgcontract.UpdatePostureRow), composed elsewhere.
//
// Returns (false, nil) when nothing is published, when the cache is already
// current, or when a rule 1-5 failure means the document is IGNORED — notify
// is fail-open (§2.4), so a manifest that cannot be decoded, verified or
// parsed produces no banner and no state change, never an error an operator
// must clear. Returns (true, nil) when a new manifest was accepted or when a
// rule 6-9 outcome changed the posture this node reports (blocked,
// stale_manifest), because those are facts an admin needs on the board.
func (c *Client) FetchOrgUpdateManifest(ctx context.Context, channel update.Channel) (bool, error) {
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return false, fmt.Errorf("orgclient.FetchOrgUpdateManifest: enrolment: %w", err)
	}
	if enr == nil {
		return false, ErrNotEnrolled
	}
	if channel == "" {
		channel = update.ChannelStable
	}
	bearer, err := c.bearers.LoadBearer()
	if err != nil {
		return false, fmt.Errorf("orgclient.FetchOrgUpdateManifest: bearer: %w", err)
	}
	url := strings.TrimRight(enr.OrgServerURL, "/") + "/api/agent/update/manifest?channel=" + string(channel)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := c.httpClient.Do(req)
	c.noteRenewalFromResponse(RenewalPathOther, resp, err)
	if err != nil {
		return false, fmt.Errorf("orgclient.FetchOrgUpdateManifest: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		// Nothing published — and also what a PRE-FEATURE server answers,
		// which is exactly the compat shape acceptance 4 requires: a new agent
		// against an old server stays idle and behaves byte-identically to
		// today.
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("orgclient.FetchOrgUpdateManifest: server returned %d", resp.StatusCode)
	}
	var env update.Envelope
	if err := orgcontract.DecodeCapped(resp.Body, maxOrgDocBytes, &env); err != nil {
		return false, fmt.Errorf("orgclient.FetchOrgUpdateManifest: decode: %w", err)
	}

	// ONE org distribution identity across rails (orgpin.go). A first manifest
	// on a long-enrolled node must present the key the routing or announcement
	// rail already pinned, not merely SOME key — without this, the very first
	// update fetch would be a fresh TOFU a network attacker could win.
	if err := c.checkOrgKeyIdentity(ctx, updateRail, env.KeyID); err != nil {
		return false, fmt.Errorf("orgclient.FetchOrgUpdateManifest: %w", err)
	}
	pinned, lastAccepted, err := c.updatePins(ctx, channel, env.KeyID)
	if err != nil {
		return false, err
	}

	goos, goarch := update.CurrentPlatform()
	res, verr := update.Verify(update.VerifyInput{
		Envelope:                    env,
		PinnedKeyID:                 pinned,
		PinnedPublicKey:             env.KeyID,
		InstalledVersion:            c.agentVersion,
		LastAcceptedManifestVersion: lastAccepted,
		AllowDowngrade:              false,
		Now:                         time.Now().UTC(),
		GOOS:                        goos, GOARCH: goarch,
	})
	if verr != nil {
		return c.recordUpdateOutcome(ctx, channel, env, res, verr)
	}
	return c.recordUpdateOutcome(ctx, channel, env, res, nil)
}

// updatePins returns the key this rail should verify against and the highest
// manifest_version already accepted on the channel.
//
// The key argument is what the SERVER offered. It becomes the pin only on a
// genuinely first sight; once this rail has seen a key, a CHANGED key is
// refused loudly here — the same class of refusal FetchOrgAnnouncement makes,
// with the same remedy (re-enrol to rotate trust).
func (c *Client) updatePins(ctx context.Context, channel update.Channel, offered string) (pinnedKeyID string, lastAccepted int64, err error) {
	c.updates.mu.Lock()
	defer c.updates.mu.Unlock()
	if c.updates.keyID != "" && c.updates.keyID != offered {
		return "", 0, fmt.Errorf("server update-manifest key CHANGED (pinned %s…, got %s…) — refusing; re-enrol to rotate trust",
			prefix8(c.updates.keyID), prefix8(offered))
	}
	if c.updates.lastAccepted == nil {
		c.updates.lastAccepted = map[string]int64{}
	}
	// Cross-rail pins are authoritative when this rail has none of its own:
	// checkOrgKeyIdentity has already refused a disagreement, so whatever it
	// let through IS the org's one identity.
	pinnedKeyID = c.updates.keyID
	if pinnedKeyID == "" {
		pins, perr := c.loadRailPins(ctx)
		if perr == nil {
			for _, p := range pins {
				pinnedKeyID = p.key
				break
			}
		}
	}
	lastAccepted = c.updates.lastAccepted[string(channel)]
	if lastAccepted == 0 {
		// The DURABLE half of rule 6's replay memory (§3.4's
		// last_manifest_version). Without it a restart reset the counter and
		// the node re-accepted the manifest it already held on every boot —
		// safe, but not the durable protection migration 105 promised. The
		// in-memory value still wins when it is ahead: it is this process's
		// own record of what it accepted this run.
		if row, rerr := c.store.LoadUpdateState(ctx); rerr == nil &&
			(row.Channel == "" || row.Channel == channel) {
			lastAccepted = row.LastManifestVersion
		}
	}
	return pinnedKeyID, lastAccepted, nil
}

// recordUpdateOutcome caches a verification result and reports whether the
// node's posture changed.
//
// Failure direction follows §2.4 exactly: rules 1-5 leave the result in
// StateIdle, which this treats as "ignore the document" — no cache write, no
// posture change, nothing to clear. Rules 6-9 return a real posture
// (blocked{...} / stale_manifest) and those ARE recorded, because they are
// facts the org board must show: "this fleet needs MDM" and "this fleet is
// unfreshened" are answers, not errors.
func (c *Client) recordUpdateOutcome(ctx context.Context, channel update.Channel, env update.Envelope, res update.VerifyResult, verr error) (bool, error) {
	c.updates.mu.Lock()
	if c.updates.lastAccepted == nil {
		c.updates.lastAccepted = map[string]int64{}
	}
	if verr != nil {
		if res.State == update.StateIdle {
			// Fail-OPEN: unreadable, unverifiable or unknown-schema documents
			// change nothing. Logged at debug, not warn — an operator has
			// nothing to do about a document their node correctly ignored.
			c.updates.mu.Unlock()
			c.logger.Debug("org update manifest ignored", "rule", res.Rule, "err", verr)
			return false, nil
		}
		changed := c.updates.state != res.State || c.updates.reason != res.Reason
		c.updates.state, c.updates.reason = res.State, res.Reason
		c.updates.manifest, c.updates.artifact = res.Manifest, res.Artifact
		if c.updates.keyID == "" {
			c.updates.keyID = env.KeyID
		}
		c.updates.mu.Unlock()
		c.logger.Info("org update manifest not applicable", "rule", res.Rule,
			"state", res.State, "reason", res.Reason)
		// A rule 6-9 outcome IS a posture the org board and the node's own
		// card must show, so it is written durably too — but WITHOUT the
		// document: an expired or replayed manifest must not become the
		// bytes a later `observer update apply` runs from.
		c.persistUpdateOutcome(ctx, channel, res, "", verr.Error())
		return changed, nil
	}
	if c.updates.keyID == "" {
		c.updates.keyID = env.KeyID
	}
	if prev := c.updates.lastAccepted[string(channel)]; prev >= res.Manifest.ManifestVersion {
		c.updates.mu.Unlock()
		return false, nil // already current
	}
	c.updates.lastAccepted[string(channel)] = res.Manifest.ManifestVersion
	c.updates.manifest, c.updates.artifact = res.Manifest, res.Artifact
	c.updates.state, c.updates.reason = res.State, res.Reason
	c.updates.mu.Unlock()
	c.logger.Info("org update manifest accepted",
		"channel", channel, "manifest_version", res.Manifest.ManifestVersion,
		"version", res.Manifest.Version, "state", res.State)
	// The DURABLE half (§3.4). Without this the verified manifest lived in
	// this process's memory only: a notify-only node — the BYO default, and
	// the majority of any fleet — showed `idle` with no target on its Health
	// card, no banner, an idle row on the org board, and
	// `observer update apply` with the daemon stopped refused with "this node
	// holds no accepted manifest". The canonical bytes are the ORG's own
	// signed document coming back, never node data going out.
	c.persistUpdateOutcome(ctx, channel, res, canonicalManifestBytes(env), "manifest verified and accepted")
	return true, nil
}

// canonicalManifestBytes recovers the exact signed bytes from the envelope.
//
// The SIGNED bytes are what a later apply must run from, so the string stored
// is the one the signature covered — never a re-marshal of the decoded struct,
// which any encoder difference would make a different document.
func canonicalManifestBytes(env update.Envelope) string {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(env.ManifestB64))
	if err != nil {
		return ""
	}
	return string(raw)
}

// persistUpdateOutcome writes one verification outcome through the ONE store
// seam (internal/store/update.go).
//
// Best-effort by construction: notify is fail-open (§2.4), so a node that
// cannot write its own state still keeps working and still holds the outcome
// in memory for this process's lifetime. A failure is logged, never returned.
func (c *Client) persistUpdateOutcome(ctx context.Context, channel update.Channel, res update.VerifyResult, manifestJSON, detail string) {
	if c.store == nil || res.Manifest.ManifestVersion <= 0 || !update.KnownState(res.State) {
		return
	}
	if err := c.store.SaveVerifiedManifest(ctx, store.VerifiedManifest{
		Channel:         channel,
		ManifestVersion: res.Manifest.ManifestVersion,
		TargetVersion:   res.Manifest.Version,
		ManifestJSON:    manifestJSON,
		State:           res.State,
		Reason:          res.Reason,
		SeenAt:          time.Now().UTC(),
		Detail:          detail,
	}); err != nil {
		c.logger.Warn("org update manifest could not be recorded on this node", "channel", channel, "err", err)
	}
}

// UpdateStatus is what `observer update status` and the dashboard card read
// from the daemon: the last verified manifest and the posture it produced.
type UpdateStatus struct {
	Channel         update.Channel
	ManifestVersion int64
	Version         string
	State           update.State
	Reason          update.Reason
	Notes           string
	NotesURL        string
	EOSAt           string
	Artifact        update.Artifact
}

// UpdateStatus returns the cached manifest posture. It reads memory only and
// makes no network call, which is what lets a status surface be honest on an
// air-gapped or offline node.
func (c *Client) UpdateStatus() UpdateStatus {
	c.updates.mu.Lock()
	defer c.updates.mu.Unlock()
	st := UpdateStatus{
		Channel:         c.updates.manifest.Channel,
		ManifestVersion: c.updates.manifest.ManifestVersion,
		Version:         c.updates.manifest.Version,
		State:           c.updates.state,
		Reason:          c.updates.reason,
		Notes:           c.updates.manifest.Notes,
		NotesURL:        c.updates.manifest.NotesURL,
		EOSAt:           c.updates.manifest.EOSAt,
		Artifact:        c.updates.artifact,
	}
	if st.State == "" {
		st.State = update.StateIdle
	}
	return st
}

// noteUpdateNudge is the receiving half of the push-ack update nudge
// (§3.5; see orgcontract.PushResponse.UpdateVersions).
//
// It decodes the version map from the RAW push response — the same raw-body
// pattern maybeApplyGrantReplacement and maybeKickPolicyResourceFetch use, so
// no generated-client regeneration — and returns the channels whose published
// version is AHEAD of what this node has accepted.
//
// The nudge carries no document and forces nothing: every gate the fetch
// applies (the size cap, the cross-rail key agreement, the nine verify rules)
// is unchanged. And because it only reports channels the server is ahead on,
// a fleet with nothing published makes ZERO extra requests — the steady-state
// property acceptance 3 asserts.
func (c *Client) noteUpdateNudge(body []byte) {
	var ack struct {
		UpdateVersions map[string]int64 `json:"update_versions"`
	}
	if err := json.Unmarshal(body, &ack); err != nil || len(ack.UpdateVersions) == 0 {
		return
	}
	c.updates.mu.Lock()
	defer c.updates.mu.Unlock()
	for name, v := range ack.UpdateVersions {
		ch := update.Channel(name)
		// An unknown channel is IGNORED rather than fetched: the vocabulary is
		// closed, and a future channel reaching an older agent is forward
		// compatibility working, not an error.
		if !update.KnownChannel(ch) {
			continue
		}
		if v <= c.updates.lastAccepted[name] {
			continue
		}
		if c.updates.pending == nil {
			c.updates.pending = map[update.Channel]struct{}{}
		}
		c.updates.pending[ch] = struct{}{}
	}
}

// takePendingUpdateChannels drains the nudge set.
func (c *Client) takePendingUpdateChannels() []update.Channel {
	c.updates.mu.Lock()
	defer c.updates.mu.Unlock()
	if len(c.updates.pending) == 0 {
		return nil
	}
	out := make([]update.Channel, 0, len(c.updates.pending))
	for ch := range c.updates.pending {
		out = append(out, ch)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	c.updates.pending = nil
	return out
}

// FetchPendingUpdateManifests fetches the manifest for every channel the last
// push acknowledgment said the server is ahead on. It is the ONE call
// PushLoop makes, so the "never fetch unless the server is ahead" rule lives
// in one place rather than at each call site — and so a fleet with nothing
// published performs no request here at all.
//
// A failure never propagates: an update fetch must not affect push health.
func (c *Client) FetchPendingUpdateManifests(ctx context.Context) {
	for _, ch := range c.takePendingUpdateChannels() {
		if _, err := c.FetchOrgUpdateManifest(ctx, ch); err != nil && !errors.Is(err, ErrNotEnrolled) {
			c.logger.Warn("org update manifest fetch failed", "channel", ch, "err", err)
		}
	}
}

// DownloadUpdateArtifact streams one artifact from the ORG MIRROR to dst.
//
// This is the ONLY place a node fetches update bytes, and the host is the org
// server it is already enrolled with — never GitHub, never npm, never a CDN
// (ruling R8). That is what makes the design air-gap-NATIVE rather than
// air-gap-capable, and what keeps CLAUDE.md's "no network calls in the
// observer/watcher" claim true with exactly one documented exception host.
//
// maxBytes is a HARD ceiling applied to the stream itself, not a check on a
// Content-Length the server chose: TUF's endless-data defence only works if
// the reader stops, so a response that exceeds it is aborted mid-flight and
// the partial bytes are the caller's to discard.
func (c *Client) DownloadUpdateArtifact(ctx context.Context, version, filename string, dst io.Writer, maxBytes int64) error {
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return fmt.Errorf("orgclient.DownloadUpdateArtifact: enrolment: %w", err)
	}
	if enr == nil {
		return ErrNotEnrolled
	}
	// The two path segments are composed by this node from a SIGNED manifest,
	// but they are still checked: a traversal here would turn a manifest into
	// a read of the server's own filesystem.
	if strings.ContainsAny(version, `/\`) || strings.ContainsAny(filename, `/\`) ||
		strings.Contains(version, "..") || strings.Contains(filename, "..") {
		return fmt.Errorf("orgclient.DownloadUpdateArtifact: refusing a path-bearing version/filename")
	}
	bearer, err := c.bearers.LoadBearer()
	if err != nil {
		return fmt.Errorf("orgclient.DownloadUpdateArtifact: bearer: %w", err)
	}
	url := strings.TrimRight(enr.OrgServerURL, "/") +
		"/api/agent/update/artifact/" + neturl.PathEscape(version) + "/" + neturl.PathEscape(filename)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := c.httpClient.Do(req)
	c.noteRenewalFromResponse(RenewalPathOther, resp, err)
	if err != nil {
		return fmt.Errorf("orgclient.DownloadUpdateArtifact: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("orgclient.DownloadUpdateArtifact: server returned %d", resp.StatusCode)
	}
	var reader io.Reader = resp.Body
	if maxBytes > 0 {
		reader = io.LimitReader(resp.Body, maxBytes+1)
	}
	n, err := io.Copy(dst, reader)
	if err != nil {
		return fmt.Errorf("orgclient.DownloadUpdateArtifact: %w", err)
	}
	if maxBytes > 0 && n > maxBytes {
		return fmt.Errorf("orgclient.DownloadUpdateArtifact: the artifact exceeded its declared %d-byte size", maxBytes)
	}
	return nil
}

// ShareOptions exposes the node's resolved push-share posture.
//
// It exists for ONE caller: the update wiring, which needs to know whether
// this node is admin-managed or enterprise-granted in order to resolve
// [update].auto_apply's DEFAULT (§3.9). Those two facts are not both in the
// TOML — EnterpriseGranted arrives on the runtime enrolment grant — so a
// caller that read the config alone would silently answer "BYO" for half the
// managed fleet. Resolving it through the SAME accessor the push seam uses is
// what keeps the two from disagreeing.
func (c *Client) ShareOptions() store.ShareOptions { return c.shareOptions() }
