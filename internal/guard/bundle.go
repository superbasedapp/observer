package guard

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// Org policy-bundle loading (guard spec §14.2, G13). The org layer is
// the same §4.4 TOML policy-file format as the user/project layers,
// but it arrives over the wire Ed25519-signed and is cached locally as
// the verified envelope ([guard.rules].org_bundle, default
// ~/.observer/org-policy-bundle.json). The cache is written ONLY by
// the org client (internal/orgclient.FetchPolicyBundle) after the full
// §14.2 acceptance gate: signature valid AND public key matching the
// hash pinned at enrolment AND version monotonic.
//
// Loading here re-verifies what it cheaply can:
//
//   - The envelope signature is ALWAYS re-checked against the key
//     embedded in the envelope (orgcontract.VerifyPolicyBundle). This
//     is self-contained — no DB, no network — so hook processes pay
//     only a ~64-byte Ed25519 verify on top of the file read, well
//     inside the §6.4 budget. It catches corruption and casual
//     tampering with the cached TOML.
//   - The key PIN is compared only when the composition supplied
//     Options.OrgKeyPinHash (the daemon path; guardwire reads the pin
//     from guard_policy_state). A self-consistent forged cache (new
//     key + matching signature) is caught there, and structurally at
//     the next poll, which re-fetches through the always-pinned wire
//     seam and rewrites the cache. An attacker who can rewrite files
//     under ~/.observer already owns the unsigned user policy and
//     config.toml — the signature's job is the WIRE and the server
//     impersonation case, not the local-root case (the §10.4
//     tamper-EVIDENT honesty framing).
//
// Every failure degrades to local-only policy with a LoadIssue — the
// daemon must never refuse to start over a bad bundle (the org floor
// is a hardening layer, not an availability dependency), and a
// rejected fetch never overwrites a previously good cache.

// parseOrgBundle reads + verifies + parses the cached org bundle
// WITHOUT mutating g — the shared parse/verify half both New and
// ReloadOrgLayer funnel through (B3/§3.2), so a reload verifies
// identically to construction. Returns the parsed layer + its
// PolicyState on success; on any failure it returns loaded=false with a
// human issue string (empty issue = the bundle is simply absent, the
// common non-enrolled case). pinHash is Options.OrgKeyPinHash ("" skips
// the pin check — the hook-process path). The caller decides how to
// record the issue / install the layer, so the function stays pure.
func (g *Guard) parseOrgBundle(path, pinHash string) (pf *policyFile, st PolicyState, issue string, loaded bool) {
	pf, st, issue, _, loaded = g.parseOrgBundleCause(path, pinHash)
	return pf, st, issue, loaded
}

// parseOrgBundleCause is parseOrgBundle that also says what is wrong with
// the file when it does not load (T-889): it could not be read, or it was
// read and did not verify. An absent file is no issue at all here; the
// caller decides whether absence is a deletion (bundleCauseMissing).
func (g *Guard) parseOrgBundleCause(path, pinHash string) (pf *policyFile, st PolicyState, issue string, cause orgBundleCause, loaded bool) {
	raw, err := g.readFile(path)
	switch {
	case os.IsNotExist(err):
		return nil, PolicyState{}, "", bundleCauseRejected, false // not enrolled / no bundle published: the common case
	case err != nil:
		return nil, PolicyState{}, fmt.Sprintf("org bundle %s: %v", path, err), bundleCauseUnreadable, false
	}
	pf, st, issue, loaded = parseOrgBundleBytes(raw, path, pinHash)
	return pf, st, issue, bundleCauseRejected, loaded
}

// parseOrgBundleBytes is parseOrgBundle over envelope bytes the caller
// already holds: the cached file, or the daemon's last verified copy from the
// MAC'd org lock (T-844). The same signature, pin and TOML checks apply to
// both, so a last verified copy is never trusted more than the file was.
//
// The issue says only what is wrong with the bytes. What the guard enforces
// instead depends on the caller's state, so each caller appends that half
// through orgLayerOutcome (T-877).
func parseOrgBundleBytes(raw []byte, path, pinHash string) (pf *policyFile, st PolicyState, issue string, loaded bool) {
	var b orgcontract.PolicyBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, PolicyState{}, fmt.Sprintf("org bundle %s: not a bundle envelope: %v", path, err), false
	}
	pub, err := orgcontract.VerifyPolicyBundle(b)
	if err != nil {
		return nil, PolicyState{}, fmt.Sprintf("org bundle %s rejected: %v", path, err), false
	}
	if pinHash != "" && orgcontract.PublicKeyPinHash(pub) != pinHash {
		return nil, PolicyState{}, fmt.Sprintf("org bundle %s rejected: signing key does not match the enrolment pin", path), false
	}
	parsed, perr := parsePolicyFile([]byte(b.BundleTOML), layerOrg)
	if perr != nil {
		return nil, PolicyState{}, fmt.Sprintf("org bundle %s (version %d): %v", path, b.Version, perr), false
	}
	st = PolicyState{
		Layer:       layerOrg,
		Path:        path,
		Version:     strconv.FormatInt(b.Version, 10),
		ContentHash: sha256hex([]byte(b.BundleTOML)),
		Notes:       orgParseNotes(parsed.notes),
	}
	parsed.envelope = append([]byte(nil), raw...)
	return parsed, st, "", true
}

// loadOrgLayer is the ONE org-layer load New and ReloadOrgLayer share
// (T-844): the cached bundle at path, and, when that file exists but no
// longer verifies, the daemon's last verified copy (lastVerified, from the
// MAC'd org lock), re-checked under the same pin. lkg reports that the layer
// came from the copy; issue still names the rejected file, so every status
// surface says the cache was tampered with.
//
// missingIsTamper (T-864 gap 1) makes a MISSING file a tamper like an edited
// one: this node accepted a verified bundle before and the org lock reaches
// every rule here (a managed node), so a deletion falls back to the last
// verified copy, and with none the caller fails closed. On an individual node
// it is false and a missing file stays "no org layer", as before.
func (g *Guard) loadOrgLayer(path, pinHash string, lastVerified []byte, missingIsTamper bool) (pf *policyFile, st PolicyState, issue string, cause orgBundleCause, loaded, lkg bool) {
	pf, st, issue, cause, loaded = g.parseOrgBundleCause(path, pinHash)
	if !loaded && issue == "" && missingIsTamper {
		issue, cause = orgBundleMissingIssue(path), bundleCauseMissing
	}
	if loaded || issue == "" {
		return pf, st, issue, cause, loaded, false
	}
	if len(lastVerified) == 0 {
		return nil, PolicyState{}, issue + " - " + g.orgLayerOutcome(""), cause, false, false
	}
	lpf, lst, lissue, lok := parseOrgBundleBytes(lastVerified, path, pinHash)
	if !lok {
		return nil, PolicyState{}, issue + "; the last verified copy did not verify either (" + lissue + ") - " + g.orgLayerOutcome(""), cause, false, false
	}
	out := g.orgLayerOutcomeFor(orgLayerOutcomeInput{enforcing: lst.Version, cause: cause, path: path})
	if out.note != "" {
		lst.Notes = append(lst.Notes, out.note)
	}
	return lpf, lst, issue + " - " + out.text, cause, true, true
}

// orgBundleCause is what is wrong with the cached org bundle file when it does
// not load (T-889). The zero value is the historical reading, "does not
// verify", so a status built before a cause was recorded keeps its wording.
type orgBundleCause int32

const (
	// bundleCauseRejected: the file was read and did not verify (signature,
	// pin, envelope or TOML).
	bundleCauseRejected orgBundleCause = iota
	// bundleCauseMissing: the file is gone on a node that accepted a
	// verified bundle (T-864 gap 1).
	bundleCauseMissing
	// bundleCauseUnreadable: something is at the path but cannot be read (a
	// directory, a file without read permission).
	bundleCauseUnreadable
)

// orgBundleCauseWords say what is wrong with the file, per cause (T-889: a
// deleted bundle's NOTE and status line said "failed verification" / "does
// not verify" next to a LOAD ISSUE that correctly said "missing"). status
// completes "the cached bundle ..."; note completes "org bundle PATH ...".
var orgBundleCauseWords = [...]struct{ status, note string }{
	bundleCauseRejected:   {"does not verify", "failed verification"},
	bundleCauseMissing:    {"is missing", "is missing"},
	bundleCauseUnreadable: {"could not be read", "could not be read"},
}

// words returns the cause's row of orgBundleCauseWords (an unknown cause
// reads as rejected, the historical wording).
func (c orgBundleCause) words() struct{ status, note string } {
	if c < 0 || int(c) >= len(orgBundleCauseWords) {
		return orgBundleCauseWords[bundleCauseRejected]
	}
	return orgBundleCauseWords[c]
}

// orgLayerOutcomeInput is what decides the second half of an org bundle
// issue: what the guard enforces while the cached bundle does not verify.
type orgLayerOutcomeInput struct {
	// enforcing is the version of the verified org layer in force: the last
	// verified copy from the org lock, or the layer the running guard loaded
	// before the file changed ("" = none).
	enforcing string
	// locksEveryRule: the org lock reaches every rule here (a managed node,
	// or a process whose tenancy is unresolved).
	locksEveryRule bool
	// cause and path name what is wrong with which file, for the NOTE a
	// row adds to the layer in force (T-889).
	cause orgBundleCause
	path  string
}

// layerOutcome is one row's rendering: text completes the LOAD ISSUE
// ("... - TEXT"), note is the NOTE the layer in force carries ("" = none).
type layerOutcome struct {
	text, note string
}

// orgLayerOutcomeRows say what is true in each state (T-877, guard tamper
// re-test 2026-10-17: the event and `observer guard status` said "running
// without the org layer" while the node enforced the last verified layer).
// The note column (T-889) is the NOTE line of the layer in force, worded by
// the actual cause. Walked top-down, first match wins (CLAUDE.md rule 5).
var orgLayerOutcomeRows = []struct {
	applies func(in orgLayerOutcomeInput) bool
	text    func(in orgLayerOutcomeInput) string
	note    func(in orgLayerOutcomeInput) string
}{
	// A verified org layer is still in force.
	{
		func(in orgLayerOutcomeInput) bool { return in.enforcing != "" },
		func(in orgLayerOutcomeInput) string {
			return "enforcing the last verified org layer (version " + in.enforcing + ")"
		},
		func(in orgLayerOutcomeInput) string {
			return "org bundle " + in.path + " " + in.cause.words().note +
				"; enforcing the last verified org layer (version " + in.enforcing + ") until the organization's next accepted bundle"
		},
	},
	// No verified layer on a node the organization holds: locked down.
	{
		func(in orgLayerOutcomeInput) bool { return in.locksEveryRule },
		func(orgLayerOutcomeInput) string {
			return "no verified org layer is available, so local approvals are refused for every rule until a verified bundle is back"
		},
		nil,
	},
	// An individual node: the org layer is a floor the developer may drop.
	{
		func(orgLayerOutcomeInput) bool { return true },
		func(orgLayerOutcomeInput) string { return "running without the org layer" },
		nil,
	},
}

// orgLayerOutcomeFor walks orgLayerOutcomeRows for in, filling in the lock
// reach from this guard.
func (g *Guard) orgLayerOutcomeFor(in orgLayerOutcomeInput) layerOutcome {
	in.locksEveryRule = g.orgLocksEveryRule()
	for _, row := range orgLayerOutcomeRows {
		if !row.applies(in) {
			continue
		}
		out := layerOutcome{text: row.text(in)}
		if row.note != nil {
			out.note = row.note(in)
		}
		return out
	}
	return layerOutcome{}
}

// orgLayerOutcome renders what this guard enforces while the cached org
// bundle does not verify; enforcing is the version of the verified org layer
// in force ("" = none).
func (g *Guard) orgLayerOutcome(enforcing string) string {
	return g.orgLayerOutcomeFor(orgLayerOutcomeInput{enforcing: enforcing}).text
}

// liveOrgVersion is the version of the org layer the snapshot es holds ("" =
// none, or es nil).
func liveOrgVersion(es *engineSet) string {
	if es == nil {
		return ""
	}
	if st, ok := es.orgState(); ok {
		return st.Version
	}
	return ""
}

// OrgBundleFileIssue re-reads the cached org bundle at the configured path
// and reports why it does not verify under this guard's pin ("" when it
// verifies or is absent). The daemon's posture loop calls it every interval
// to report a tampered cache as a guard event (T-844); it never changes the
// live engine.
func (g *Guard) OrgBundleFileIssue() (issue string, raw []byte) {
	if g.orgBundlePath == "" {
		return "", nil
	}
	es := g.set.Load()
	// The live guard is never changed here: it keeps the org layer it holds,
	// which is what the issue says it enforces (T-877).
	outcome := func() string { return " - " + g.orgLayerOutcome(liveOrgVersion(es)) }
	data, err := g.readFile(g.orgBundlePath)
	if err != nil {
		if os.IsNotExist(err) {
			if g.missingBundleIsTamper(es) {
				return orgBundleMissingIssue(g.orgBundlePath) + outcome(), nil
			}
			return "", nil
		}
		return fmt.Sprintf("org bundle %s: %v", g.orgBundlePath, err) + outcome(), nil
	}
	if _, _, issue, ok := parseOrgBundleBytes(data, g.orgBundlePath, g.orgKeyPinHash); !ok {
		return issue + outcome(), data
	}
	return "", data
}

// orgBundleMissingIssue is the issue a deleted bundle records (T-864 gap 1).
// Like every other rejection it says only what is wrong; the caller appends
// what the guard enforces instead (orgLayerOutcome).
func orgBundleMissingIssue(path string) string {
	return fmt.Sprintf("org bundle %s is missing although this node accepted a verified bundle", path)
}

// missingBundleIsTamper reports whether a missing org bundle file is a
// deletion on THIS node (T-864 gap 1): the node accepted a verified bundle
// before (the daemon's store or org lock says so, or es, the live snapshot,
// still holds an org layer) and the org lock reaches every rule here (a
// managed node, or a process whose tenancy is unresolved: the conservative
// reading). On an individual node the developer keeps full control and a
// missing bundle is simply no org layer. es may be nil (during New).
func (g *Guard) missingBundleIsTamper(es *engineSet) bool {
	if !g.orgBundleExpected && (es == nil || !es.orgApplies()) {
		return false
	}
	return g.orgLocksEveryRule()
}

// orgParseNotes turns the ignored-key paths parsePolicyFile collected
// for the org layer into the one human line every status surface
// prints. Nil in, nil out — a clean bundle carries no notes, and the
// note is deliberately NOT a LoadIssue: the layer loaded and is in
// force, only the keys this binary predates were skipped.
func orgParseNotes(ignored []string) []string {
	if len(ignored) == 0 {
		return nil
	}
	return []string{fmt.Sprintf(
		"org bundle: ignored %d unknown key(s): %s (newer server; update the node binary)",
		len(ignored), strings.Join(ignored, ", "),
	)}
}

// loadVerifiedOrgLayer reads + signature-verifies the cached org bundle
// at path with the given reader and returns the parsed org layer, or nil
// when it is absent/corrupt/unverifiable. It shares parseOrgBundle's
// verify path (no pin — the local-root lint context, where the root can
// already write the user policy) and is the org half of the
// trusted-project lint gate (LintTrustedProject). A throwaway Guard is
// used only to reach the shared parse/verify method; no other Guard
// state is touched.
func loadVerifiedOrgLayer(readFile func(string) ([]byte, error), path string) *policyFile {
	g := &Guard{readFile: readFile}
	if pf, _, _, loaded := g.parseOrgBundle(path, ""); loaded {
		return pf
	}
	return nil
}
