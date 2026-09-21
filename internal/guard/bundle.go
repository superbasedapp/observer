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
	raw, err := g.readFile(path)
	switch {
	case os.IsNotExist(err):
		return nil, PolicyState{}, "", false // not enrolled / no bundle published — the common case
	case err != nil:
		return nil, PolicyState{}, fmt.Sprintf("org bundle %s: %v", path, err), false
	}
	var b orgcontract.PolicyBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, PolicyState{}, fmt.Sprintf("org bundle %s: not a bundle envelope: %v — running without the org layer", path, err), false
	}
	pub, err := orgcontract.VerifyPolicyBundle(b)
	if err != nil {
		return nil, PolicyState{}, fmt.Sprintf("org bundle %s rejected: %v — running without the org layer", path, err), false
	}
	if pinHash != "" && orgcontract.PublicKeyPinHash(pub) != pinHash {
		return nil, PolicyState{}, fmt.Sprintf("org bundle %s rejected: signing key does not match the enrolment pin — running without the org layer", path), false
	}
	parsed, perr := parsePolicyFile([]byte(b.BundleTOML), layerOrg)
	if perr != nil {
		return nil, PolicyState{}, fmt.Sprintf("org bundle %s (version %d): %v — running without the org layer", path, b.Version, perr), false
	}
	st = PolicyState{
		Layer:       layerOrg,
		Path:        path,
		Version:     strconv.FormatInt(b.Version, 10),
		ContentHash: sha256hex([]byte(b.BundleTOML)),
		Notes:       orgParseNotes(parsed.notes),
	}
	return parsed, st, "", true
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
