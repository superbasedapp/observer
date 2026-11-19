package sandboxremote

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// consent.go is the per-provider consent record (sandbox plan v2 sections
// 5.7 and 7.2): before the first upload the user sees what leaves the
// machine and agrees, per provider. The record is node-local and owner-only
// (the cmd layer writes it); a change to any fact that decides what leaves
// the machine or what it costs invalidates it, so the next launch asks
// again.

// ConsentVersion moves with every change to the record's shape or to the
// set of facts it binds.
const ConsentVersion = 1

// ConsentFacts are what the user agreed to. Each field is shown on the
// consent screen; every one binds the record.
type ConsentFacts struct {
	// Provider is the vendor id (VendorE2B, ...).
	Provider string `json:"provider"`
	// Endpoint is the API origin the credential and the upload go to.
	Endpoint string `json:"endpoint"`
	// Region is the region the box runs in ("provider chosen" when the
	// vendor cannot pin one).
	Region string `json:"region"`
	// Custody is where the model credential sits (section 7.2).
	Custody string `json:"custody"`
	// Tier is the egress tier and Capture the capture level it computes.
	Tier    string `json:"tier"`
	Capture string `json:"capture"`
	// ScopeKey names the upload scope (Manifest.ScopeKey).
	ScopeKey string `json:"scope_key"`
	// BoxBinary names the in-box observer (its version and where it came
	// from: the running binary or box_binary).
	BoxBinary string `json:"box_binary"`
	// MemoryImages is the [terminal.sandbox.hosted].memory_images value.
	MemoryImages string `json:"memory_images"`
	// MaxRunMinutes and DailyBoxMinutes are the spend caps.
	MaxRunMinutes   int `json:"max_run_minutes"`
	DailyBoxMinutes int `json:"daily_box_minutes"`
	// PrivateRanges is the effective private-range deny of the tier
	// (PrivateRangePosture.ConsentValue: "denied", "allowed", or "" where no
	// setting changes it; decision SBXD-7). It joined the record without a
	// ConsentVersion step: an empty value is left out of the digest and the
	// JSON, so every record made before it still verifies, and a launch whose
	// posture is now denied or allowed reopens consent as
	// consent_changed_private_ranges.
	PrivateRanges string `json:"private_ranges,omitempty"`
	// InBoxKeys are the stored providers whose keys would enter the box
	// (decision SBXD-3): bound only while the custody settings can put a
	// key in the box (in_box_api_key, or auto), so a home_relay node's
	// consent never reopens for a stored key. Sorted provider ids, "," joined.
	InBoxKeys string `json:"in_box_keys,omitempty"`
	// ToolKeys and LoginSeed are the tools opted in to the in-box sources of
	// decision SBXD-4 (their own saved keys; their login access token),
	// bound under the same condition. Sorted tool ids, "," joined.
	ToolKeys  string `json:"tool_keys,omitempty"`
	LoginSeed string `json:"login_seed,omitempty"`
}

// ConsentRecord is the stored agreement.
type ConsentRecord struct {
	Version int          `json:"version"`
	Facts   ConsentFacts `json:"facts"`
	// At is when the user agreed (RFC 3339, set by the cmd layer).
	At string `json:"at"`
	// Digest is ConsentDigest(Facts), so a hand-edited fact fails.
	Digest string `json:"digest"`
}

// The closed consent verdicts.
const (
	ConsentOK            = "ok"
	ConsentMissing       = "consent_required"
	ConsentStaleVersion  = "consent_stale_version"
	ConsentTampered      = "consent_tampered"
	ConsentChangedPrefix = "consent_changed_"
)

// consentFields are the bound facts with the name a change reports, in the
// order they are compared (table-driven, CLAUDE.md rule 5).
var consentFields = []struct {
	name string
	get  func(ConsentFacts) string
	// omitEmpty: an empty value is left out of the digest (a field added
	// after records were made).
	omitEmpty bool
}{
	{"provider", func(f ConsentFacts) string { return f.Provider }, false},
	{"endpoint", func(f ConsentFacts) string { return f.Endpoint }, false},
	{"region", func(f ConsentFacts) string { return f.Region }, false},
	{"custody", func(f ConsentFacts) string { return f.Custody }, false},
	{"tier", func(f ConsentFacts) string { return f.Tier }, false},
	{"capture", func(f ConsentFacts) string { return f.Capture }, false},
	{"scope", func(f ConsentFacts) string { return f.ScopeKey }, false},
	{"box_binary", func(f ConsentFacts) string { return f.BoxBinary }, false},
	{"memory_images", func(f ConsentFacts) string { return f.MemoryImages }, false},
	{"cap", func(f ConsentFacts) string { return fmt.Sprintf("%d/%d", f.MaxRunMinutes, f.DailyBoxMinutes) }, false},
	// Added after version 1 (decisions SBXD-7, SBXD-3 and SBXD-4): an empty value
	// adds nothing to the digest, so every record made before them still
	// checks, and a change from empty still reports the field.
	{"private_ranges", func(f ConsentFacts) string { return f.PrivateRanges }, true},
	{"in_box_keys", func(f ConsentFacts) string { return f.InBoxKeys }, true},
	{"tool_keys", func(f ConsentFacts) string { return f.ToolKeys }, true},
	{"login_seed", func(f ConsentFacts) string { return f.LoginSeed }, true},
}

// ConsentDigest hashes the facts in a fixed order.
func ConsentDigest(f ConsentFacts) string {
	h := sha256.New()
	fmt.Fprintf(h, "v%d", ConsentVersion)
	for _, c := range consentFields {
		if c.omitEmpty && c.get(f) == "" {
			continue
		}
		fmt.Fprintf(h, "\x00%s=%s", c.name, c.get(f))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// NewConsent builds the record the user agreed to at.
func NewConsent(f ConsentFacts, at string) ConsentRecord {
	return ConsentRecord{Version: ConsentVersion, Facts: f, At: at, Digest: ConsentDigest(f)}
}

// CheckConsent compares a stored record (nil when none) with the facts of
// the launch now: ConsentOK, or the verdict naming what changed.
func CheckConsent(rec *ConsentRecord, now ConsentFacts) string {
	switch {
	case rec == nil:
		return ConsentMissing
	case rec.Version != ConsentVersion:
		return ConsentStaleVersion
	case rec.Digest != ConsentDigest(rec.Facts):
		return ConsentTampered
	}
	for _, c := range consentFields {
		if c.get(rec.Facts) != c.get(now) {
			return ConsentChangedPrefix + c.name
		}
	}
	return ConsentOK
}

// DecodeConsent parses a stored record strictly; a record that does not
// parse is treated as missing by the caller.
func DecodeConsent(b []byte) (ConsentRecord, error) {
	var rec ConsentRecord
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rec); err != nil {
		return ConsentRecord{}, fmt.Errorf("sandboxremote.DecodeConsent: %w", err)
	}
	return rec, nil
}

// ConsentLine is one line of the consent screen.
type ConsentLine struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// ConsentScreen is what the panel and `observer sandbox hosted consent`
// show before the user agrees.
type ConsentScreen struct {
	Provider string        `json:"provider"`
	Lines    []ConsentLine `json:"lines"`
	// Excluded lists the credential-shaped and other excluded files.
	Excluded []Exclusion `json:"excluded"`
	// Uploaded names the files that are sent, the first ConsentFileList of
	// them in manifest order; UploadedMore counts the rest (live run
	// 2026-10-23, finding F11: the screen gave only a count).
	Uploaded     []string     `json:"uploaded"`
	UploadedMore int          `json:"uploaded_more"`
	Facts        ConsentFacts `json:"facts"`
	// CloneWhere is where a clone-remote agreement's clone runs ("box", or
	// "home": this machine clones and uploads; decision SBXD-5), "" for an
	// upload of a project.
	CloneWhere string `json:"clone_where,omitempty"`
}

// ConsentFileList caps the file names the consent screen lists.
const ConsentFileList = 50

// remoteClonePrefix opens the consent scope of a box-side clone.
const remoteClonePrefix = "remote_clone:"

// RemoteCloneScopeKey is the consent scope of a box-side clone of url (a
// remote_clone delivery): the one owner the launch checks and every consent
// surface records (FX3 item 3, live finding F-L6P4-1), so the two never
// differ. The URL is kept exactly as the launch carries it.
func RemoteCloneScopeKey(url string) string { return remoteClonePrefix + url }

// RemoteCloneURL reads the clone URL out of a remote-clone scope key (ok
// false for any other scope).
func RemoteCloneURL(scope string) (string, bool) {
	url, ok := strings.CutPrefix(scope, remoteClonePrefix)
	return url, ok && url != ""
}

// homeClonePrefix opens the consent scope of a clone this machine makes and
// uploads (decision SBXD-5, clone_where home).
const homeClonePrefix = "home_clone:"

// HomeCloneScopeKey is the consent scope of a clone of url made on this
// machine with its own git login, whose tracked files are then uploaded
// under the upload manifest's rules (decision SBXD-5): distinct from
// RemoteCloneScopeKey of the same URL, so switching where the clone runs
// asks again, and bound to the manifest rule version, so a rule change asks
// again as it does for a project's upload. The URL is kept exactly as the
// launch carries it.
func HomeCloneScopeKey(url string) string {
	return homeClonePrefix + "v" + strconv.Itoa(ManifestVersion) + ":" + url
}

// HomeCloneURL reads the clone URL out of a home-clone scope key (ok false
// for any other scope, or one bound to another manifest rule version).
func HomeCloneURL(scope string) (string, bool) {
	rest, ok := strings.CutPrefix(scope, homeClonePrefix+"v"+strconv.Itoa(ManifestVersion)+":")
	return rest, ok && rest != ""
}

// BuildConsentScreen renders the facts, the manifest, the vendor row and an
// estimate into the screen's lines (the same lines on every surface).
func BuildConsentScreen(v Vendor, f ConsentFacts, m Manifest, estimate Estimate) ConsentScreen {
	captureLine := f.Capture
	if f.Capture != "full" {
		captureLine += " (guard advisory for anything judged inside the box)"
	}
	lines := []ConsentLine{
		{"Provider", v.Name + " (" + f.Endpoint + ")"},
		{"Where the box runs", whereLine(v, f.Region)},
		{"What is uploaded", m.Summary() + " from " + m.Root + " (git tracked and untracked-not-ignored files; never your home directory, never .git history)"},
		{"In-box observer", f.BoxBinary},
		{"Model credential", custodyLine(f.Custody)},
		{"Network tier", tierLine(v, f.Tier)},
		{"Capture", captureLine},
		{HooksConsentLabel, HostedHookNote},
		{"Memory images", memoryLine(v, f.MemoryImages)},
		{"Spend cap", fmt.Sprintf("each box stops after at most %d minutes, sooner when less is left of this machine's own cap of %d box-minutes a day on %s", f.MaxRunMinutes, f.DailyBoxMinutes, v.Name)},
		{"Estimated cost", costLine(v, estimate)},
	}
	if f.Region == RegionOrgPublished {
		// SBX-GOV-2: the endpoint is shown, and what it may not do.
		lines = append(lines, ConsentLine{"Endpoint", f.Endpoint + " was published by your organization: data only (it enables nothing by itself), and your credential is sent there only when you connected one for this endpoint"})
	}
	// The tier's own network facts (H10, SBXD-7): on a tier whose meaning the
	// vendor does not document, that the box's traffic is the vendor's and
	// whether the metadata address and private ranges are denied by
	// Observer's request, not deniable there, or allowed by the person's
	// setting (the bound PrivateRanges fact); then what live runs saw.
	for _, n := range TierNetworkNotes(v, vocab.Tier(f.Tier), f.PrivateRanges == PrivateRangesAllowedBySetting.ConsentValue()) {
		lines = append(lines, ConsentLine{"Outside Observer's control", n})
	}
	if m.NonRepository {
		// SBXD-8: a folder that is not a repository, and how its files
		// were chosen (the listed files follow the lines).
		setConsentLine(lines, "What is uploaded", m.Summary()+" from "+m.Root+" (this folder is not a git repository: every file except what its .gitignore files and Observer's default ignore list leave out, which are dependency, build and virtual-environment folders, version-control folders, .env files and operating-system clutter; never your home directory; the agent's changes come back as a diff file, with no branch to open)")
	}
	if url, ok := RemoteCloneURL(m.ScopeKey); ok {
		// A box-side clone uploads nothing from this machine; the URL is
		// shown in full, as the digest binds it.
		setConsentLine(lines, "What is uploaded", "nothing from this machine: the box clones "+url+" itself (the clone never runs here)")
		lines = append(lines, ConsentLine{"Repository access", cloneAccessLine(v)})
	}
	if url, ok := HomeCloneURL(m.ScopeKey); ok {
		// A clone made here (SBXD-5): what leaves is the clone's tracked
		// files, listed only once the clone exists, under the same rules.
		setConsentLine(lines, "What is uploaded", HomeCloneUploadLine(url))
		lines = append(lines, ConsentLine{"Repository access", HomeCloneAccessLine})
	}
	scr := ConsentScreen{Provider: v.ID, Lines: lines, Excluded: m.Excluded, Facts: f, Uploaded: []string{}}
	if _, ok := RemoteCloneURL(m.ScopeKey); ok {
		scr.CloneWhere = "box"
	} else if _, ok := HomeCloneURL(m.ScopeKey); ok {
		scr.CloneWhere = "home"
	}
	for i, file := range m.Files {
		if i == ConsentFileList {
			scr.UploadedMore = len(m.Files) - i
			break
		}
		scr.Uploaded = append(scr.Uploaded, file.Path)
	}
	return scr
}

// setConsentLine replaces the value of the line with this label (FX3-A9:
// by label, never by position, so a line added above it cannot shift it).
func setConsentLine(lines []ConsentLine, label, value string) {
	for i := range lines {
		if lines[i].Label == label {
			lines[i].Value = value
			return
		}
	}
}

// HomeCloneUploadLine is the consent screen's upload line for a clone of
// url made on this machine (SBXD-5).
func HomeCloneUploadLine(url string) string {
	return "the files git tracks in " + url + ", cloned on this machine with your own git login just before the box starts (never the git history; credential-shaped files are left out and the upload caps apply); the run's terminal says how many files went and which were left out, and the temporary clone is removed after the upload"
}

// HomeCloneAccessLine is the consent screen's repository line for a clone
// made on this machine (SBXD-5).
const HomeCloneAccessLine = "your git login is used only on this machine, for the clone; no git credential is sent to the box, so a private repository works"

// cloneAccessLine says what the box clones with (lane CLONE): a row whose
// calls carry a token the organization mints (MintedCredential) may have the
// organization's own read-only credential for that one repository attached
// for the clone (g1-design 4.3); every other row's box gets no git
// credential at all, so only a public repository clones. Neither ever sends
// a git credential of this machine.
func cloneAccessLine(v Vendor) string {
	if v.MintedCredential {
		return "no git credential of this machine is sent; your organization attaches its own read-only credential for that one repository during the clone when it registered one, and the box reaches the git host over its own network"
	}
	return "no git credential is sent to the box, so only a public repository clones; a private one fails before the agent starts and the box is deleted. The box reaches the git host over " + v.Name + "'s network, so it needs the internet tier"
}

// whereLine names whose machines run the box (live finding F-L3-7): a
// vendor whose endpoint only an organization publishes (OrgEndpoint) runs
// on that organization's machines, never on a vendor named after the row.
func whereLine(v Vendor, region string) string {
	if v.OrgEndpoint {
		return "on your organization's machines, region " + region
	}
	return "on " + v.Name + "'s machines, region " + region
}

// costLine is the estimate line (live finding F-L3-7): a vendor with no
// recorded list price gets no estimate with empty fields; an
// organization-published one says the organization's compute is not billed
// to the user here.
func costLine(v Vendor, e Estimate) string {
	if e.Price.Date != "" || e.Price.USDPerHour != 0 {
		return e.Label()
	}
	if v.OrgEndpoint {
		return "no estimate: the box runs on your organization's compute, which it provides and pays for; your organization's quotas apply"
	}
	return "no estimate: no list price is recorded for " + v.Name
}

// tierLine is the network tier line: the tier, and the vendor's own
// mechanism for it when the row has one.
func tierLine(v Vendor, tier string) string {
	if m, ok := v.Tiers[vocab.Tier(tier)]; ok && m.Mechanism != "" {
		return tier + ": " + m.Mechanism
	}
	return tier
}

func custodyLine(c string) string {
	// A custody fact may carry per-tool values after the node's
	// ("auto; droid=in_box_api_key"); the line describes the node's.
	c, _, _ = strings.Cut(c, "; ")
	switch c {
	case "home_relay":
		return "stays on this machine; the home proxy adds it on the way out"
	case "auto":
		return "for each agent, stays on this machine when the home proxy can add it, otherwise an API key is placed in the box environment, readable by the agent and by anyone with access to the box; the New Terminal dialog says which before each start"
	case "in_box_api_key":
		return "an API key is placed in the box environment, readable by the agent and by anyone with access to the box; revoke it with its provider after the run if in doubt"
	case "in_box_oauth_seed":
		return "your subscription login (access and refresh token) is copied into the box; revoke the session with its vendor after the run if in doubt"
	case "provider_injected":
		return "the provider's secret broker adds the key on egress; token counts are box-reported"
	}
	return c
}

func memoryLine(v Vendor, policy string) string {
	switch {
	case !v.MemoryImages.AutoPauseExists:
		return v.Name + " takes no memory image of a running box (" + v.MemoryImages.Note + ")"
	case v.MemoryImages.CanDisable:
		return "auto-pause is switched off at create, so no memory image is taken (" + policy + ")"
	}
	return "this provider can take a memory image of the live box (" + policy + ")"
}
