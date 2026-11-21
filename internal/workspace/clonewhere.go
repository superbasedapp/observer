package workspace

import (
	"fmt"
	"strings"
)

// clonewhere.go decides where a hosted row's "Clone a remote URL" source
// clones (decision SBXD-5, audit H7): in the box (the box runs `git clone`
// of a public address, nothing is uploaded, no git credential leaves this
// machine) or at home (this machine clones with its own git login, through
// the same clone-remote plan the local rows use, and the clone's tracked
// files are uploaded the way a project is, so a private repository works
// and no credential leaves). [terminal.sandbox.hosted].clone_where pins the
// answer (box, home) or leaves it to the per-launch table (auto, the
// default): an address that answers an anonymous listing is cloned in the
// box, any other at home. Pure: the caller runs the gates and the
// anonymous listing (AnonymousListArgv) and passes their answers in.

// CloneWhere is a clone location setting or answer.
type CloneWhere string

// The closed CloneWhere vocabulary.
const (
	// CloneWhereAuto decides per launch (the default, decision SBXD-0).
	CloneWhereAuto CloneWhere = "auto"
	// CloneWhereBox clones in the box (public repositories only on a row
	// whose box gets no git credential).
	CloneWhereBox CloneWhere = "box"
	// CloneWhereHome clones on this machine and uploads the clone's files.
	CloneWhereHome CloneWhere = "home"
)

// CloneWhereValues lists the vocabulary in the order a picker shows it.
var CloneWhereValues = []CloneWhere{CloneWhereAuto, CloneWhereBox, CloneWhereHome}

// ParseCloneWhere reads a setting; "" is the default, auto.
func ParseCloneWhere(s string) (CloneWhere, error) {
	switch w := CloneWhere(strings.TrimSpace(s)); w {
	case "":
		return CloneWhereAuto, nil
	case CloneWhereAuto, CloneWhereBox, CloneWhereHome:
		return w, nil
	}
	return "", fmt.Errorf("workspace.ParseCloneWhere: %q not in {auto, box, home}", s)
}

// AnonAnswer is what an anonymous listing of a URL said.
type AnonAnswer string

// The closed AnonAnswer vocabulary.
const (
	// AnonNotAsked: no listing was run (the dialog's list, before a URL).
	AnonNotAsked AnonAnswer = ""
	// AnonPublic: the address answered with no credential at all.
	AnonPublic AnonAnswer = "public"
	// AnonRefused: it did not (a sign-in needed, not found, or no answer
	// within the bound): only this machine's own login can clone it.
	AnonRefused AnonAnswer = "refused"
)

// CloneWhereInput is one decision's input.
type CloneWhereInput struct {
	// Setting is the effective setting (the launch's choice, else the
	// config's).
	Setting CloneWhere
	// HomeCapable: the row can take an upload of a home clone (it uploads
	// a tree and its box clone is the core one, not an organization's own
	// clone with its own credential).
	HomeCapable bool
	// BoxOK and HomeOK: every gate of that way passed (for the dialog's
	// list, every gate but the URL's).
	BoxOK, HomeOK bool
	// Anon is the anonymous listing's answer.
	Anon AnonAnswer
}

// The closed decision reasons; CloneWhereReasonText words each one.
const (
	ReasonRowClonesInBox  = "row_clones_in_box"
	ReasonSetBox          = "set_box"
	ReasonSetHome         = "set_home"
	ReasonBoxCannotClone  = "box_cannot_clone"
	ReasonPublic          = "public"
	ReasonNeedsLogin      = "needs_login"
	ReasonListingRequired = "listing_required"
)

// CloneWhereReasonText is each reason in plain words (the dialog's line, the
// run's terminal and the consent screen say it).
var CloneWhereReasonText = map[string]string{
	ReasonRowClonesInBox:  "this provider's box clones the repository itself",
	ReasonSetBox:          "the setting says to clone in the box",
	ReasonSetHome:         "the setting says to clone on this machine",
	ReasonBoxCannotClone:  "the box cannot clone it (the network setting, the git hosts or the address rule it in), so this machine clones it",
	ReasonPublic:          "anyone can read this repository, so the box clones it",
	ReasonNeedsLogin:      "this repository needs a sign-in, so this machine clones it with your own git login",
	ReasonListingRequired: "whether anyone can read the repository is checked at launch",
}

// CloneWhereDecision is the answer: where the clone runs ("" while the
// listing is still owed), why, and whether the caller must run the
// anonymous listing and decide again.
type CloneWhereDecision struct {
	Where     CloneWhere
	Reason    string
	NeedsAnon bool
}

// cloneWhereRule is one row of the decision table; "" in setting and the
// nil anon match any value.
type cloneWhereRule struct {
	name  string
	match func(in CloneWhereInput) bool
	out   CloneWhereDecision
}

// cloneWhereRules is the table, walked top-down, the first match wins:
//   - a row that cannot take a home clone (the organization's row, whose
//     clone is its organization's own) clones in the box whatever the
//     setting;
//   - a setting of box or home is that way (its own gates then decide);
//   - auto: a box that cannot clone the URL hands it home; a box that can
//     needs the anonymous listing first; an address that answered clones in
//     the box, any other at home.
var cloneWhereRules = []cloneWhereRule{
	{"row clones in the box", func(in CloneWhereInput) bool { return !in.HomeCapable }, CloneWhereDecision{Where: CloneWhereBox, Reason: ReasonRowClonesInBox}},
	{"set box", func(in CloneWhereInput) bool { return in.Setting == CloneWhereBox }, CloneWhereDecision{Where: CloneWhereBox, Reason: ReasonSetBox}},
	{"set home", func(in CloneWhereInput) bool { return in.Setting == CloneWhereHome }, CloneWhereDecision{Where: CloneWhereHome, Reason: ReasonSetHome}},
	{"auto, the box cannot clone", func(in CloneWhereInput) bool { return !in.BoxOK }, CloneWhereDecision{Where: CloneWhereHome, Reason: ReasonBoxCannotClone}},
	{"auto, the listing is owed", func(in CloneWhereInput) bool { return in.Anon == AnonNotAsked }, CloneWhereDecision{Reason: ReasonListingRequired, NeedsAnon: true}},
	{"auto, public", func(in CloneWhereInput) bool { return in.Anon == AnonPublic }, CloneWhereDecision{Where: CloneWhereBox, Reason: ReasonPublic}},
	{"auto, needs a login", func(CloneWhereInput) bool { return true }, CloneWhereDecision{Where: CloneWhereHome, Reason: ReasonNeedsLogin}},
}

// DecideCloneWhere walks the table. An unknown setting is read as auto
// (ParseCloneWhere refuses it earlier, at config validation).
func DecideCloneWhere(in CloneWhereInput) CloneWhereDecision {
	for _, r := range cloneWhereRules {
		if r.match(in) {
			return r.out
		}
	}
	return CloneWhereDecision{Where: CloneWhereHome, Reason: ReasonNeedsLogin}
}

// ValidateHomeCloneURL is the URL gate of a clone this machine makes for a
// hosted box (SBXD-5): ValidateRemoteURL with the local rows' host rule (an
// empty allowedHosts allows any host, because the clone runs here, as a
// local clone-remote does), plus no credential in the URL: the URL is kept
// in the consent and run records and shown on the run's terminal, and this
// machine's own git login (an ssh key, a credential helper) is what signs
// in to a private repository.
func ValidateHomeCloneURL(url string, allowedHosts []string) error {
	if err := ValidateRemoteURL(url, allowedHosts); err != nil {
		return err
	}
	if urlCarriesCredential(url, false) {
		return fmt.Errorf("workspace.ValidateHomeCloneURL: the URL carries a user name, password or token; name the repository without one, your own git login signs in")
	}
	return nil
}

// AnonymousListArgv is the anonymous listing of url that decides auto: git
// asks the remote for its HEAD with every credential source switched off
// on the command line too (no credential helper, no askpass; the caller's
// environment, AnonymousListEnv, adds no config, no prompt and an empty
// home so no .netrc or stored login is read). Only an https:// address is
// ever listed (an address the box can clone), validated by
// ValidateBoxCloneURL first; "--" comes before it.
func AnonymousListArgv(url string) ([]string, error) {
	if err := validateNoControlOrWhitespace("URL", url); err != nil || !strings.HasPrefix(url, "https://") || urlCarriesCredential(url, true) {
		return nil, fmt.Errorf("workspace.AnonymousListArgv: %q is not a credential-free https:// address", url)
	}
	return []string{
		"git", "-c", "credential.helper=", "-c", "core.askPass=", "-c", "http.followRedirects=false",
		"ls-remote", "--", url, "HEAD",
	}, nil
}

// AnonymousListEnv is the listing's fixed environment beside the caller's
// git hardening: no prompt, no askpass, no system or global config, and
// home (an empty directory the caller makes) as HOME and XDG_CONFIG_HOME,
// so git reads no stored credential of this machine.
func AnonymousListEnv(home string) map[string]string {
	return map[string]string{
		"GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "", "SSH_ASKPASS": "",
		"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
		"HOME": home, "XDG_CONFIG_HOME": home,
	}
}
