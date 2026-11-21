package secassess

import (
	"fmt"
	"strings"
)

// The environment files a pen test box can read (depth plan W4.4, the setting
// workspace_secret_mode). The box binds the developer's live project folder and
// does not hide .env files unless asked, so the setting chooses what Observer
// does about them: say nothing, warn, hide them (a sandbox capability: the
// bubblewrap row can, decision D32; the others cannot), or refuse to start while
// the findings store holds an open secret in one (or cannot be read, so nobody
// can tell). EffectiveSecretMode resolves the setting against what the run's
// sandbox can do, in words a dialog can show; MaskReport and MaskWords say what
// the mask covered once the box has started.

// The values of workspace_secret_mode.
const (
	SecretOff    = "off"
	SecretWarn   = "warn"
	SecretMask   = "mask"
	SecretRefuse = "refuse"
)

// What Observer knows of a scan of the project (SecretModeInput.Scan).
const (
	// ScanUnasked: the findings store was not asked (the mode does not depend
	// on it).
	ScanUnasked = ""
	// ScanDone: the project has been scanned; LastScan says when.
	ScanDone = "scanned"
	// ScanNever: the findings store holds no scan of the project, so "none open"
	// says nothing about what is in the folder.
	ScanNever = "never"
)

// MaskCapability is what is known of whether the run's sandbox can hide the
// workspace's secret files: the one input of the mask decision that comes from
// the machine. The dashboard resolves it from the sandbox probe's row (a
// capability flag, never the row's name) and from whether the launcher can
// report what the mask hid.
type MaskCapability string

// The mask capabilities. The zero value is the careful one: nothing is known,
// so nothing is asked.
const (
	// MaskNoBackend: no sandbox row is determined for the run (the plan is
	// refused before one is chosen, or the chosen row is not in the probe).
	MaskNoBackend MaskCapability = ""
	// MaskCannot: the row the run will use cannot hide files.
	MaskCannot MaskCapability = "cannot"
	// MaskNoReport: the row can, but the launcher cannot report what the mask
	// hid, and a mask whose outcome nobody can read is not asked for.
	MaskNoReport MaskCapability = "no_report"
	// MaskCan: the row can hide files and the launcher reports the outcome.
	MaskCan MaskCapability = "can"
)

// maskDowngrade is one row of the table of reasons a configured mask acts as a
// warning: the capability that causes it, the closed word a record and a
// surface carry, and the clause the dialog reads ("the setting asks ..., but
// <Clause>, so it acts as a warning").
type maskDowngrade struct {
	Cap    MaskCapability
	Why    string
	Clause string
}

// maskDowngrades is the table, one row per capability short of MaskCan. A
// capability not in it (MaskCan) is not a downgrade.
var maskDowngrades = []maskDowngrade{
	{MaskNoBackend, "no_backend", "no sandbox is chosen for this run yet"},
	{MaskCannot, "backend_cannot_mask", "the sandbox this run will use cannot hide files"},
	{MaskNoReport, "launcher_cannot_report", "this daemon's launcher cannot report what the mask hid, and a mask nobody can check is not asked for"},
}

// MaskDowngradeWhy is the closed word for why a mask is not asked for on a
// machine with the capability c, and whether it is a downgrade at all.
func MaskDowngradeWhy(c MaskCapability) (why string, downgraded bool) {
	for _, r := range maskDowngrades {
		if r.Cap == c {
			return r.Why, true
		}
	}
	return "", false
}

// MaskDowngradeWords is the clause of one closed reason (SecretMode.Why), ""
// for a word this build does not know.
func MaskDowngradeWords(why string) string {
	for _, r := range maskDowngrades {
		if r.Why == why {
			return r.Clause
		}
	}
	return ""
}

// MaskCapabilityOf reads the capability of the backend with the given id out of
// the probe's facts: MaskNoBackend when the id is empty or not among them,
// MaskCannot when the row cannot hide files, MaskNoReport when it can but the
// launcher cannot report the outcome, MaskCan otherwise.
func MaskCapabilityOf(backends []BackendFact, id string, launcherReports bool) MaskCapability {
	if id == "" {
		return MaskNoBackend
	}
	for _, b := range backends {
		if b.ID != id {
			continue
		}
		switch {
		case !b.MasksSecrets:
			return MaskCannot
		case !launcherReports:
			return MaskNoReport
		}
		return MaskCan
	}
	return MaskNoBackend
}

// SecretModeInput is what the effective mode depends on.
type SecretModeInput struct {
	// Configured is the setting.
	Configured string
	// EnvFiles is how many environment files sit at the TOP LEVEL of the project
	// folder (nested ones are not counted: the plan lists the top level only).
	EnvFiles int
	// Mask says whether the run's sandbox can hide files inside the box (decision
	// D32); the zero value is MaskNoBackend.
	Mask MaskCapability
	// OpenSecret says the findings store holds an open secret finding in an
	// environment or key file of the project (at any depth).
	OpenSecret bool
	// FindingsUnreadable says the findings store could not be read completely
	// (no store, no project, an error, or more rows than the bounded read
	// covers), so OpenSecret is not a fact. Under refuse that is a refusal: a
	// control that cannot check does not wave a run through.
	FindingsUnreadable bool
	// Scan says what is known of a scan of the project (ScanUnasked, ScanDone,
	// ScanNever) and LastScan the day of the newest one ("2006-01-02") when
	// Scan is ScanDone.
	Scan     string
	LastScan string
	// Tier is the sandbox network tier of the run ("proxy_only" or wider).
	Tier string
}

// SecretMode is the resolved behaviour.
type SecretMode struct {
	// Configured is the setting as given, Effective what happens ("mask" acts
	// as "warn" while the run's sandbox cannot hide files).
	Configured string `json:"configured"`
	Effective  string `json:"effective"`
	// Refuse says the launch is refused (the setting is refuse and a secret is
	// open, or the findings could not be read).
	Refuse bool `json:"refuse"`
	// Unreadable says the refusal is because the findings could not be read
	// (ReasonFindingsUnreadable), not because a secret is open.
	Unreadable bool `json:"unreadable,omitempty"`
	// Downgraded says the setting asked for more than the run's sandbox can do,
	// and Why is the closed word for the reason (MaskDowngradeWhy; "" when it is
	// not a downgrade).
	Downgraded bool   `json:"downgraded"`
	Why        string `json:"downgrade,omitempty"`
	// Words is the sentence for the plan dialog ("" when there is nothing to
	// say).
	Words string `json:"words"`
	// TierWords is the extra consent line under a sandbox network wider than
	// the model proxy alone ("" otherwise).
	TierWords string `json:"tier_words,omitempty"`
}

// ReasonSecretFilesOpen is the sentence of the refusal.
const ReasonSecretFilesOpen = "A secret that Observer found is still open in an environment or key file of this project, and \"" + LabelEnvFiles + "\" is set to refuse a penetration test while one is open. Close the finding (rotate the secret, then mark it handled) or change that setting in " + WhereSettings + "."

// ReasonFindingsUnreadable is the sentence of the refusal when the findings
// could not be read: under refuse the control does not guess.
const ReasonFindingsUnreadable = "\"" + LabelEnvFiles + "\" is set to refuse a penetration test while a secret is open in an environment or key file, and Observer could not read its findings for this project, so it cannot tell. Try again, or change that setting in " + WhereSettings + "."

// secretModeRow is one row of the words table: the first row whose test holds
// gives the sentence.
type secretModeRow struct {
	ID    string
	Holds func(SecretModeInput, string) bool
	Words func(SecretModeInput) string
}

func envFilesText(n int) string {
	if n == 1 {
		return "1 environment file is"
	}
	return fmt.Sprintf("%d environment files are", n)
}

// envFilesCounted says where the files were counted.
func envFilesCounted(n int) string {
	return envFilesText(n) + " at the top level of this folder (nested ones are not counted)"
}

// envFilesHere is envFilesCounted with the fact that the box can read them.
func envFilesHere(n int) string {
	return envFilesCounted(n) + " and readable inside the box."
}

// refuseKnown says what the findings store actually knows under refuse: that it
// holds no open secret in an environment or key file, and how much that says.
func refuseKnown(in SecretModeInput) string {
	switch in.Scan {
	case ScanDone:
		return "Observer's findings hold no open secret in an environment or key file (the project was last scanned " + in.LastScan + "; a file it has not scanned is not covered)."
	case ScanNever:
		return "Observer has never scanned this project, so its findings hold nothing to refuse on and that says little: run a scan under Code security to check."
	}
	return "Observer's findings hold no open secret in an environment or key file."
}

// maskedWords is the sentence of a run whose mask is in force. It states what
// the mask is and is not (a snapshot of names taken when the box starts), because
// the prompt keeps its "do not open them" line under mask: the files the mask
// does not recognise are exactly the ones the agent must still be told about.
const maskedWords = "Observer asks the sandbox to hide environment and key files inside the box, by file name (.env and its variants, certificate and key files, SSH identity files, package-registry and netrc credentials), down to a bounded depth. The hiding is a snapshot taken when the box starts: a file created later, a link to a secret, a secret in a file with another name (.envrc, for example) and anything past the bounds stay readable, so the agent is still told not to open environment files, which is a request and not a barrier. Once the run has started, Observer says how many files it hid and what it could not."

// secretModeWords is the ordered table of sentences. Effective is the mode after
// the capability check.
var secretModeWords = []secretModeRow{
	{
		"refused", func(in SecretModeInput, eff string) bool { return eff == SecretRefuse && in.OpenSecret },
		func(SecretModeInput) string { return ReasonSecretFilesOpen },
	},
	{
		"refused_unreadable", func(in SecretModeInput, eff string) bool { return eff == SecretRefuse && in.FindingsUnreadable },
		func(SecretModeInput) string { return ReasonFindingsUnreadable },
	},
	{
		"refuse_armed", func(in SecretModeInput, eff string) bool { return eff == SecretRefuse },
		func(in SecretModeInput) string {
			s := "\"" + LabelEnvFiles + "\" is set to refuse a penetration test while a secret is open in an environment or key file. " + refuseKnown(in)
			if in.EnvFiles > 0 {
				s = envFilesHere(in.EnvFiles) + " " + s
			}
			return s + " The agent is told not to open them, which is a request and not a barrier."
		},
	},
	{
		"masked", func(in SecretModeInput, eff string) bool { return eff == SecretMask },
		func(in SecretModeInput) string {
			if in.EnvFiles > 0 {
				return envFilesCounted(in.EnvFiles) + ". " + maskedWords
			}
			return maskedWords
		},
	},
	{
		// The setting asks to hide and the run's sandbox cannot: the reason is the
		// table's clause for the capability, so each way of falling short has its
		// own words and its own test row.
		"mask_unavailable", func(in SecretModeInput, eff string) bool {
			return in.Configured == SecretMask && eff != SecretMask && in.EnvFiles > 0
		},
		func(in SecretModeInput) string {
			why, _ := MaskDowngradeWhy(in.Mask)
			return "\"" + LabelEnvFiles + "\" asks to hide environment files inside the box, but " + MaskDowngradeWords(why) + ", so it acts as a warning: " + envFilesHere(in.EnvFiles) + " The agent is told not to open them, which is a request and not a barrier."
		},
	},
	{
		"warned", func(in SecretModeInput, eff string) bool { return eff == SecretWarn && in.EnvFiles > 0 },
		func(in SecretModeInput) string {
			return envFilesHere(in.EnvFiles) + " The agent is told not to open them, which is a request and not a barrier."
		},
	},
}

// tierWords is the consent line under a network tier wider than the model
// connection: it does not depend on a file being found at the top level, because
// a nested environment file or a key file is as readable in the box.
const tierWords = "This run's sandbox network is wider than the model connection alone. Real keys in any environment or key file the box can read, attack payloads and a route out are a risk you accept by starting it."

// EffectiveSecretMode resolves workspace_secret_mode against the run's sandbox.
// An unknown setting reads as warn (the safer reading); mask acts as warn unless
// the sandbox can hide files (in.Mask is MaskCan), and says why.
func EffectiveSecretMode(in SecretModeInput) SecretMode {
	switch in.Configured {
	case SecretOff, SecretWarn, SecretMask, SecretRefuse:
	default:
		in.Configured = SecretWarn
	}
	out := SecretMode{Configured: in.Configured, Effective: in.Configured}
	if in.Configured == SecretMask {
		if why, down := MaskDowngradeWhy(in.Mask); down {
			out.Effective, out.Downgraded, out.Why = SecretWarn, true, why
		}
	}
	if out.Effective == SecretRefuse {
		out.Unreadable = in.FindingsUnreadable && !in.OpenSecret
		out.Refuse = in.OpenSecret || in.FindingsUnreadable
	}
	for _, row := range secretModeWords {
		if row.Holds(in, out.Effective) {
			out.Words = row.Words(in)
			break
		}
	}
	if out.Effective != SecretOff && in.Tier != "" && in.Tier != "proxy_only" {
		out.TierWords = tierWords
	}
	return out
}

// MaskReport is what the workspace secret mask covered for one run, as counts
// and closed words only: a path never enters it, so it can be recorded, shown and
// written to an audit row freely. A run that did not ask for the mask has no
// report at all (nil where it is kept), and "none" is never read as "nothing was
// found": Reported says an outcome came back.
type MaskReport struct {
	// Reported says the sandbox returned an outcome. A mask that was asked for and
	// not reported on is the one state nobody can vouch for.
	Reported bool `json:"reported"`
	// Masked is the number of files hidden in the box.
	Masked int `json:"masked"`
	// Complete says the walk covered everything it could see: no limit was
	// reached, no folder was unreadable, every secret-named entry it met is
	// hidden. It is false whenever Gaps is above zero.
	Complete bool `json:"complete"`
	// Gaps is how many places the mask does not cover, and Reasons how many per
	// closed reason (MaskGapReasons); listed gaps only, the rest are in Gaps.
	Gaps    int            `json:"gaps,omitempty"`
	Reasons map[string]int `json:"reasons,omitempty"`
}

// MaxMaskCount bounds every count a MaskReport keeps.
const MaxMaskCount = 1_000_000

// MaskOtherReason is the word an unknown reason is recorded under.
const MaskOtherReason = "other"

// maskGapReason is one row of the table of closed reasons the sandbox gives for a
// place its mask does not cover, with the words a dialog reads. The first eight
// ids are the sandbox planner's vocabulary (a test in the dashboard package holds
// the table to it); other is where a word this build does not know lands.
type maskGapReason struct {
	ID    string
	Words string
}

// MaskGapReasons is the table, in the order the words are listed.
var MaskGapReasons = []maskGapReason{
	{"depth_limit", "a folder below the depth the walk reads"},
	{"dir_limit", "folders past the number the walk reads"},
	{"dir_entries_limit", "a folder with more entries than the walk reads"},
	{"mask_limit", "secret files past the number the mask hides"},
	{"unreadable", "a folder that could not be listed"},
	{"symlink", "a secret-named link, never followed"},
	{"not_regular", "a secret-named entry that is not a regular file"},
	{"unsafe_name", "a secret file whose path could not be handed to the sandbox"},
	{MaskOtherReason, "a place the mask could not describe"},
}

// ValidMaskReason reports whether id is a row of MaskGapReasons.
func ValidMaskReason(id string) bool {
	for _, r := range MaskGapReasons {
		if r.ID == id {
			return true
		}
	}
	return false
}

func clampMask(n int) int {
	return max(0, min(n, MaxMaskCount))
}

// CleanMaskReport bounds a report that came from outside this package: counts
// within [0, MaxMaskCount], an unknown reason folded into MaskOtherReason, a
// zero count dropped, Gaps never below the reasons' sum, and Complete false
// whenever there are gaps (a report is never more complete than its own gaps).
// A report that was not Reported keeps nothing else.
func CleanMaskReport(r MaskReport) MaskReport {
	if !r.Reported {
		return MaskReport{}
	}
	out := MaskReport{Reported: true, Masked: clampMask(r.Masked), Gaps: clampMask(r.Gaps)}
	sum := 0
	for id, n := range r.Reasons {
		n = clampMask(n)
		if n == 0 {
			continue
		}
		if !ValidMaskReason(id) {
			id = MaskOtherReason
		}
		if out.Reasons == nil {
			out.Reasons = map[string]int{}
		}
		out.Reasons[id] = clampMask(out.Reasons[id] + n)
	}
	for _, n := range out.Reasons {
		sum += n
	}
	out.Gaps = max(out.Gaps, clampMask(sum))
	out.Complete = r.Complete && out.Gaps == 0
	return out
}

func filesWord(n int) string {
	if n == 1 {
		return "1 file"
	}
	return fmt.Sprintf("%d files", n)
}

func placesWord(n int) string {
	if n == 1 {
		return "1 place"
	}
	return fmt.Sprintf("%d places", n)
}

// maskReasonList renders the per-reason counts in table order, "words (n)".
func maskReasonList(reasons map[string]int) string {
	var parts []string
	for _, row := range MaskGapReasons {
		if n := reasons[row.ID]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s (%d)", row.Words, n))
		}
	}
	return strings.Join(parts, "; ")
}

// MaskWords says, for a developer, what the mask covered, and whether that is
// partial (the run's sandbox may still show some environment or key files). It
// states counts and closed words only. The decision it carries is a warning, not
// a refusal: the box has already started when the outcome is known, and the
// setting's own refusal (refuse) is about open findings, not about coverage.
func MaskWords(r MaskReport) (words string, partial bool) {
	r = CleanMaskReport(r)
	switch {
	case !r.Reported:
		return "Observer asked the sandbox to hide environment and key files, but the sandbox did not report what it hid, so treat them as readable inside the box.", true
	case r.Complete && r.Masked == 0:
		return "The sandbox found no environment or key file under a name it recognises, so it hid none. A snapshot was taken when the box started; a file created later is not hidden.", false
	case r.Complete:
		return filesWord(r.Masked) + " hidden inside the box, and the walk covered everything it could see. It is a snapshot taken when the box started, by file name: a file created later or under another name is not hidden.", false
	}
	s := filesWord(r.Masked) + " hidden inside the box; " + placesWord(r.Gaps) + " could not be covered"
	if list := maskReasonList(r.Reasons); list != "" {
		s += ": " + list
	}
	return s + ". Some environment or key files may still be readable inside the box.", true
}
