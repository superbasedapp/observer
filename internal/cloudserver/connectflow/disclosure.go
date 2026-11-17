package connectflow

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// ShareLevel is how much a connected machine sends.
type ShareLevel string

// Share levels.
const (
	// ShareSummary is "Summary only": a personal dashboard.
	ShareSummary ShareLevel = "summary"
	// ShareFull is "Full detail": a team, whose admins can read it.
	ShareFull ShareLevel = "full"
)

// DashboardKind is the kind of dashboard a machine connects to.
type DashboardKind string

// Dashboard kinds (the cloud's org kinds).
const (
	KindPersonal DashboardKind = "personal"
	KindTeam     DashboardKind = "team"
)

// shareLevels maps a dashboard kind to the share level it implies. The
// browser never chooses a share level; the server reads it from here.
var shareLevels = []struct {
	kind  DashboardKind
	level ShareLevel
}{
	{kind: KindPersonal, level: ShareSummary},
	{kind: KindTeam, level: ShareFull},
}

// ShareLevelFor returns the share level of a dashboard kind; ok is false for
// an unknown kind.
func ShareLevelFor(kind DashboardKind) (ShareLevel, bool) {
	for _, s := range shareLevels {
		if s.kind == kind {
			return s.level, true
		}
	}
	return "", false
}

// DisclosureVersion names the disclosure texts below. Change it whenever a
// text changes, so a consent receipt always names the words that were shown.
const DisclosureVersion = "connect-disclosure.v1"

// teamNameMark is where a team's name goes in a disclosure template.
const teamNameMark = "{team}"

// disclosureTexts is the disclosure per share level, at DisclosureVersion.
var disclosureTexts = []struct {
	level    ShareLevel
	title    string
	template string
}{
	{
		level: ShareSummary,
		title: "Summary only",
		template: "Counts, costs, timings, tool and model names, file paths as hashes. " +
			"Never prompts, responses or file contents. Stored by SuperBased in the EU. " +
			"Only you see it. Only new activity; earlier sessions stay local.",
	},
	{
		level:    ShareFull,
		title:    "Full detail",
		template: teamNameMark + "'s admins can read full detail: prompts, responses and file paths.",
	},
}

// DisclosureText is the disclosure shown for one dashboard.
type DisclosureText struct {
	Level   ShareLevel `json:"share_level"`
	Title   string     `json:"title"`
	Text    string     `json:"text"`
	Version string     `json:"disclosure_version"`
	// SHA256 is the hex SHA-256 of Version, a newline and Text: what a
	// consent receipt records.
	SHA256 string `json:"disclosure_sha256"`
}

// Disclosure renders the disclosure of level for a dashboard named name; ok
// is false for an unknown level.
func Disclosure(level ShareLevel, name string) (DisclosureText, bool) {
	for _, d := range disclosureTexts {
		if d.level != level {
			continue
		}
		text := strings.ReplaceAll(d.template, teamNameMark, CleanMachineName(name))
		sum := sha256.Sum256([]byte(DisclosureVersion + "\n" + text))
		return DisclosureText{
			Level: level, Title: d.title, Text: text,
			Version: DisclosureVersion, SHA256: hex.EncodeToString(sum[:]),
		}, true
	}
	return DisclosureText{}, false
}
