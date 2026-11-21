package sandboxvocab

import "strconv"

// quota.go is the one wording of the organization's daily box-minutes quota
// (live finding G-L3 rerun, the consent and approve screens). The org's
// quota is per member and counts every one of the member's machines; a
// node's own [terminal.sandbox.hosted] daily_box_minutes is a different,
// per-machine cap. Before this, the node's consent screen said "today's 240
// box-minutes" (the machine's cap) while the org's approve page said "480
// box minutes a day" (the member's quota), two numbers that read as one.
// Both screens now name the org's quantity with this phrase, and the
// consent screen names the machine's cap as the machine's.

// OrgDailyBoxMinutesPhrase names the organization's per-member daily
// box-minutes quota of n minutes.
func OrgDailyBoxMinutesPhrase(n int) string {
	return strconv.Itoa(n) + " box-minutes a day per member, counted across all of the member's machines"
}
