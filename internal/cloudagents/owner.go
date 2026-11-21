package cloudagents

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Member-scoped connectors (security ledger CLOUDAGENTS-6, operator decision
// 2026-11-02 "Devin own sessions only", extended to OpenHands and Warp by
// task CA-T8). A Devin v3 key is scoped to an organization: GET
// /v3/organizations/{org_id}/sessions lists EVERY member's sessions, and
// Devin documents no call naming the key's owner. An OpenHands Cloud key's
// search lists every conversation the key can see (an organization's, each
// with its creator's created_by_user_id), and a Warp Personal key lists the
// runs of the user's teams as well as the user's own (an Agent key the whole
// team's), each naming its creator; neither vendor documents a call naming
// the key's owner either. Without a filter a developer's node would land
// every colleague's session as the developer's own (and push it to the org
// as theirs). So an account of a member-scoped row names its vendor user,
// picked by the developer from the users the list itself reports, and only
// that user's sessions land. With no user named, a pass pulls nothing
// (VendorUserNotChosen), never "everything".

// MemberUsers is the member scope of a connector row whose list returns the
// sessions of every member of the account's organization or team.
type MemberUsers struct {
	// Label names a vendor user in the UI ("Devin user", "OpenHands user",
	// "Warp user").
	Label string
	// Pattern is the grammar of a vendor user id (Devin: user-<32 hex>).
	// A chosen id that does not match is refused, and a listed id that does
	// not match is never offered, so a user id is never free text.
	Pattern *regexp.Regexp
}

// MemberScoped reports whether the connector's list returns every member's
// sessions, so its account must name its vendor user.
func (c Connector) MemberScoped() bool { return c.MemberUsers != nil && c.MemberUsers.Pattern != nil }

// ValidVendorUser reports whether id is a vendor user id of the connector's
// grammar. A connector that is not member scoped takes none.
func ValidVendorUser(c Connector, id string) bool {
	return c.MemberScoped() && c.MemberUsers.Pattern.MatchString(id)
}

// devinUserRE is the grammar of a Devin user id (live-verified 2026-11-01:
// user-<32 hex>).
var devinUserRE = regexp.MustCompile(`^user-[0-9a-fA-F]{32}$`)

// openHandsUserRE is the grammar of an OpenHands Cloud user id
// (created_by_user_id). Its format is NOT grounded: the reference names the
// member but not its shape, and the only sample is the synthetic fixture
// ("user-synth-0001"). So the grammar is a conservative id token: an
// alphanumeric lead, then letters, digits, '.', '_' or '-', at most 128 (a
// UUID and the fixture's shape fit; whitespace, '/', ':', '@' and control
// characters never do). Narrow it at the live check (CA-T1).
var openHandsUserRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// warpUserRE is the grammar of a Warp user uid (creator.uid of a run whose
// creator.type is "user"). The OpenAPI types it as a plain string and the
// only samples are the synthetic fixtures ("synthUserUid0001"), so this is a
// conservative id token: an alphanumeric lead, then letters, digits, '_' or
// '-', at most 128. Narrow it at the first live check (hand-back CA-V1).
var warpUserRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)

// VendorUserState says whether an account of a member-scoped connector has
// named its vendor user.
type VendorUserState string

// The closed VendorUserState vocabulary.
const (
	// VendorUserNotApplicable: the connector is not member scoped.
	VendorUserNotApplicable VendorUserState = ""
	// VendorUserNotChosen: no user named yet (a new connect, or an account
	// linked before the member scope existed). A pass pulls nothing.
	VendorUserNotChosen VendorUserState = "vendor_user_not_chosen"
	// VendorUserChosen: a user is named; only that user's sessions land.
	VendorUserChosen VendorUserState = "vendor_user_chosen"
)

// VendorUserStateOf returns an account's state from its connector and the
// vendor user it names ("" = none).
func VendorUserStateOf(c Connector, chosen string) VendorUserState {
	switch {
	case !c.MemberScoped():
		return VendorUserNotApplicable
	case chosen == "":
		return VendorUserNotChosen
	}
	return VendorUserChosen
}

// Ownership is the decision for one listed task of a member-scoped account.
type Ownership string

// The closed Ownership vocabulary.
const (
	// OwnerKeep: the task's vendor user is the account's chosen user.
	OwnerKeep Ownership = "keep"
	// OwnerSkipOtherMember: another member of the organization started it.
	OwnerSkipOtherMember Ownership = "skip_other_member"
	// OwnerSkipServiceUser: a service user (an automation or an API key of
	// the organization) started it; no person is named.
	OwnerSkipServiceUser Ownership = "skip_service_user"
	// OwnerSkipNoUser: the vendor named no user at all.
	OwnerSkipNoUser Ownership = "skip_no_user"
)

// OwnershipInput is what the ownership decision reads.
type OwnershipInput struct {
	// Chosen is the account's vendor user ("" = none chosen).
	Chosen string
	// User is the task's vendor user id ("" = not stated).
	User string
	// ServiceUser is the task's service user id ("" = not stated).
	ServiceUser string
}

// ownershipRule is one row of the ownership table.
type ownershipRule struct {
	name string
	when func(in OwnershipInput) bool
	out  Ownership
}

// ownershipRules is THE ownership decision, walked top-down; the first row
// that matches decides. Only a task whose user equals the chosen user is
// kept; nothing is kept while no user is chosen.
var ownershipRules = []ownershipRule{
	{"service user, no person", func(in OwnershipInput) bool { return in.User == "" && in.ServiceUser != "" }, OwnerSkipServiceUser},
	{"no user stated", func(in OwnershipInput) bool { return in.User == "" }, OwnerSkipNoUser},
	{"the chosen user", func(in OwnershipInput) bool { return in.Chosen != "" && in.User == in.Chosen }, OwnerKeep},
	{"anyone else", func(OwnershipInput) bool { return true }, OwnerSkipOtherMember},
}

// DecideOwnership walks ownershipRules.
func DecideOwnership(in OwnershipInput) Ownership {
	for _, r := range ownershipRules {
		if r.when(in) {
			return r.out
		}
	}
	return OwnerSkipOtherMember
}

// OwnershipOf decides one task of an account of connector c whose chosen
// vendor user is chosen. A connector that is not member scoped keeps every
// task (its list is already the key owner's).
func OwnershipOf(c Connector, chosen string, t Task) Ownership {
	if !c.MemberScoped() {
		return OwnerKeep
	}
	return DecideOwnership(OwnershipInput{Chosen: chosen, User: t.User, ServiceUser: t.ServiceUser})
}

// --- the user picker ---------------------------------------------------------

// VendorUserCandidate is one vendor user the picker offers: a user the
// organization's list reported, with the number of listed sessions it
// started and, when one of its messages names it, its username (display
// only, never the key).
type VendorUserCandidate struct {
	UserID   string `json:"user_id"`
	Username string `json:"username,omitempty"`
	Sessions int    `json:"sessions"`
}

// MaxUserNameReads bounds the message reads one candidate listing makes:
// one page of one session per distinct user, for at most this many users.
const MaxUserNameReads = 10

// UserCandidatePlan is the picker plan from one listed page: the candidates
// (users with at least one session, most sessions first) and, on a connector
// whose users are named only on their own messages (Devin), for the first
// MaxUserNameReads of them the one session whose messages are read for the
// username. A connector whose list itself names its users (Warp,
// ParseListUserNames) or that names none (OpenHands: ids only) plans no
// probe.
type UserCandidatePlan struct {
	Candidates []VendorUserCandidate
	// Probes are (user id, session id) pairs, in candidate order.
	Probes []UserProbe
	// ServiceUserSessions / NoUserSessions count listed sessions no person
	// started (never offered as a choice).
	ServiceUserSessions int
	NoUserSessions      int
}

// UserProbe is one username read: the messages of SessionID name UserID.
type UserProbe struct {
	UserID    string
	SessionID string
}

// PlanUserCandidates groups listed tasks by vendor user. A user id outside
// the connector's grammar is not offered (it could never be chosen).
func PlanUserCandidates(c Connector, tasks []Task) UserCandidatePlan {
	var plan UserCandidatePlan
	if !c.MemberScoped() {
		return plan
	}
	type acc struct {
		n      int
		newest Task
	}
	by := map[string]*acc{}
	for _, t := range tasks {
		switch DecideOwnership(OwnershipInput{User: t.User, ServiceUser: t.ServiceUser}) {
		case OwnerSkipServiceUser:
			plan.ServiceUserSessions++
			continue
		case OwnerSkipNoUser:
			plan.NoUserSessions++
			continue
		}
		if !ValidVendorUser(c, t.User) {
			plan.NoUserSessions++
			continue
		}
		a := by[t.User]
		if a == nil {
			a = &acc{newest: t}
			by[t.User] = a
		}
		a.n++
		if t.UpdatedAt.After(a.newest.UpdatedAt) {
			a.newest = t
		}
	}
	for id, a := range by {
		plan.Candidates = append(plan.Candidates, VendorUserCandidate{UserID: id, Sessions: a.n})
	}
	sort.Slice(plan.Candidates, func(i, j int) bool {
		a, b := plan.Candidates[i], plan.Candidates[j]
		if a.Sessions != b.Sessions {
			return a.Sessions > b.Sessions
		}
		return a.UserID < b.UserID
	})
	if !namesFromHistory(c) {
		return plan
	}
	for _, cand := range plan.Candidates {
		if len(plan.Probes) >= MaxUserNameReads {
			break
		}
		plan.Probes = append(plan.Probes, UserProbe{UserID: cand.UserID, SessionID: by[cand.UserID].newest.ID})
	}
	return plan
}

// namesFromHistory reports whether the connector's users are named on their
// own history records (one message read per user, Devin).
func namesFromHistory(c Connector) bool {
	d, err := apiFor(c)
	return err == nil && d.userName != nil && d.history != nil
}

// ParseListUserNames returns the display names one list page itself carries
// for its users (user id -> name), on a connector whose list names them
// (Warp: a user creator's display_name); nil on any other. The page is
// validated by the connector's list driver first; only the creator's type,
// id and display name are read from it (never its e-mail, the prompt or the
// title). Only ids of the connector's grammar are kept; each name is display
// only, bounded and stripped of control and bidirectional formatting
// characters, and is never stored.
func ParseListUserNames(c Connector, params map[string]string, cursorIn string, body []byte) (map[string]string, error) {
	d, err := apiFor(c)
	if err != nil {
		return nil, err
	}
	if !c.MemberScoped() || d.listUserNames == nil {
		return nil, nil
	}
	if _, err := parseDriver(d.list, c, "", driverParams(c, params, ""), cursorIn, body); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for id, name := range d.listUserNames(body) {
		if !ValidVendorUser(c, id) {
			continue
		}
		if n := cleanDisplayName(name); n != "" {
			out[id] = n
		}
	}
	return out, nil
}

// warpRunCreators is the narrow view of a Warp runs page the picker reads:
// each run's creator type, uid and display name, nothing else.
type warpRunCreators struct {
	Runs []struct {
		Creator *struct {
			Type        *string `json:"type"`
			UID         *string `json:"uid"`
			DisplayName *string `json:"display_name"`
		} `json:"creator"`
	} `json:"runs"`
}

// warpListUserNames maps each person creator's uid to the first non-empty
// display name the page gives it. A service account is never a person and
// is never named here (warpCreators).
func warpListUserNames(body []byte) map[string]string {
	var doc warpRunCreators
	if json.Unmarshal(body, &doc) != nil {
		return nil
	}
	out := map[string]string{}
	for _, r := range doc.Runs {
		c := r.Creator
		if c == nil || c.Type == nil || c.UID == nil || c.DisplayName == nil || !warpCreatorIsPerson(*c.Type) {
			continue
		}
		uid, name := strings.TrimSpace(*c.UID), strings.TrimSpace(*c.DisplayName)
		if _, named := out[uid]; named || uid == "" || name == "" {
			continue
		}
		out[uid] = name
	}
	return out
}

// UserNameRequest builds the one message read of a probe (the first history
// page of its session).
func UserNameRequest(c Connector, params map[string]string, p UserProbe) (Request, error) {
	if !c.MemberScoped() || !ValidSessionID(p.SessionID) {
		return Request{}, errInvalid("not a member-scoped connector or not a session id")
	}
	return APIHistoryRequest(c, params, p.SessionID, "", time.Time{}, time.Time{})
}

// ParseUserName returns the username the probe's user carries on one of its
// own messages in a history page ("" when no message names it). The page is
// validated by the connector's history driver first; only the user id,
// source and username are kept from it (the message text is never read
// here). The name is display only: bounded and stripped of control and
// bidirectional formatting characters.
func ParseUserName(c Connector, params map[string]string, p UserProbe, body []byte) (string, error) {
	d, err := apiFor(c)
	if err != nil {
		return "", err
	}
	if !c.MemberScoped() || d.userName == nil || d.history == nil {
		return "", errInvalid("connector names no users")
	}
	if _, err := parseDriver(*d.history, c, "", driverParams(c, params, p.SessionID), "", body); err != nil {
		return "", err
	}
	return cleanDisplayName(d.userName(body, p.UserID)), nil
}

// devinMessageUser is the narrow view of a Devin message the picker reads.
type devinMessageUser struct {
	Items []struct {
		Source   *string `json:"source"`
		UserID   *string `json:"user_id"`
		Username *string `json:"username"`
	} `json:"items"`
}

// devinUserName returns the username of the first message of source "user"
// whose user_id is userID.
func devinUserName(body []byte, userID string) string {
	var doc devinMessageUser
	if json.Unmarshal(body, &doc) != nil {
		return ""
	}
	for _, m := range doc.Items {
		if m.Source == nil || *m.Source != "user" || m.UserID == nil || *m.UserID != userID || m.Username == nil {
			continue
		}
		if name := strings.TrimSpace(*m.Username); name != "" {
			return name
		}
	}
	return ""
}

// maxDisplayName bounds a vendor username kept for display.
const maxDisplayName = 128

// cleanDisplayName bounds a vendor display value and replaces control and
// bidirectional formatting characters with '?'; invalid UTF-8 is dropped.
func cleanDisplayName(s string) string {
	s = strings.TrimSpace(s)
	if !utf8.ValidString(s) {
		return ""
	}
	if len(s) > maxDisplayName {
		cut := maxDisplayName
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut]
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) || !unicode.IsPrint(r) {
			return '?'
		}
		return r
	}, s)
}
