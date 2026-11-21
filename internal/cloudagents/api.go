package cloudagents

import (
	"encoding/json"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/tooltax"
	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	"github.com/marmutapp/superbased-observer/internal/vendorapi/cline"
	"github.com/marmutapp/superbased-observer/internal/vendorapi/cognition"
	"github.com/marmutapp/superbased-observer/internal/vendorapi/cursor"
	"github.com/marmutapp/superbased-observer/internal/vendorapi/openhands"
	"github.com/marmutapp/superbased-observer/internal/vendorapi/qoder"
	"github.com/marmutapp/superbased-observer/internal/vendorapi/warp"
)

// The API connectors (lane CA-B2): cursor-cloud, devin, openhands-cloud.
// Every request is built by a lane CA-A4 pure driver (internal/vendorapi/
// cursor, cognition, openhands) and every response is parsed by the same
// driver; this file turns the driver's request into an absolute URL on the
// row's own host and maps the driver's page onto Task and Activity through
// one function per surface (CA-D6). The key never enters this package.

// apiDrivers binds an API connector to the A4 drivers of each operation.
type apiDrivers struct {
	list    vendorapi.Driver
	detail  map[DetailKind]vendorapi.Driver
	history *vendorapi.Driver
	// stream builds a run stream path (no A4 driver exists for the SSE
	// route; the path is the documented /v1/agents/{id}/runs/{runId}/stream).
	stream bool
	// userName reads, from one history page, the username a member-scoped
	// connector's user carries on its own messages (the user picker,
	// owner.go); nil for a connector that names no users.
	userName func(body []byte, userID string) string
	// listUserNames reads, from one list page, the display name each of a
	// member-scoped connector's users carries on the list itself (Warp: a
	// user creator's display_name; ParseListUserNames); nil for a connector
	// whose list names no users.
	listUserNames func(body []byte) map[string]string
}

var apiTable = map[string]apiDrivers{
	ConnectorCursorCloud: {
		list: cursor.CloudAgents(),
		detail: map[DetailKind]vendorapi.Driver{
			DetailRuns:  cursor.CloudAgentRuns(),
			DetailUsage: cursor.CloudAgentUsage(),
		},
		stream: true,
	},
	ConnectorDevin: {
		list:     cognition.OrgSessions(),
		history:  ptrDriver(cognition.SessionMessages()),
		userName: devinUserName,
	},
	ConnectorOpenHandsCloud: {
		list:    openhands.AppConversations(),
		history: ptrDriver(openhands.Events()),
	},
	// Lane CA-V1. The run transcript (a 302 to a signed URL off the exact
	// host) has no binding: it is never fetched.
	ConnectorWarpCloud: {
		list:          warp.RunsList(),
		detail:        map[DetailKind]vendorapi.Driver{DetailHarnessUsage: warp.RunHarnessUsage()},
		history:       ptrDriver(warp.RunConversation()),
		listUserNames: warpListUserNames,
	},
	ConnectorQoderCloud: {
		list:    qoder.CloudSessions(),
		detail:  map[DetailKind]vendorapi.Driver{DetailEnvironment: qoder.CloudEnvironment()},
		history: ptrDriver(qoder.CloudEvents()),
	},
	// Lane CA-V6 (cline.go).
	ConnectorClineCloud: {
		list:    cline.Sessions(),
		detail:  map[DetailKind]vendorapi.Driver{DetailStatus: cline.SessionStatus()},
		history: ptrDriver(cline.SessionHistory()),
	},
}

func ptrDriver(d vendorapi.Driver) *vendorapi.Driver { return &d }

func apiFor(c Connector) (apiDrivers, error) {
	d, ok := apiTable[c.ID]
	if !ok || c.Kind != SourceAPI {
		return apiDrivers{}, errInvalid("not an API connector")
	}
	return d, nil
}

// orgIDRE bounds a Devin organization id (the A4 driver's own rule).
var orgIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// paramRules validate an API connector's free-form connection parameters (a
// picker parameter is validated against its Choices instead).
var paramRules = map[string]*regexp.Regexp{ParamOrgID: orgIDRE}

// ValidateParams checks the non-secret connection parameters a connector
// declares and returns the ones it uses; an undeclared or malformed one is
// refused.
func ValidateParams(c Connector, in map[string]string) (map[string]string, error) {
	out := map[string]string{}
	for k := range in {
		if !c.declares(k) && strings.TrimSpace(in[k]) != "" {
			return nil, errInvalid("connector takes no parameter " + strconv.Quote(k))
		}
	}
	for _, p := range c.Params {
		v := strings.TrimSpace(in[p.Name])
		if v == "" {
			return nil, errInvalid(p.Label + " is required")
		}
		if re := paramRules[p.Name]; re != nil && !re.MatchString(v) {
			return nil, errInvalid(p.Label + " is not a valid id")
		}
		if len(p.Choices) > 0 && !p.offers(v) {
			return nil, errInvalid(p.Label + " must be one of the listed choices")
		}
		out[p.Name] = v
	}
	return out, nil
}

// offers reports whether v is one of a picker parameter's choices.
func (p ParamSpec) offers(v string) bool {
	for _, ch := range p.Choices {
		if ch.Value == v {
			return true
		}
	}
	return false
}

// AccountParamSep separates the key account id from a picker parameter's
// value in the account id of a connector whose account is the stored key
// (Qoder: "keychain-key@cn"), so the parameter survives in the account row
// and two regions are two accounts.
const AccountParamSep = "@"

func (c Connector) declares(name string) bool {
	for _, p := range c.Params {
		if p.Name == name {
			return true
		}
	}
	return false
}

// AccountParams returns the parameters a linked account's requests use. A
// connector with a parameter keeps it as the account id (Devin: the
// organization), so nothing besides the key is stored outside the account
// row.
func AccountParams(c Connector, accountID string) map[string]string {
	out := map[string]string{}
	if len(c.Params) != 1 {
		return out
	}
	p := c.Params[0]
	if len(p.Choices) == 0 {
		out[p.Name] = accountID
		return out
	}
	// A picker parameter rides on the key account id; one that is not a
	// listed choice is dropped, so the request builder refuses it.
	if _, v, ok := strings.Cut(accountID, AccountParamSep); ok && p.offers(v) {
		out[p.Name] = v
	}
	return out
}

// driverParams maps connector parameters onto a driver's parameter names.
func driverParams(c Connector, params map[string]string, sessionID string) vendorapi.Params {
	p := vendorapi.Params{}
	switch c.ID {
	case ConnectorDevin:
		p[cognition.ParamOrgID] = params[ParamOrgID]
		if sessionID != "" {
			p[cognition.ParamSessionID] = sessionID
		}
	case ConnectorCursorCloud:
		if sessionID != "" {
			p[cursor.ParamAgentID] = sessionID
		}
	case ConnectorOpenHandsCloud:
		if sessionID != "" {
			p[openhands.ParamConversationID] = sessionID
		}
	case ConnectorWarpCloud:
		if sessionID != "" {
			p[warp.ParamRunID] = sessionID
		}
	case ConnectorQoderCloud:
		if sessionID != "" {
			p[qoder.ParamSessionID] = sessionID
		}
	case ConnectorClineCloud:
		if sessionID != "" {
			p[cline.ParamSessionID] = sessionID
		}
	}
	return p
}

// baseURLFor is the https origin of an account's requests: the region host
// its parameters pick on a row with a region table (never a fallback), else
// the row's one host.
func baseURLFor(c Connector, params map[string]string) (string, error) {
	if len(c.Regions) == 0 {
		return c.BaseURL(), nil
	}
	r, ok := c.RegionFor(params)
	if !ok {
		return "", errInvalid("the account names no known region")
	}
	return "https://" + r.Host, nil
}

// apiRequest turns a driver request into an egress request on the host the
// account's parameters select (baseURLFor).
func apiRequest(c Connector, params map[string]string, op Op, r vendorapi.Request, accept string) (Request, error) {
	if r.Method != "GET" || r.Body != nil || !strings.HasPrefix(r.Path, "/") {
		return Request{}, errInvalid("the driver built a request this connector does not send")
	}
	base, err := baseURLFor(c, params)
	if err != nil {
		return Request{}, err
	}
	u := base + r.Path
	if q := encodeQuery(r.Query); q != "" {
		u += "?" + q
	}
	return Request{Connector: c.ID, Op: op, URL: u, Auth: c.Auth, Accept: accept, Absent: c.AbsentFor(op)}, nil
}

// encodeQuery renders a query with every byte outside RFC 3986's unreserved
// set percent-encoded, keys sorted (deterministic for tests and logs).
func encodeQuery(q map[string][]string) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		for _, v := range q[k] {
			if b.Len() > 0 {
				b.WriteByte('&')
			}
			b.WriteString(escape(k))
			b.WriteByte('=')
			b.WriteString(escape(v))
		}
	}
	return b.String()
}

func escape(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '.' || ch == '_' || ch == '~' {
			b.WriteByte(ch)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[ch>>4])
		b.WriteByte(hex[ch&15])
	}
	return b.String()
}

// parseDriver runs a driver's parser over a 2xx body and validates the page.
func parseDriver(d vendorapi.Driver, c Connector, path string, p vendorapi.Params, cursorIn string, body []byte) (vendorapi.Page, error) {
	resp := vendorapi.Response{Status: 200, Origin: c.BaseURL() + ":443", Path: path, Body: body, Params: p, Cursor: cursorIn}
	var (
		page vendorapi.Page
		err  error
	)
	switch {
	case d.ParseResponse != nil:
		page, err = d.ParseResponse(resp)
	case d.Parse != nil:
		page, err = d.Parse(body)
	default:
		return vendorapi.Page{}, errInvalid("driver has no parser")
	}
	if err != nil {
		return vendorapi.Page{}, wrongShape(string(d.Surface) + " response is not the documented shape")
	}
	if err := vendorapi.Validate(page); err != nil {
		return vendorapi.Page{}, wrongShape(string(d.Surface) + " response failed validation")
	}
	return page, nil
}

// --- identity -------------------------------------------------------------

// KeychainKeyAccount is the account id of an API connector whose vendor
// documents no call naming the key's owner: the account is "the key stored
// in the keychain for this connector on this machine" (one per connector;
// connecting again replaces the key).
const KeychainKeyAccount = "keychain-key"

// cursorMePath is GET /v1/me (Cloud Agents API "API Key Info", fixture
// testdata/vendorapi/cursor/cursor.cloudagent.meta, a verbatim official
// example). Its closed shape and parser are the org driver's
// (cursor.ParseKeyInfo, lane CA-C8), so the node and the org read the key's
// owner the same way.
const cursorMePath = "/v1/me"

// APIIdentityRequest builds the connect probe of an API connector: Cursor
// reads the key's user (GET /v1/me); Devin and OpenHands read one list page
// (it proves the key works and reads nothing else).
func APIIdentityRequest(c Connector, params map[string]string) (Request, error) {
	d, err := apiFor(c)
	if err != nil {
		return Request{}, err
	}
	if c.ID == ConnectorCursorCloud {
		return Request{Connector: c.ID, Op: OpIdentity, URL: c.BaseURL() + cursorMePath, Auth: c.Auth, Accept: AcceptJSON}, nil
	}
	r, err := d.list.Build(driverParams(c, params, ""), vendorapi.Window{}, "")
	if err != nil {
		return Request{}, errInvalid("bad connection parameter")
	}
	req, err := apiRequest(c, params, OpIdentity, r, AcceptJSON)
	if err != nil {
		return Request{}, err
	}
	return req, nil
}

// ParseAPIIdentity parses a connect probe's response.
func ParseAPIIdentity(c Connector, params map[string]string, body []byte) (Identity, error) {
	d, err := apiFor(c)
	if err != nil {
		return Identity{}, err
	}
	switch c.ID {
	case ConnectorCursorCloud:
		me, err := cursor.ParseKeyInfo(body)
		if err != nil || me.UserID <= 0 {
			return Identity{}, wrongShape("GET /v1/me returned no user id")
		}
		// The e-mail is display only and comes from the vendor: kept only
		// when it has an address's shape (KeyKindUser = a positive user id
		// AND an e-mail-shaped value, which admits no control, bidi or
		// other non-printable character), else dropped, never stored raw.
		display := ""
		if me.Kind == cursor.KeyKindUser {
			display = boundField(me.Email)
		}
		return Identity{AccountID: "user:" + strconv.FormatInt(me.UserID, 10), Display: display}, nil
	case ConnectorDevin:
		if _, err := parseDriver(d.list, c, "", driverParams(c, params, ""), "", body); err != nil {
			return Identity{}, err
		}
		return Identity{AccountID: params[ParamOrgID], Display: "organization " + params[ParamOrgID]}, nil
	case ConnectorQoderCloud:
		// No documented call names the token's owner: the account is the
		// stored key, in the picked region.
		r, ok := c.RegionFor(params)
		if !ok {
			return Identity{}, errInvalid("the account names no known region")
		}
		if _, err := parseDriver(d.list, c, "", driverParams(c, params, ""), "", body); err != nil {
			return Identity{}, err
		}
		return Identity{AccountID: KeychainKeyAccount + AccountParamSep + r.ID, Display: "region " + r.Label}, nil
	default:
		if _, err := parseDriver(d.list, c, "", driverParams(c, params, ""), "", body); err != nil {
			return Identity{}, err
		}
		return Identity{AccountID: KeychainKeyAccount}, nil
	}
}

// --- discovery --------------------------------------------------------------

// APIListRequest builds one discovery page. A connector that filters on the
// server is asked for [since, until) (a zero since lists everything).
func APIListRequest(c Connector, params map[string]string, since, until time.Time, cursorIn string) (Request, error) {
	d, err := apiFor(c)
	if err != nil {
		return Request{}, err
	}
	w := vendorapi.Window{}
	if c.ServerWindow && !since.IsZero() && until.After(since) {
		w = vendorapi.Window{From: since, To: until}
	}
	r, err := d.list.Build(driverParams(c, params, ""), w, cursorIn)
	if err != nil {
		return Request{}, errInvalid("bad list request")
	}
	return apiRequest(c, params, OpList, r, AcceptJSON)
}

// ParseAPIList parses one discovery page into tasks.
func ParseAPIList(c Connector, params map[string]string, cursorIn string, body []byte) (Page, error) {
	d, err := apiFor(c)
	if err != nil {
		return Page{}, err
	}
	vp, err := parseDriver(d.list, c, "", driverParams(c, params, ""), cursorIn, body)
	if err != nil {
		return Page{}, err
	}
	p := Page{Cursor: vp.NextCursor}
	if p.Cursor != "" && !ValidCursor(p.Cursor) {
		return Page{}, wrongShape("list returned an unusable cursor")
	}
	usage := map[string][]vendorapi.UsageRow{}
	for _, u := range vp.Usage {
		usage[u.SessionRef] = append(usage[u.SessionRef], u)
	}
	for _, s := range vp.Snapshots {
		t, ok := mapSnapshot(c, s, usage[s.Subject])
		if ok {
			p.Tasks = append(p.Tasks, t)
		}
	}
	return p, nil
}

// snapshotTime reads an RFC 3339 body value (the drivers render UTC
// seconds).
func snapshotTime(body map[string]string, key string) time.Time {
	t, err := time.Parse(time.RFC3339, body[key])
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// mapSnapshot is the one mapping from a driver's session snapshot (and its
// usage rows) to a Task.
func mapSnapshot(c Connector, s vendorapi.VendorSnapshot, usage []vendorapi.UsageRow) (Task, bool) {
	if !ValidSessionID(s.Subject) {
		return Task{}, false
	}
	b := s.Body
	t := Task{
		Connector: c.ID, ID: s.Subject,
		CreatedAt: snapshotTime(b, "created_at"), UpdatedAt: snapshotTime(b, "updated_at"),
	}
	status, detail := b["status"], ""
	var end time.Time
	switch s.Class {
	case cursor.CloudAgentClass:
		t.DetailPending = len(c.Detail) > 0
	case cognition.SessionClass:
		detail = b["status_detail"]
		t.RepoRemote = RemoteFromURL(b["pr_url"])
		if _, n := PullRequestFromURL(b["pr_url"]); n > 0 {
			t.PullRequestNumber, t.PullRequestURL = n, boundField(b["pr_url"])
		}
		// The person who started the session and, apart, the service user
		// (an automation or an organization API key). The organization's
		// list holds every member's sessions: OwnershipOf keeps only the
		// account's chosen user's (CLOUDAGENTS-6).
		t.User = boundField(b["user_id"])
		t.ServiceUser = boundField(b["service_user_id"])
		t.ParentID = boundField(b["parent_session_id"])
		if v := b["on_demand_usage_usd"]; v != "" {
			if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0 {
				no := false
				t.Usage = append(t.Usage, UsageFigure{
					Unit: "usd", Value: f, ValueType: models.UsageValueCumulative, Source: models.UsageSourceProviderRunTotal,
					MonetaryStatus: models.UsageMonetaryReported, IncludesChildren: &no, ReportedAt: t.UpdatedAt,
				})
			}
		}
		for _, u := range usage {
			if u.ChargedUnit == cognition.UnitACU {
				t.Usage = append(t.Usage, UsageFigure{
					Unit: "acu", Value: float64(u.ChargedMicros) / 1e6, ValueType: models.UsageValueCumulative,
					Source: models.UsageSourceProviderRunTotal, MonetaryStatus: models.UsageMonetaryNone, ReportedAt: u.At,
				})
			}
		}
	case qoder.CloudSessionClass:
		t = qoderTask(c, t, b, usage)
	case openhands.ConversationClass:
		status = firstNonEmpty(b["execution_status"], b["sandbox_status"])
		t.RepoRemote = remoteFromProvider(b["git_provider"], b["selected_repository"])
		// The conversation's creator. The search lists every conversation
		// the key can see (an organization's too): OwnershipOf keeps only
		// the account's chosen user's (CLOUDAGENTS-6, CA-T8). A
		// conversation naming no creator is never assumed to be the key
		// owner's.
		t.User = boundField(b["created_by_user_id"])
		t.ParentID = boundField(b["parent_conversation_id"])
		for _, u := range usage {
			if u.Flags[openhands.InputBasisFlag] != "" {
				t.Tokens = &TokenFigure{
					Kind: TokenFromProviderRunTotal, Model: boundField(u.Model),
					Input: netInput(u.InputTokens, u.CacheReadTokens), Output: u.OutputTokens,
					CacheRead: u.CacheReadTokens, CacheCreation: u.CacheWriteTokens, Reasoning: u.ReasoningTokens,
					ReportedAt: u.At,
				}
			}
			if u.ChargedUnit == openhands.ChargedUnitUSD {
				t.Usage = append(t.Usage, UsageFigure{
					Unit: "usd", Value: float64(u.ChargedMicros) / 1e6, ValueType: models.UsageValueCumulative,
					Source: models.UsageSourceProviderRunTotal, MonetaryStatus: models.UsageMonetaryReported,
					ReportedAt: u.At, Model: boundField(u.Model),
				})
			}
		}
	case warp.RunClass:
		if !mapWarpRun(&t, b, usage) {
			return Task{}, false
		}
		status = b["state"]
	case cline.SessionClass:
		status, detail, end = mapClineSession(b, &t, time.Now().UTC())
	default:
		return Task{}, false
	}
	t.VendorStatus = boundToken(status)
	t.Lifecycle = c.LifecycleOfDetail(status, detail)
	if t.Lifecycle.Terminal() {
		t.CompletedAt = t.UpdatedAt
		if f := snapshotTime(b, "finished_at"); !f.IsZero() {
			t.CompletedAt = f
		}
		if !end.IsZero() {
			t.CompletedAt = end
		}
	}
	return t, true
}

// warpExecutionRules decide whether a listed Warp run is landed and where it
// ran, walked top-down on its execution_location and worker_host. The list
// is asked for REMOTE runs only; a LOCAL run (executed in the user's own
// Warp app) is refused here too, so the cloud connector never lands what a
// local adapter owns. An absent execution_location is the REMOTE filter's
// answer and is trusted.
var warpExecutionRules = []struct {
	name string
	when func(loc, worker string) bool
	land bool
	at   string
}{
	{"a local run is not a cloud session", func(loc, _ string) bool { return loc != "" && loc != warp.ExecutionRemote }, false, ""},
	{"a self-hosted worker is customer compute", func(_, w string) bool { return w != "" && !strings.EqualFold(w, "warp") }, true, models.ExecutionCustomerWorker},
	{"otherwise Warp-hosted", func(string, string) bool { return true }, true, ""},
}

// mapWarpRun fills a Warp run's task fields (lane CA-V1): the conversation
// id as the second reference, the parent run as lineage, the harness (which
// decides the tool, ForTask), the first pull request's repository, and the
// run's request_usage as two ledger figures, Warp credits and billed USD,
// never summed (CA-D11). It reports false for a run the connector does not
// land.
func mapWarpRun(t *Task, b map[string]string, usage []vendorapi.UsageRow) bool {
	for _, r := range warpExecutionRules {
		if r.when(b["execution_location"], b["worker_host"]) {
			if !r.land {
				return false
			}
			t.ExecutionLocation = r.at
			break
		}
	}
	if ref := b["conversation_id"]; ref != "" && ValidSessionID(ref) {
		t.VendorRef = ref
	}
	t.ParentID = boundField(b["parent_run_id"])
	t.Harness = boundToken(b["harness"])
	if fill, ok := warpCreators[strings.ToLower(b["creator_type"])]; ok {
		fill(t, boundField(b["creator_uid"]))
	}
	t.RepoRemote = RemoteFromURL(b["pr_url"])
	if _, n := PullRequestFromURL(b["pr_url"]); n > 0 {
		t.PullRequestNumber, t.PullRequestURL = n, boundField(b["pr_url"])
	}
	for _, u := range usage {
		f, ok := warpUnits[u.ChargedUnit]
		if !ok || u.JoinValue != t.ID {
			continue
		}
		t.Usage = append(t.Usage, UsageFigure{
			Unit: f.unit, Value: float64(u.ChargedMicros) / 1e6, ValueType: models.UsageValueCumulative,
			Source: models.UsageSourceProviderRunTotal, MonetaryStatus: f.monetary, ReportedAt: u.At,
			Model: boundField(u.Model),
		})
	}
	return true
}

// warpCreatorUser and warpCreatorServiceAccount are the documented
// RunCreatorInfo types (OpenAPI; grounding wave-c section 1).
const (
	warpCreatorUser           = "user"
	warpCreatorServiceAccount = "service_account"
)

// warpCreators maps a run's creator.type to the Task field its uid fills
// (CLOUDAGENTS-6, CA-T8). A person's uid is the run's User, the one the
// ownership table compares with the account's chosen Warp user. A service
// account (the team's Default Service Account an Agent key acts as, or an
// integration) is the run's ServiceUser: it names no person, so the run is
// never landed on a member-scoped account (OwnerSkipServiceUser). A type
// with no row (absent, or one Warp adds later) fills neither: the run names
// no one and is skipped (OwnerSkipNoUser), never guessed to be a person's.
var warpCreators = map[string]func(t *Task, uid string){
	warpCreatorUser:           func(t *Task, uid string) { t.User = uid },
	warpCreatorServiceAccount: func(t *Task, uid string) { t.ServiceUser = uid },
}

// warpCreatorIsPerson reports whether a creator type names a person.
func warpCreatorIsPerson(kind string) bool { return strings.ToLower(kind) == warpCreatorUser }

// warpUnits maps a Warp usage row's unit to its ledger unit and monetary
// status: credits are not money; the USD amount is what the run was billed
// at, as Warp reports it.
var warpUnits = map[string]struct{ unit, monetary string }{
	warp.UnitCredit: {"warp_credit", models.UsageMonetaryNone},
	warp.UnitUSD:    {"usd", models.UsageMonetaryReported},
}

// netInput nets a prompt total that includes cache reads (the LiteLLM
// convention OpenHands reports through; hand-back CA-B2 records it as
// documented, not live-verified). Never negative.
func netInput(prompt, cacheRead int64) int64 {
	if prompt > cacheRead {
		return prompt - cacheRead
	}
	return 0
}

// providerHosts maps an OpenHands git_provider to its host.
var providerHosts = map[string]string{"github": "github.com", "gitlab": "gitlab.com", "bitbucket": "bitbucket.org"}

func remoteFromProvider(provider, slug string) string {
	host, ok := providerHosts[strings.ToLower(strings.TrimSpace(provider))]
	if !ok || !ValidRepoSlug(slug) {
		return ""
	}
	return host + "/" + slug
}

// prSegments are the path segments after owner/repo that make a URL a pull
// or merge request of that repository (GitHub, GitLab, Bitbucket).
var prSegments = map[string]bool{"pull": true, "pulls": true, "-": true, "merge_requests": true, "pull-requests": true}

// RemoteFromURL returns the hosted remote "host/owner/repo" a repository
// URL or a pull request URL names ("https://github.com/o/r", "github.com/o/r.git",
// "https://github.com/o/r/pull/7"), or "" when it names none. Nothing is
// guessed: an unknown trailing path is refused.
func RemoteFromURL(raw string) string {
	s := strings.TrimSpace(raw)
	for _, p := range []string{"https://", "http://"} {
		s = strings.TrimPrefix(s, p)
	}
	if strings.ContainsAny(s, "@?# ") {
		return ""
	}
	parts := strings.Split(strings.TrimSuffix(s, "/"), "/")
	if len(parts) < 3 || !strings.Contains(parts[0], ".") {
		return ""
	}
	if len(parts) > 3 && !prSegments[parts[3]] {
		return ""
	}
	slug := parts[1] + "/" + strings.TrimSuffix(parts[2], ".git")
	if !ValidRepoSlug(slug) {
		return ""
	}
	return strings.ToLower(parts[0]) + "/" + slug
}

// PullRequestFromURL returns the repository ("host/owner/repo") and the
// number a pull or merge request URL names ("https://github.com/o/r/pull/7"
// -> "github.com/o/r", 7). A URL that names a repository but no request, or
// anything else, yields number 0; nothing is guessed.
func PullRequestFromURL(raw string) (remote string, number int64) {
	remote = RemoteFromURL(raw)
	if remote == "" {
		return "", 0
	}
	s := strings.TrimSpace(raw)
	for _, p := range []string{"https://", "http://"} {
		s = strings.TrimPrefix(s, p)
	}
	parts := strings.Split(strings.TrimSuffix(s, "/"), "/")
	// host/owner/repo/<segment>/N, or GitLab's host/owner/repo/-/merge_requests/N.
	i := 3
	if len(parts) > i && parts[i] == "-" {
		i++
	}
	if len(parts) != i+2 || !prSegments[parts[i]] || parts[i] == "-" {
		return remote, 0
	}
	n, err := strconv.ParseInt(parts[i+1], 10, 64)
	if err != nil || n <= 0 {
		return remote, 0
	}
	return remote, n
}

// --- detail (Cursor runs and usage) -----------------------------------------

// APIDetailRequest builds one detail call for a session on a row whose
// detail calls take only the session id and one host (Cursor).
func APIDetailRequest(c Connector, kind DetailKind, sessionID string) (Request, error) {
	return APIDetailRequestFor(c, nil, kind, Task{ID: sessionID})
}

// detailIDs picks, per detail kind, the driver parameters of a task's
// detail call: the session itself, or the environment it ran in.
var detailIDs = map[DetailKind]func(Task) vendorapi.Params{
	DetailRuns:  func(t Task) vendorapi.Params { return vendorapi.Params{cursor.ParamAgentID: t.ID} },
	DetailUsage: func(t Task) vendorapi.Params { return vendorapi.Params{cursor.ParamAgentID: t.ID} },
	// Warp (lane CA-V1): a run's harness usage, by the run id.
	DetailHarnessUsage: func(t Task) vendorapi.Params { return vendorapi.Params{warp.ParamRunID: t.ID} },
	// Cline (lane CA-V6): a session's status, by the session id.
	DetailStatus: func(t Task) vendorapi.Params { return vendorapi.Params{cline.ParamSessionID: t.ID} },
	DetailEnvironment: func(t Task) vendorapi.Params {
		return vendorapi.Params{qoder.ParamEnvironmentID: t.EnvironmentID}
	},
}

// APIDetailRequestFor builds one detail call for a task on the host the
// account's parameters select.
func APIDetailRequestFor(c Connector, params map[string]string, kind DetailKind, t Task) (Request, error) {
	d, err := apiFor(c)
	if err != nil {
		return Request{}, err
	}
	drv, ok := d.detail[kind]
	ids, known := detailIDs[kind]
	if !ok || !known {
		return Request{}, errInvalid("connector has no " + string(kind) + " detail")
	}
	r, err := drv.Build(ids(t), vendorapi.Window{}, "")
	if err != nil {
		return Request{}, errInvalid("bad session or environment id")
	}
	return apiRequest(c, params, OpDetail, r, AcceptJSON)
}

// detailSkippable lists the detail kinds whose read may fail for one task
// without failing the pass, and the failure classes that may: an
// environment that is gone or not readable (403/404) leaves the session's
// location unknown, never the pass failed.
var detailSkippable = map[DetailKind]map[ErrorClass]bool{
	DetailEnvironment: {ErrPermissionDenied: true},
}

// DetailSkippable reports whether a failed detail read of kind is skipped
// for its task (the rest of the pass goes on).
func DetailSkippable(kind DetailKind, err error) bool { return detailSkippable[kind][ClassOf(err)] }

// ApplyAPIDetail folds one detail response into a task: the runs fill the
// repository, the lifecycle (the latest run's) and Runs; the usage fills the
// agent's token total and the vendor-reported cost of each finished run
// (runCosts). The row's detail order reads the runs first, so the usage read
// finds them.
func ApplyAPIDetail(c Connector, kind DetailKind, t Task, body []byte) (Task, error) {
	d, err := apiFor(c)
	if err != nil {
		return t, err
	}
	drv, ok := d.detail[kind]
	if !ok {
		return t, errInvalid("connector has no " + string(kind) + " detail")
	}
	vp, err := parseDriver(drv, c, "", detailIDs[kind](t), "", body)
	if err != nil {
		return t, err
	}
	switch kind {
	case DetailHarnessUsage:
		for _, u := range vp.Usage {
			if u.JoinNamespace == warp.HarnessUsageNamespace && u.JoinValue == t.ID {
				t.Tokens = warpTokens(u)
			}
		}
	case DetailEnvironment:
		t = applyQoderEnvironment(t, vp.Snapshots)
	case DetailRuns:
		t = applyRuns(c, t, vp.Snapshots)
	case DetailStatus:
		t = applyClineStatus(c, t, vp.Snapshots)
	case DetailUsage:
		t.Usage = withoutRunCosts(t.Usage)
		var total map[string]string
		for _, s := range vp.Snapshots {
			switch {
			case s.Class == cursor.CloudAgentUsageClass && s.Subject == t.ID:
				t.Tokens = cursorTokens(s.Body, t.UpdatedAt)
				total = s.Body
			case s.Class == cursor.CloudAgentRunUsageClass:
				t.Usage = append(t.Usage, runCosts(t, s)...)
			}
		}
		t.Usage = append(t.Usage, unattributedCosts(t, total)...)
	}
	return t, nil
}

// costMeasures are the two vendor-reported amounts of a Cursor run's usage
// (live-verified 2026-11-01), each landed as its own ledger measurement in
// US dollars (the vendor reports cents; the value is divided by 100, never
// derived from tokens, CA-D11). rawCostCents is what the usage would cost at
// list rates, so it is an API-list-price equivalent and never a charge;
// chargedCents is what was billed (0 on a plan's included usage).
var costMeasures = []struct {
	key      string
	monetary string
}{
	{"raw_cost_cents", models.UsageMonetaryAPIEquivalent},
	{"charged_cents", models.UsageMonetaryReported},
}

// runCosts maps one run usage snapshot to its cost figures. Only a run the
// runs read shows as ended lands: its amounts are final, so the ledger row
// keyed by the run's usageUuid is landed once and a re-read never changes or
// duplicates it. A run still going (its cost may grow), one the runs read
// did not list, or one without a usageUuid lands nothing yet.
func runCosts(t Task, s vendorapi.VendorSnapshot) []UsageFigure {
	uuid := s.Body["usage_uuid"]
	if uuid == "" {
		return nil
	}
	var run *Run
	for i := range t.Runs {
		if t.Runs[i].ID == s.Subject {
			run = &t.Runs[i]
		}
	}
	if run == nil || !run.Lifecycle.Terminal() {
		return nil
	}
	var out []UsageFigure
	for _, m := range costMeasures {
		v, ok := s.Body[m.key]
		if !ok {
			continue
		}
		cents, err := strconv.ParseFloat(v, 64)
		if err != nil || cents < 0 {
			continue
		}
		f := UsageFigure{
			Unit: "usd", Value: cents / 100, ValueType: models.UsageValueInterval,
			Source: models.UsageSourceProviderRunTotal, MonetaryStatus: m.monetary,
			ReportedAt: run.UpdatedAt, RecordID: uuid, Run: run.ID,
		}
		if !run.CreatedAt.IsZero() && !run.UpdatedAt.Before(run.CreatedAt) {
			f.IntervalStart, f.IntervalEnd = run.CreatedAt, run.UpdatedAt
		}
		out = append(out, f)
	}
	return out
}

// RevisableUnattributed is the Revisable key of an agent's cost that no
// run reports.
const RevisableUnattributed = "unattributed"

// unattributedCosts is the part of the agent's reported cost that its landed
// run rows do not carry: the agent total minus the sum of the runs landed
// from this read, per measure, clamped at zero. Live 2026-11-01 the agent
// total exceeded the sum of its runs by 35 to 50 percent on three of four
// agents (work reported on the agent but on no run), and a run still going
// is not landed yet, so its cost is here until it ends. With the run rows
// (value type interval, summed) this row makes the agent's full reported
// cost count exactly once. It moves when a run starts or ends, so it is
// Revisable: one live revision per agent and measure, each change
// superseding the previous one (ResolveRevisions), never frozen.
func unattributedCosts(t Task, total map[string]string) []UsageFigure {
	if total == nil {
		return nil
	}
	var out []UsageFigure
	for _, m := range costMeasures {
		v, ok := total[m.key]
		if !ok {
			continue
		}
		cents, err := strconv.ParseFloat(v, 64)
		if err != nil || cents < 0 {
			continue
		}
		for _, f := range t.Usage {
			if f.Run != "" && f.MonetaryStatus == m.monetary {
				cents -= f.Value * 100
			}
		}
		// Round away float noise (the vendor reports at most 1e-5 cents).
		cents = math.Round(cents*1e6) / 1e6
		if cents <= 0 {
			cents = 0
		}
		f := UsageFigure{
			Unit: "usd", Value: cents / 100, ValueType: models.UsageValueInterval,
			Source: models.UsageSourceProviderRunTotal, MonetaryStatus: m.monetary,
			ReportedAt: t.UpdatedAt, Revisable: RevisableUnattributed,
		}
		if !t.CreatedAt.IsZero() && !t.UpdatedAt.Before(t.CreatedAt) {
			f.IntervalStart, f.IntervalEnd = t.CreatedAt, t.UpdatedAt
		}
		out = append(out, f)
	}
	return out
}

// withoutRunCosts drops the cost figures a previous usage read put on the
// task (per run and unattributed), so applying a usage read twice does not
// repeat them.
func withoutRunCosts(in []UsageFigure) []UsageFigure {
	var out []UsageFigure
	for _, f := range in {
		if f.Run == "" && f.Revisable == "" {
			out = append(out, f)
		}
	}
	return out
}

func applyRuns(c Connector, t Task, snaps []vendorapi.VendorSnapshot) Task {
	var runs []Run
	repo := map[string]string{}
	for _, s := range snaps {
		if s.Class != cursor.CloudAgentRunClass || !ValidSessionID(s.Subject) {
			continue
		}
		r := Run{
			ID: s.Subject, Status: boundToken(s.Body["status"]), Lifecycle: c.LifecycleOf(s.Body["status"]),
			CreatedAt: snapshotTime(s.Body, "created_at"), UpdatedAt: snapshotTime(s.Body, "updated_at"),
		}
		if r.UpdatedAt.IsZero() {
			r.UpdatedAt = r.CreatedAt
		}
		r.Remote = RemoteFromURL(s.Body["repo_url"])
		if r.Remote != "" {
			r.Branch = boundField(s.Body["branch"])
		}
		runs = append(runs, r)
		repo[r.ID] = r.Remote
	}
	sort.SliceStable(runs, func(i, j int) bool { return runs[i].CreatedAt.Before(runs[j].CreatedAt) })
	t.Runs = runs
	for i := len(runs) - 1; i >= 0; i-- {
		if r := repo[runs[i].ID]; r != "" {
			t.RepoRemote = r
			break
		}
	}
	if n := len(runs); n > 0 {
		latest := runs[n-1]
		if latest.Lifecycle != LifecycleUnknown {
			t.VendorStatus, t.Lifecycle = latest.Status, latest.Lifecycle
		}
		if latest.UpdatedAt.After(t.UpdatedAt) {
			t.UpdatedAt = latest.UpdatedAt
		}
		t.CompletedAt = time.Time{}
		if t.Lifecycle.Terminal() {
			t.CompletedAt = latest.UpdatedAt
		}
	}
	return t
}

// cursorTokens reads an agent usage snapshot body; the Cloud Agents usage
// counts are already split (input excludes cache reads and writes: the
// fixture's total equals the four parts). An absent count is absent.
func cursorTokens(b map[string]string, at time.Time) *TokenFigure {
	read := func(k string) (int64, bool) {
		v, ok := b[k]
		if !ok {
			return 0, false
		}
		n, err := strconv.ParseInt(v, 10, 64)
		return n, err == nil && n >= 0
	}
	f := &TokenFigure{Kind: TokenFromProviderRunTotal, ReportedAt: at}
	any := false
	for _, x := range []struct {
		key string
		dst *int64
	}{{"input", &f.Input}, {"output", &f.Output}, {"cache_read", &f.CacheRead}, {"cache_write", &f.CacheCreation}} {
		if n, ok := read(x.key); ok {
			*x.dst = n
			any = true
		}
	}
	if !any {
		return nil
	}
	return f
}

// warpBasis nets a native counter by its basis flag: Codex reports input
// including cached input and output including reasoning (the OpenAI
// convention, the Codex adapter's netting); Claude Code's input already
// excludes the cache counters. Never negative.
var warpBasis = map[string]func(u vendorapi.UsageRow) (in, out int64){
	warp.BasisNetOfCache + "/" + warp.BasisNoReasoningSplit: func(u vendorapi.UsageRow) (int64, int64) {
		return u.InputTokens, u.OutputTokens
	},
	warp.BasisIncludesCached + "/" + warp.BasisIncludesReasoning: func(u vendorapi.UsageRow) (int64, int64) {
		return netInput(u.InputTokens, u.CacheReadTokens), netInput(u.OutputTokens, u.ReasoningTokens)
	},
}

// warpTokens maps a run's harness usage row to its token figure at the
// provider-run-total tier (CA-D12). The counters are cumulative and only
// grow, and the token row's counts only move up (store MAX upgrade), so the
// newest snapshot wins. A basis the table does not know lands nothing.
func warpTokens(u vendorapi.UsageRow) *TokenFigure {
	net, ok := warpBasis[u.Flags[warp.FlagInputBasis]+"/"+u.Flags[warp.FlagOutputBasis]]
	if !ok {
		return nil
	}
	in, out := net(u)
	f := &TokenFigure{
		Kind: TokenFromProviderRunTotal, Model: boundField(u.Model), Input: in, Output: out,
		CacheRead: u.CacheReadTokens, CacheCreation: u.CacheWriteTokens, Reasoning: u.ReasoningTokens, ReportedAt: u.At,
	}
	if v, err := strconv.ParseInt(u.Flags[warp.FlagCache1h], 10, 64); err == nil && v >= 0 && v <= f.CacheCreation {
		f.CacheCreation1h = v
	}
	return f
}

// --- history (Devin messages, OpenHands events, Warp conversations) ---------

// HistoryCursor is a session_history checkpoint's cursor for an API
// connector: the position to resume the session's history from, and
// whether its detail is still pending.
type HistoryCursor struct {
	// After is the page cursor that fetched the last page read (Devin: the
	// "after" value; re-reading that page is the overlap, deduplicated by
	// message id). "" starts at the beginning.
	After string `json:"a,omitempty"`
	// Since is the newest event time read (OpenHands); the next pass asks
	// for events from Since minus the overlap.
	Since time.Time `json:"s,omitempty"`
	// DetailPending marks a session whose detail calls are still owed.
	DetailPending bool `json:"p,omitempty"`
	// StreamsOwed marks a session with at least one run stream a later pass
	// still has to read (over the per-pass stream budget, still open, or a
	// transient failure). Such a session is re-read on the next pass even
	// when the list does not show it as changed.
	StreamsOwed bool `json:"o,omitempty"`
	// Lifecycle is the session's lifecycle when it was last listed.
	Lifecycle string `json:"l,omitempty"`
	// Harness is the session's harness when it was last listed (Warp), so a
	// pass that re-reads it without listing it still knows its tool.
	Harness string `json:"h,omitempty"`
}

// Owed reports whether the cursor's session still owes a read (detail or a
// run stream) whatever its lifecycle.
func (h HistoryCursor) Owed() bool { return h.DetailPending || h.StreamsOwed }

// CheckpointLifecycle is the lifecycle a session_history checkpoint records:
// an API connector's history cursor carries it as JSON, a CLI connector's
// cursor is the lifecycle token itself. A checkpoint that records none is
// unknown (never assumed finished).
func CheckpointLifecycle(cursor string) Lifecycle {
	s := strings.TrimSpace(cursor)
	if strings.HasPrefix(s, "{") {
		if l := DecodeHistoryCursor(s).Lifecycle; l != "" {
			return Lifecycle(l)
		}
		return LifecycleUnknown
	}
	if s == "" {
		return LifecycleUnknown
	}
	return Lifecycle(s)
}

// EncodeHistoryCursor renders a history cursor for the checkpoint (bounded
// below the store's field limit: an over-long page cursor is dropped, which
// re-reads from the start and is deduplicated).
func EncodeHistoryCursor(h HistoryCursor) string {
	if len(h.After) > 400 {
		h.After = ""
	}
	b, _ := jsonMarshal(h)
	return string(b)
}

// DecodeHistoryCursor reads a checkpoint cursor; junk is the zero cursor.
func DecodeHistoryCursor(s string) HistoryCursor {
	var h HistoryCursor
	if jsonUnmarshal([]byte(s), &h) != nil {
		return HistoryCursor{}
	}
	if h.After != "" && !ValidCursor(h.After) {
		h.After = ""
	}
	if h.Harness != "" && boundToken(h.Harness) != h.Harness {
		h.Harness = ""
	}
	return h
}

// HistoryPage is one parsed page of a session's history.
type HistoryPage struct {
	Activity []Activity
	// Next continues the history in this pass ("" = the end).
	Next string
	// Newest is the newest record time on the page.
	Newest time.Time
	// Records counts the vendor records the page parsed (landed or not).
	Records int
	// Tokens and Usage are the figures the page reported: Cline's summed
	// message metrics for the session (landed in the ledger with the
	// session); nil and empty otherwise. Qoder's events report none (their
	// credits repeat the session's cumulative total).
	Tokens *TokenFigure
	Usage  []UsageFigure
}

// APIHistoryRequest builds one history page for a session: cursorIn is the
// page cursor within this pass (or the checkpoint's After on the first
// page), since the checkpoint's Since minus the overlap (OpenHands).
func APIHistoryRequest(c Connector, params map[string]string, sessionID, cursorIn string, since, until time.Time) (Request, error) {
	d, err := apiFor(c)
	if err != nil {
		return Request{}, err
	}
	if d.history == nil {
		return Request{}, errInvalid("connector has no history call")
	}
	w := vendorapi.Window{}
	if c.HistoryWindow && !since.IsZero() && until.After(since) {
		w = vendorapi.Window{From: since, To: until}
	}
	r, err := d.history.Build(driverParams(c, params, sessionID), w, cursorIn)
	if err != nil {
		return Request{}, errInvalid("bad history request")
	}
	return apiRequest(c, params, OpHistory, r, AcceptJSON)
}

// ParseAPIHistory parses one history page into metadata-only activity:
// messages become prompt/response records without their text, tool calls
// carry the tool name only, every other event kind is counted.
func ParseAPIHistory(c Connector, params map[string]string, sessionID, cursorIn string, body []byte) (HistoryPage, error) {
	d, err := apiFor(c)
	if err != nil {
		return HistoryPage{}, err
	}
	if d.history == nil {
		return HistoryPage{}, errInvalid("connector has no history call")
	}
	vp, err := parseDriver(*d.history, c, "", driverParams(c, params, sessionID), cursorIn, body)
	if err != nil {
		return HistoryPage{}, err
	}
	hp := HistoryPage{Next: vp.NextCursor, Records: vp.SourceRecords}
	if hp.Next != "" && !ValidCursor(hp.Next) {
		return HistoryPage{}, wrongShape("history returned an unusable cursor")
	}
	if c.ID == ConnectorQoderCloud {
		qoderHistory(vp, sessionID, &hp)
		return hp, nil
	}
	seen := func(at time.Time) {
		if at.After(hp.Newest) {
			hp.Newest = at
		}
	}
	for _, ci := range vp.Content {
		if ci.SessionRef != sessionID {
			continue
		}
		kind, ok := contentKinds[ci.Role]
		if !ok {
			continue
		}
		hp.Activity = append(hp.Activity, Activity{ID: "msg:" + ci.ItemID, At: ci.At, Kind: kind})
		seen(ci.At)
	}
	calls := map[string]int{}
	for _, a := range vp.Audit {
		seen(a.At)
		if a.AgentSessionID != sessionID {
			continue
		}
		switch a.Action {
		case "tool_call":
			calls[a.EventID] = len(hp.Activity)
			hp.Activity = append(hp.Activity, Activity{ID: "ev:" + a.EventID, At: a.At, Kind: ActivityToolCall, Tool: toolToken(a.Target)})
		case "tool_result":
			// A result that names its call (Warp action_result) settles the
			// call's outcome; one that names none (OpenHands) is counted.
			i, ok := calls[a.Detail["action_id"]]
			r, known := resultStates[a.Detail["state"]]
			if !ok || !known {
				continue
			}
			hp.Activity[i].OutcomeKnown, hp.Activity[i].Failed, hp.Activity[i].Pending = r.known, r.failed, !r.known
		}
	}
	for _, u := range vp.Usage {
		if u.SessionRef != sessionID || u.JoinNamespace != cline.UsageNamespace {
			continue
		}
		tok, usage := clineHistoryFigures(u)
		if tok != nil {
			hp.Tokens = tok
		}
		hp.Usage = append(hp.Usage, usage...)
		seen(u.At)
	}
	return hp, nil
}

// resultStates maps a tool result's state (Warp ActionState) to the call's
// outcome. A state with no row leaves the call as it was.
var resultStates = map[string]struct{ known, failed bool }{
	"completed": {true, false},
	"failed":    {true, true},
	"denied":    {true, true},
	"running":   {false, false},
}

// contentKinds maps a driver content role to an activity kind.
var contentKinds = map[string]ActivityKind{"prompt": ActivityPrompt, "response": ActivityResponse}

// --- stream (Cursor) --------------------------------------------------------

// reRunID bounds a run id before it enters a stream path.
var reRunID = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,256}$`)

// APIStreamRequest builds a run's event stream request: GET
// /v1/agents/{id}/runs/{runId}/stream, resumed with Last-Event-ID when one
// is stored (reference chapter 02, CU01).
func APIStreamRequest(c Connector, agentID, runID, lastEventID string) (Request, error) {
	d, err := apiFor(c)
	if err != nil {
		return Request{}, err
	}
	if !d.stream {
		return Request{}, errInvalid("connector has no stream")
	}
	// The A4 runs driver validates the agent id and escapes it.
	r, err := d.detail[DetailRuns].Build(driverParams(c, nil, agentID), vendorapi.Window{}, "")
	if err != nil || !reRunID.MatchString(runID) {
		return Request{}, errInvalid("bad agent or run id")
	}
	if strings.ContainsAny(lastEventID, "\r\n\x00") || len(lastEventID) > MaxSSEEventID {
		return Request{}, errInvalid("bad Last-Event-ID")
	}
	return Request{
		Connector: c.ID, Op: OpStream, URL: c.BaseURL() + r.Path + "/" + runID + "/stream",
		Auth: c.Auth, Accept: AcceptEventStream, LastEventID: lastEventID,
	}, nil
}

// --- activity mapping -------------------------------------------------------

// activityActions maps a non-tool activity kind to its action type.
var activityActions = map[ActivityKind]string{
	ActivityPrompt:   models.ActionUserPrompt,
	ActivityResponse: models.ActionAssistantMessage,
}

// activityRawNames are the raw tool names of the non-tool records.
var activityRawNames = map[ActivityKind]string{
	ActivityPrompt:   "cloud_message:prompt",
	ActivityResponse: "cloud_message:response",
}

// MapActivity maps metadata-only activity to actions: messages as
// user_prompt / assistant_message rows with no text, tool calls through the
// canonical taxonomy (internal/tooltax) under the connector's tool
// vocabulary (Connector.Vocabulary), unknown names as "unknown" with the raw
// name kept. Ids are stable, so re-reads are idempotent.
func MapActivity(c Connector, sessionID, projectRoot string, acts []Activity) []models.ToolEvent {
	if sessionID == "" || projectRoot == "" {
		return nil
	}
	out := make([]models.ToolEvent, 0, len(acts))
	for _, a := range acts {
		if a.At.IsZero() || a.ID == "" {
			continue
		}
		ev := models.ToolEvent{
			SourceFile: SourceFile(c.ID), SourceEventID: c.ID + ":" + sessionID + ":" + a.ID,
			SessionID: sessionID, ProjectRoot: projectRoot, Timestamp: a.At, Tool: c.Tool, Success: !a.Failed,
			Target: a.Target, OutcomePending: a.Pending,
		}
		switch a.Kind {
		case ActivityToolCall:
			ev.ActionType, _ = tooltax.ResolveActionType(c.Vocabulary(), a.Tool)
			ev.RawToolName = a.Tool
			if ev.RawToolName == "" {
				ev.RawToolName = "cloud_tool_call"
			}
		default:
			at, ok := activityActions[a.Kind]
			if !ok {
				continue
			}
			ev.ActionType, ev.RawToolName = at, activityRawNames[a.Kind]
		}
		out = append(out, ev)
	}
	return out
}

// MapOutcomes returns the outcome patches for the activities whose outcome
// is known: a call landed in an earlier read while still running keeps its
// row (the insert never updates it) and gets its measured success here,
// under the same source event id MapActivity gave it. Only success is
// patched; no error text and no output (the result is never stored).
func MapOutcomes(c Connector, sessionID string, acts []Activity) []models.ActionOutcomeUpdate {
	if sessionID == "" {
		return nil
	}
	var out []models.ActionOutcomeUpdate
	for _, a := range acts {
		if a.Kind != ActivityToolCall || !a.OutcomeKnown || a.ID == "" {
			continue
		}
		out = append(out, models.ActionOutcomeUpdate{
			SourceFile: SourceFile(c.ID), SourceEventID: c.ID + ":" + sessionID + ":" + a.ID,
			SuccessKnown: true, Success: !a.Failed,
		})
	}
	return out
}

// ChildLink is a parent-to-child agent link a run stream reported, or (Fork)
// a session continuing another one (Cline: a local task handed off to the
// cloud).
type ChildLink struct {
	Parent, Child string
	// Fork marks a continuation rather than a spawned subagent.
	Fork bool
}

// ChildLineage is the lineage stamp for a child agent's session: its
// parent thread is the agent whose run created it. A fork is a user fork
// instead (forked_from_id with thread_source "user", the teleport shape of
// internal/adapter/claudecode), so a handed-off session is never counted as
// a subagent. Nothing is guessed; a link without two distinct valid ids
// yields none.
func ChildLineage(l ChildLink) (models.SessionLineage, bool) {
	if !ValidSessionID(l.Parent) || !ValidSessionID(l.Child) || l.Parent == l.Child {
		return models.SessionLineage{}, false
	}
	if l.Fork {
		return models.SessionLineage{SessionID: l.Child, ForkedFromID: l.Parent, ThreadSource: ThreadSourceUser}, true
	}
	return models.SessionLineage{SessionID: l.Child, ParentThreadID: l.Parent, ThreadSource: ThreadSourceSubagent}, true
}

// ThreadSourceUser is the thread_source of a normal or user-forked session.
const ThreadSourceUser = "user"

// forkCursorPrefix marks a fork link in a lineage checkpoint's cursor.
const forkCursorPrefix = "fork:"

// LinkCursor is the checkpoint cursor that records a pending link: the
// parent id, prefixed for a fork.
func LinkCursor(l ChildLink) string {
	if l.Fork {
		return forkCursorPrefix + l.Parent
	}
	return l.Parent
}

// LinkFromCursor rebuilds a pending link from its checkpoint (LinkCursor);
// a bare parent id is a subagent link, as checkpoints written before forks
// existed are.
func LinkFromCursor(child, cursor string) ChildLink {
	if p, ok := strings.CutPrefix(cursor, forkCursorPrefix); ok {
		return ChildLink{Parent: p, Child: child, Fork: true}
	}
	return ChildLink{Parent: cursor, Child: child}
}

// ThreadSourceSubagent is the thread_source of a session another agent
// spawned (the vocabulary the codex lineage uses).
const ThreadSourceSubagent = "subagent"

// APIOps lists every request shape the API connectors can produce, with
// placeholder ids, for review and the egress host test.
func APIOps() []Request {
	var out []Request
	for _, c := range Connectors {
		if c.Kind != SourceAPI {
			continue
		}
		params := map[string]string{}
		for _, p := range c.Params {
			params[p.Name] = "org-1"
		}
		// A row with regions produces one request set per region.
		regions := []map[string]string{params}
		if len(c.Regions) > 0 {
			regions = nil
			for _, r := range c.Regions {
				regions = append(regions, map[string]string{ParamRegion: r.ID})
			}
		}
		add := func(r Request, err error) {
			if err == nil {
				out = append(out, r)
			}
		}
		for _, params := range regions {
			add(APIIdentityRequest(c, params))
			add(APIListRequest(c, params, time.Time{}, time.Time{}, ""))
			for _, k := range c.Detail {
				add(APIDetailRequestFor(c, params, k, Task{ID: "bc-00000000-0000-0000-0000-000000000001", EnvironmentID: "env_1"}))
			}
			if c.History {
				add(APIHistoryRequest(c, params, "s1", "", time.Time{}, time.Time{}))
			}
		}
		if c.Stream {
			add(APIStreamRequest(c, "bc-00000000-0000-0000-0000-000000000001", "run-1", ""))
		}
	}
	return out
}

func jsonMarshal(v any) ([]byte, error)   { return json.Marshal(v) }
func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

// TaskFromSnapshot is the one snapshot mapping (mapSnapshot) exported for the
// org server's vendor-connection projection (lane CA-C3, CA-D6): the org
// runner lands the same A4 driver's snapshots the node connector parses, and
// the org projection turns a landed snapshot into a Task through this same
// function, so the lifecycle tables, the repository rule and the lineage
// field are written once. usage are the driver's usage rows for the same
// session (none when the caller has none; a Task's Usage then stays empty).
// It returns false for a connector that is not an API connector, a class the
// connector does not parse, or a subject that is not a session id.
func TaskFromSnapshot(connectorID string, s vendorapi.VendorSnapshot, usage []vendorapi.UsageRow) (Task, bool) {
	c, ok := ConnectorByID(connectorID)
	if !ok || c.Kind != SourceAPI {
		return Task{}, false
	}
	return mapSnapshot(c, s, usage)
}
