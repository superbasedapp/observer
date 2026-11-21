package planlimits

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"time"
)

// drv_appserver.go is the official local route to ChatGPT-plan (Codex)
// windows: the documented Codex App Server JSON-RPC method
// account/rateLimits/read (https://learn.chatgpt.com/docs/app-server).
//
// Transport (documented): `codex app-server` over stdio, newline-delimited
// JSON, JSON-RPC 2.0 with the "jsonrpc" member omitted on the wire. The
// client sends initialize, then the initialized notification, then requests;
// the server may interleave notifications, which are skipped. Observer never
// asks for a token refresh (account/read refreshToken=false).

// AppServerArgv is the fixed launch vector: read-only sandbox, never ask for
// approval, so the server cannot be coaxed into writes.
var AppServerArgv = []string{"codex", "-s", "read-only", "-a", "never", "app-server"}

// AppServerClientName is the clientInfo.name sent at initialize. The vendor
// uses it to identify the client in compliance logs, so it is honest.
const AppServerClientName = "superbased_observer_plans"

func init() {
	register(SourceCodexAppServer, Driver{Converse: converseAppServer, Argv: AppServerArgv})
}

type rpcMsg struct {
	ID     *int64          `json:"id,omitempty"`
	Method string          `json:"method,omitempty"`
	Params any             `json:"params,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// rpcSession is one app-server conversation over a reader and a writer.
type rpcSession struct {
	w      io.Writer
	r      *bufio.Scanner
	nextID int64
}

func newRPCSession(w io.Writer, r io.Reader) *rpcSession {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	return &rpcSession{w: w, r: sc}
}

func (s *rpcSession) send(m rpcMsg) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	_, err = s.w.Write(append(b, '\n'))
	return err
}

// call sends one request and waits for the response with the same id.
func (s *rpcSession) call(method string, params any) (json.RawMessage, error) {
	id := s.nextID
	s.nextID++
	if err := s.send(rpcMsg{ID: &id, Method: method, Params: params}); err != nil {
		return nil, fmt.Errorf("%w: app-server %s: %s", ErrTransient, method, err.Error())
	}
	for s.r.Scan() {
		var m rpcMsg
		if json.Unmarshal(s.r.Bytes(), &m) != nil || m.ID == nil || *m.ID != id {
			continue // a notification, noise, or another id
		}
		if m.Error != nil {
			return nil, fmt.Errorf("%w: app-server %s: %s", ErrShape, method, SanitizeLabel(m.Error.Message))
		}
		return m.Result, nil
	}
	return nil, fmt.Errorf("%w: app-server %s: closed", ErrTransient, method)
}

// AppServerWindow is the documented window shape.
type AppServerWindow struct {
	UsedPercent        float64 `json:"usedPercent"`
	WindowDurationMins *int64  `json:"windowDurationMins"`
	ResetsAt           *int64  `json:"resetsAt"`
}

// AppServerBucket is one rate-limit bucket.
type AppServerBucket struct {
	LimitID              string           `json:"limitId"`
	Primary              *AppServerWindow `json:"primary"`
	Secondary            *AppServerWindow `json:"secondary"`
	PlanType             *string          `json:"planType"`
	RateLimitReachedType *string          `json:"rateLimitReachedType"`
	Credits              *struct {
		HasCredits bool    `json:"hasCredits"`
		Unlimited  bool    `json:"unlimited"`
		Balance    *string `json:"balance"`
	} `json:"credits"`
}

// AppServerRateLimits is the account/rateLimits/read result.
type AppServerRateLimits struct {
	RateLimits          *AppServerBucket           `json:"rateLimits"`
	RateLimitsByLimitID map[string]AppServerBucket `json:"rateLimitsByLimitId"`
}

func converseAppServer(w io.Writer, r io.Reader, in PlanInput) (Snapshot, error) {
	s := newRPCSession(w, r)
	if _, err := s.call("initialize", map[string]any{"clientInfo": map[string]string{
		"name": AppServerClientName, "title": "SuperBased Observer Plans & limits", "version": in.Params["observer_version"],
	}}); err != nil {
		return Snapshot{}, err
	}
	if err := s.send(rpcMsg{Method: "initialized", Params: map[string]any{}}); err != nil {
		return Snapshot{}, fmt.Errorf("%w: app-server initialized: %s", ErrTransient, err.Error())
	}
	var acct struct {
		Account *struct {
			Type     string  `json:"type"`
			PlanType *string `json:"planType"`
		} `json:"account"`
	}
	if raw, err := s.call("account/read", map[string]any{"refreshToken": false}); err == nil {
		_ = json.Unmarshal(raw, &acct) // the email in the result is never read
	}
	if acct.Account != nil && acct.Account.Type != "chatgpt" {
		return Snapshot{}, fmt.Errorf("%w: Codex is not signed in with ChatGPT", ErrNotApplicable)
	}
	raw, err := s.call("account/rateLimits/read", nil)
	if err != nil {
		return Snapshot{}, err
	}
	var rl AppServerRateLimits
	if err := json.Unmarshal(raw, &rl); err != nil {
		return Snapshot{}, shapeErr("app-server rate limits", err)
	}
	plan := ""
	if acct.Account != nil && acct.Account.PlanType != nil {
		plan = *acct.Account.PlanType
	}
	snap, err := MapAppServer(rl, plan, in.Now)
	if err != nil {
		return snap, err
	}
	snap.Usage = readAppServerUsage(s)
	return snap, nil
}

// readAppServerUsage asks the same session for the account's daily token
// totals (account/usage/read, params null). It runs only after the rate-limit
// reading is in hand and is fail-soft by construction: an error, a closed
// pipe, a timeout or an unknown shape yields nil and never touches the
// reading, so the snapshot is exactly what it would be without this call.
// No thread id is sent: only the account-wide daily buckets are wanted.
func readAppServerUsage(s *rpcSession) *UsageReport {
	// An explicit JSON null, as the live probe sent it (a nil params member
	// would be omitted from the wire).
	raw, err := s.call("account/usage/read", json.RawMessage("null"))
	if err != nil {
		return nil
	}
	u, ok := ParseAppServerUsage(raw)
	if !ok {
		return nil
	}
	return &u
}

// MapAppServer converts a rateLimits result onto the model. The default
// bucket yields 5h/weekly by declared duration (never by position); other
// buckets yield model:<limitId>:<5h|weekly> windows, in a stable order.
func MapAppServer(rl AppServerRateLimits, accountPlan string, now time.Time) (Snapshot, error) {
	s := newSnap(ProviderChatGPT, SourceCodexAppServer, KindVendorRPC, ConfPercentOnly, now)
	s.PlanCode = SanitizeLabel(accountPlan)
	addBucket := func(prefix string, b AppServerBucket) {
		if b.PlanType != nil && *b.PlanType != "" {
			s.PlanCode = SanitizeLabel(*b.PlanType)
		}
		for _, w := range []*AppServerWindow{b.Primary, b.Secondary} {
			if w == nil {
				continue
			}
			class := "5h"
			var length *time.Duration
			if w.WindowDurationMins != nil {
				class = windowKeyForMinutes(*w.WindowDurationMins)
				length = dur(time.Duration(*w.WindowDurationMins) * time.Minute)
			}
			key := prefix + class
			if _, dup := FindWindow(s, key); dup {
				continue
			}
			nw := Window{Key: key, Unit: UnitPercent, UsedFrac: fracFromPercent(w.UsedPercent), Length: length, Rolling: true}
			if w.ResetsAt != nil {
				nw.ResetsAt = unixPtr(*w.ResetsAt)
			}
			s.Windows = append(s.Windows, nw)
		}
		if c := b.Credits; c != nil && c.HasCredits && !c.Unlimited && c.Balance != nil {
			if f, err := strconv.ParseFloat(*c.Balance, 64); err == nil {
				if _, have := FindBalance(s, "credits"); !have {
					s.Balances = append(s.Balances, Balance{Kind: "credits", Unit: UnitCredits, Amount: int64(f)})
				}
			}
		}
		if b.RateLimitReachedType != nil && *b.RateLimitReachedType != "" {
			s.Status = StatusThrottled
		}
	}
	if rl.RateLimits != nil {
		addBucket("", *rl.RateLimits)
	}
	ids := make([]string, 0, len(rl.RateLimitsByLimitID))
	for id := range rl.RateLimitsByLimitID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		b := rl.RateLimitsByLimitID[id]
		switch {
		case rl.RateLimits != nil && id == rl.RateLimits.LimitID:
			continue
		case id == "codex" && rl.RateLimits == nil:
			addBucket("", b)
		default:
			addBucket("model:"+slug(id)+":", b)
		}
	}
	if len(s.Windows)+len(s.Balances) == 0 {
		return Snapshot{}, shapeErr("app-server: no windows", nil)
	}
	return s, nil
}
