package dirac

import (
	"bufio"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Presentation-log file names (bundle constants mm.uiMessageOperations /
// mm.uiMessagesBaseline).
const (
	uiOpsName      = "ui_messages.jsonl"
	uiBaselineName = "ui_messages.baseline.jsonl"
)

// uiStatus is the token-bearing subset of a Dirac `api_status`
// presentation message — one per API request, keyed `api-req-<ms>`. It
// is the ONLY place the per-request split Dirac computes is persisted:
// the api-history `metrics.tokens.cached` folds cache writes into cache
// reads and carries no reasoning count. Pointers distinguish "absent"
// from a reported zero. `startMs` is the request's start (the creating
// message's `ts`, which is also the `<ms>` of its id): the assistant
// message that answers it is persisted when the stream ends
// (`ts:Date.now()` in the bundle), so the pair is the request's own
// start+end — the generation span.
type uiStatus struct {
	TokensIn        *int64   `json:"tokensIn"`
	TokensOut       *int64   `json:"tokensOut"`
	ReasoningTokens *int64   `json:"reasoningTokens"`
	CacheWrites     *int64   `json:"cacheWrites"`
	CacheReads      *int64   `json:"cacheReads"`
	Cost            *float64 `json:"cost"`

	startMs int64
}

// usable reports whether the status carries a completed usage report.
func (s *uiStatus) usable() bool { return s.TokensIn != nil && s.TokensOut != nil }

// merge applies a `patch_api_status` patch (only the token keys are
// tracked) and its `deletions`.
func (s *uiStatus) merge(p uiStatus, deletions []string) {
	if p.TokensIn != nil {
		s.TokensIn = p.TokensIn
	}
	if p.TokensOut != nil {
		s.TokensOut = p.TokensOut
	}
	if p.ReasoningTokens != nil {
		s.ReasoningTokens = p.ReasoningTokens
	}
	if p.CacheWrites != nil {
		s.CacheWrites = p.CacheWrites
	}
	if p.CacheReads != nil {
		s.CacheReads = p.CacheReads
	}
	if p.Cost != nil {
		s.Cost = p.Cost
	}
	for _, d := range deletions {
		switch d {
		case "tokensIn":
			s.TokensIn = nil
		case "tokensOut":
			s.TokensOut = nil
		case "reasoningTokens":
			s.ReasoningTokens = nil
		case "cacheWrites":
			s.CacheWrites = nil
		case "cacheReads":
			s.CacheReads = nil
		case "cost":
			s.Cost = nil
		}
	}
}

func val(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

// uiCard is the timing-bearing subset of a tool `card` presentation
// message. A card's `toolName` names the tool (read_file, execute_command,
// edit_file, respond, ...); `startTime`/`endTime` are the tool's own start
// and end (Date.now() at card creation / completion), so end-start is the
// tool's real execution time (a hook running before the tool is not in
// it). Approval cards (`requireApproval`, header "Permission Request" /
// "Execute: <cmd>") share the tool's name but their span is the HUMAN's
// wait, so they never count as execution.
type uiCard struct {
	toolName string
	status   string
	start    int64
	end      int64
	approval bool
}

// done reports whether the card finished (status success/error, with an
// end stamp). A card still running has no duration yet.
func (c *uiCard) done() bool {
	return c.end > 0 && c.end >= c.start && c.status != "running" && c.status != "waiting_for_input"
}

// uiMessage is the subset of a presentation message this adapter reads.
type uiMessage struct {
	ID      string `json:"id"`
	Ts      int64  `json:"ts"`
	Content struct {
		Type   string   `json:"type"`
		Status uiStatus `json:"status"`
		Card   *struct {
			ToolName        string `json:"toolName"`
			Status          string `json:"status"`
			StartTime       int64  `json:"startTime"`
			EndTime         int64  `json:"endTime"`
			RequireApproval bool   `json:"requireApproval"`
		} `json:"card"`
	} `json:"content"`
}

// uiOp is one presentation-log record. `create`, `patch_api_status`,
// `patch_card` and `reset` touch the state this adapter tracks;
// `message` is the baseline-file record shape. `patch` is decoded per
// op type (its shape differs between api_status and card patches).
type uiOp struct {
	Type      string          `json:"type"`
	ID        string          `json:"id"`
	Message   *uiMessage      `json:"message"`
	Messages  []uiMessage     `json:"messages"`
	Patch     json.RawMessage `json:"patch"`
	Deletions []string        `json:"deletions"`
}

// cardPatch is the subset of a `patch_card` patch that carries timing.
type cardPatch struct {
	Status  *string `json:"status"`
	EndTime *int64  `json:"endTime"`
}

// uiLog is the replayed presentation state: the creation-ordered
// api_status list (token split + request start times) and the tool cards.
type uiLog struct {
	order  []string
	byID   map[string]*uiStatus
	cards  map[string]*uiCard
	corder []string
}

func newUILog() *uiLog {
	return &uiLog{byID: map[string]*uiStatus{}, cards: map[string]*uiCard{}}
}

func (l *uiLog) add(m *uiMessage) {
	if m == nil || m.ID == "" {
		return
	}
	switch m.Content.Type {
	case "api_status":
		if _, ok := l.byID[m.ID]; ok {
			return
		}
		st := m.Content.Status
		st.startMs = m.Ts
		if st.startMs <= 0 {
			st.startMs = apiReqMillis(m.ID)
		}
		l.byID[m.ID] = &st
		l.order = append(l.order, m.ID)
	case "card":
		c := m.Content.Card
		if c == nil || c.ToolName == "" {
			return
		}
		if _, ok := l.cards[m.ID]; ok {
			return
		}
		l.cards[m.ID] = &uiCard{
			toolName: c.ToolName, status: c.Status,
			start: c.StartTime, end: c.EndTime, approval: c.RequireApproval,
		}
		l.corder = append(l.corder, m.ID)
	}
}

// apiReqMillis parses the `<ms>` of an `api-req-<ms>` id (0 when the id
// is another shape).
func apiReqMillis(id string) int64 {
	const prefix = "api-req-"
	if !strings.HasPrefix(id, prefix) {
		return 0
	}
	n, err := strconv.ParseInt(strings.TrimPrefix(id, prefix), 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

func (l *uiLog) apply(op *uiOp) {
	switch op.Type {
	case "create", "message":
		l.add(op.Message)
	case "patch_api_status":
		if st, ok := l.byID[op.ID]; ok {
			var p uiStatus
			_ = json.Unmarshal(op.Patch, &p)
			st.merge(p, op.Deletions)
		}
	case "patch_card":
		if c, ok := l.cards[op.ID]; ok {
			var p cardPatch
			if json.Unmarshal(op.Patch, &p) == nil {
				if p.Status != nil {
					c.status = *p.Status
				}
				if p.EndTime != nil {
					c.end = *p.EndTime
				}
			}
		}
	case "reset":
		l.order, l.byID = nil, map[string]*uiStatus{}
		l.corder, l.cards = nil, map[string]*uiCard{}
		for i := range op.Messages {
			l.add(&op.Messages[i])
		}
	}
}

// uiData is the replayed presentation state in the shape the parser
// consumes: the COMPLETED statuses in creation order, every status's
// start time (the request boundaries that delimit one assistant
// message's tool cards), and the cards.
type uiData struct {
	statuses []*uiStatus
	starts   []int64 // every api_status start, ascending
	cards    []*uiCard
}

func (l *uiLog) data() *uiData {
	d := &uiData{}
	for _, id := range l.order {
		st := l.byID[id]
		if st == nil {
			continue
		}
		if st.startMs > 0 {
			d.starts = append(d.starts, st.startMs)
		}
		if st.usable() {
			d.statuses = append(d.statuses, st)
		}
	}
	sort.Slice(d.starts, func(i, j int) bool { return d.starts[i] < d.starts[j] })
	for _, id := range l.corder {
		if c := l.cards[id]; c != nil {
			d.cards = append(d.cards, c)
		}
	}
	return d
}

// loadUI replays the task's presentation log — the baseline (the
// materialized state at the last rotation) then the live operation log —
// keeping only api_status and tool-card state. Lines that cannot mention
// either are skipped by a cheap substring test before any JSON decode,
// and a missing file is an empty log, never an error: the token rows then
// fall back to the api-history metrics and no tool carries a duration.
func loadUI(taskDir string) *uiData {
	log := newUILog()
	for _, name := range []string{uiBaselineName, uiOpsName} {
		replayUIFile(filepath.Join(taskDir, name), log)
	}
	return log.data()
}

func replayUIFile(path string, log *uiLog) {
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() {
		return // absent, or a symlink this adapter refuses to follow
	}
	f, err := os.Open(path) //nolint:gosec // regular sibling of a watched task file
	if err != nil {
		return
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 64*1024)
	for {
		line, err := r.ReadString('\n')
		if strings.HasSuffix(line, "\n") && uiLineRelevant(line) {
			var op uiOp
			if json.Unmarshal([]byte(strings.TrimRight(line, "\r\n")), &op) == nil {
				log.apply(&op)
			}
		}
		if err != nil {
			return
		}
	}
}

// uiLineRelevant is the cheap pre-filter: only api_status records and
// card creates/patches (or a reset that re-lists them) are decoded.
func uiLineRelevant(line string) bool {
	return strings.Contains(line, "api_status") || strings.Contains(line, "patch_card") ||
		strings.Contains(line, `"type":"card"`) || strings.Contains(line, `"type":"reset"`)
}

// requestSpan returns the half-open window [from, to) in which the tool
// cards of the assistant message answering status st were created: from
// the request's start to the NEXT request's start (a tool runs between
// the response and the following request).
func (d *uiData) requestSpan(st *uiStatus) (from, to int64) {
	from, to = st.startMs, math.MaxInt64
	i := sort.Search(len(d.starts), func(i int) bool { return d.starts[i] > from })
	if i < len(d.starts) {
		to = d.starts[i]
	}
	return from, to
}

// toolDuration is the summed execution time of the non-approval cards of
// `tool` inside the request span of st: one card per call, or one per
// command of a multi-command execute_command. A write's execution card
// stays "running" while its approval card waits for the human, so the
// overlap with the same tool's approval cards is subtracted (the human's
// wait is not execution). ok is false when there is no finished card
// (never invented).
func (d *uiData) toolDuration(st *uiStatus, tool string) (int64, bool) {
	if st == nil || st.startMs <= 0 {
		return 0, false
	}
	from, to := d.requestSpan(st)
	var exec, approvals []*uiCard
	for _, c := range d.cards {
		if c.toolName != tool || c.start < from || c.start >= to {
			continue
		}
		if !c.done() {
			return 0, false // a half-finished call has no duration yet
		}
		if c.approval {
			approvals = append(approvals, c)
		} else {
			exec = append(exec, c)
		}
	}
	var sum int64
	for _, c := range exec {
		dur := c.end - c.start
		for _, a := range approvals {
			dur -= overlapMs(c.start, c.end, a.start, a.end)
		}
		if dur < 0 {
			dur = 0
		}
		sum += dur
	}
	return sum, len(exec) > 0
}

// overlapMs is the length of the intersection of [s1,e1] and [s2,e2].
func overlapMs(s1, e1, s2, e2 int64) int64 {
	lo, hi := s1, e1
	if s2 > lo {
		lo = s2
	}
	if e2 < hi {
		hi = e2
	}
	if hi <= lo {
		return 0
	}
	return hi - lo
}

// pick returns the status that is the usage record of an assistant
// message (counts equal, see matches) at or after position `from`, plus
// its index. Among equal-count candidates the one started LAST at or
// before the message's own persist time wins: the true request is the
// latest one begun before its response was written, so two requests with
// identical counts in one task cannot be swapped. Without start times it
// is the first match.
func (d *uiData) pick(m rawMetricTokens, ts int64, from int) (*uiStatus, int) {
	first, firstIdx := (*uiStatus)(nil), -1
	best, bestIdx := (*uiStatus)(nil), -1
	for k := from; k < len(d.statuses); k++ {
		s := d.statuses[k]
		if !matches(m, s) {
			continue
		}
		if first == nil {
			first, firstIdx = s, k
		}
		if ts > 0 && s.startMs > 0 && s.startMs <= ts && (best == nil || s.startMs > best.startMs) {
			best, bestIdx = s, k
		}
	}
	if best != nil {
		return best, bestIdx
	}
	return first, firstIdx
}

// tokenSplit is the resolved per-request token bundle.
type tokenSplit struct {
	input, output, cacheRead, cacheWrite, reasoning int64
	// split is true when an api_status supplied the read/write/reasoning
	// split; false = the metrics-only fallback.
	split bool
}

// reasoningShape says how a provider's reported output relates to its
// reported reasoning count.
type reasoningShape int

const (
	// reasoningUnknown: no grounded relation — reasoning is NOT stamped
	// and output is kept exactly as reported.
	reasoningUnknown reasoningShape = iota
	// reasoningSubset: output INCLUDES reasoning (OpenAI usage
	// output_tokens ⊇ output_tokens_details.reasoning_tokens) — net it.
	reasoningSubset
	// reasoningDisjoint: output EXCLUDES reasoning (Gemini
	// candidatesTokenCount vs thoughtsTokenCount) — stamp both as-is.
	reasoningDisjoint
)

// reasoningShapes is the provider-id → reasoning relation table, each
// row grounded in the dirac-cli 0.5.22 bundle's own usage normalizers:
// the Responses handler (openai-codex / openai-native) yields
// `outputTokens:output_tokens, reasoningTokens:output_tokens_details.
// reasoning_tokens`; the chat-completions handler (openai) yields
// `outputTokens:completion_tokens, reasoningTokens:completion_tokens_
// details.reasoning_tokens`; the Gemini handler yields `outputTokens:
// candidatesTokenCount, reasoningTokens:thoughtsTokenCount`. Anthropic
// reports no reasoning count (thinking is inside output_tokens), so it
// needs no row. Unlisted providers keep reasoningUnknown.
var reasoningShapes = map[string]reasoningShape{
	"openai-codex":  reasoningSubset,
	"openai-native": reasoningSubset,
	"openai":        reasoningSubset,
	"gemini":        reasoningDisjoint,
}

// resolveSplit turns an assistant message's metrics and its matched
// api_status (nil = no match) into the emitted bundle. Input is NET on
// both sources (Dirac's own normalizers subtract cached reads/writes
// from the provider prompt count; verified on the operator's
// openai-codex sessions: per-request prompt + cached == the next
// request's context, and Σprompt == taskHistory tokensIn).
func resolveSplit(m rawMetricTokens, st *uiStatus, provider string) tokenSplit {
	if st == nil {
		// Fallback: `cached` is reads+writes and is booked as reads (the
		// only grounded providers write no cache); no reasoning count.
		return tokenSplit{input: m.Prompt, output: m.Completion, cacheRead: m.Cached}
	}
	ts := tokenSplit{
		input:      val(st.TokensIn),
		output:     val(st.TokensOut),
		cacheRead:  val(st.CacheReads),
		cacheWrite: val(st.CacheWrites),
		split:      true,
	}
	r := val(st.ReasoningTokens)
	switch reasoningShapes[strings.ToLower(provider)] {
	case reasoningUnknown:
		// no grounded relation: reasoning is not stamped
	case reasoningSubset:
		if r > ts.output {
			r = ts.output
		}
		ts.output -= r
		ts.reasoning = r
	case reasoningDisjoint:
		ts.reasoning = r
	}
	return ts
}

// matches reports whether an api_status is the usage record of an
// assistant message: the three counts Dirac copies from one taskMetrics
// snapshot into both files must agree exactly.
func matches(m rawMetricTokens, st *uiStatus) bool {
	return val(st.TokensIn) == m.Prompt &&
		val(st.TokensOut) == m.Completion &&
		val(st.CacheReads)+val(st.CacheWrites) == m.Cached
}

// cacheProviders maps Dirac provider ids onto the cachetrack provider
// vocabulary (internal/cachetrack implicitProviderTable). Dirac's OpenAI
// variants are distinct provider ids for ONE upstream family; an
// unlisted id passes through lower-cased (anthropic, deepseek,
// openrouter, … already match the table spelling).
var cacheProviders = map[string]string{
	"openai-codex":  "openai",
	"openai-native": "openai",
}

func cacheProvider(provider string) string {
	p := strings.ToLower(strings.TrimSpace(provider))
	if mapped, ok := cacheProviders[p]; ok {
		return mapped
	}
	return p
}
