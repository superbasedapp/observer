package superbased

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// Prompt labels (contract prompts.md).
const (
	LabelProduction = "production"
	LabelStaging    = "staging"
)

var (
	promptNameRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	placeholderRe  = regexp.MustCompile(`\{\{[ \t]*([A-Za-z_][A-Za-z0-9_]*)[ \t]*\}\}`)
	notFoundCodes  = map[string]bool{"prompt_not_found": true, "version_not_found": true, "label_not_set": true, "not_implemented": true}
	sidesWithRoute = map[string]bool{"candidate": true, "base": true, "unkeyed": true}
)

// Prompt errors. Use errors.Is: GetPrompt's errors wrap ErrPromptNotFound or
// ErrPromptFetch; a bad argument wraps ErrInvalidArgument.
var (
	ErrPromptNotFound  = errors.New("superbased: prompt not found")
	ErrPromptFetch     = errors.New("superbased: prompt fetch failed")
	ErrInvalidArgument = errors.New("superbased: invalid argument")
)

// PromptCompileError is a Compile call missing values; Missing is sorted.
type PromptCompileError struct{ Missing []string }

func (e *PromptCompileError) Error() string {
	return "missing prompt variables: " + strings.Join(e.Missing, ", ")
}

// Message is one chat message (role, content and any other fields as served).
type Message = map[string]any

// PromptRollout is a label's staged rollout as the server reported it
// (prompts.md v2 section 9.3).
type PromptRollout struct {
	BaseVersion      int    `json:"base_version"`
	CandidateVersion int    `json:"candidate_version"`
	Percent          int    `json:"percent"`
	Cohort           string `json:"cohort"` // candidate, base or unkeyed
	Key              string `json:"key"`    // user, session or ""
	Salt             string `json:"salt"`
}

func (r *PromptRollout) signature() string {
	if r == nil {
		return ""
	}
	return fmt.Sprintf("%d|%d|%s", r.CandidateVersion, r.Percent, r.Salt)
}

// Prompt is one prompt version as the registry served it.
type Prompt struct {
	Name          string
	Version       int
	Type          string    // text or chat
	Text          string    // the body of a text prompt
	Messages      []Message // the messages of a chat prompt
	Config        map[string]any
	Labels        []string
	Label         string // the label it was resolved by; "" for a version fetch
	ResolvedBy    string
	Variables     []string
	Digest        string
	CommitMessage string
	CreatedAt     string
	IsFallback    bool
	Source        string // online, local or fallback
	Rollout       *PromptRollout
}

// Cohort is the rollout side that served this copy (candidate, base or
// unkeyed); "" when the label has no rollout.
func (p *Prompt) Cohort() string {
	if p.Rollout == nil {
		return ""
	}
	return p.Rollout.Cohort
}

// placeholders are the distinct placeholder names in text, sorted.
func placeholders(text string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, m := range placeholderRe.FindAllStringSubmatch(text, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	sort.Strings(out)
	return out
}

// asText is a placeholder value as text: a string as is, anything else as
// JSON.stringify writes it.
func asText(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if raw, ok := v.(json.RawMessage); ok {
		// A JSON value whose JavaScript value is a string is inserted as is.
		if dv, err := decodeOrdered(raw); err == nil {
			if s, ok := dv.(string); ok {
				return s
			}
		}
	}
	return jsJSON(v, false)
}

func missingNames(text string, values map[string]any, into map[string]bool) {
	for _, m := range placeholderRe.FindAllStringSubmatch(text, -1) {
		if _, ok := values[m[1]]; !ok {
			into[m[1]] = true
		}
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// compileText fills text's placeholders in one left-to-right pass (a
// substituted value is never re-scanned).
func compileText(text string, values map[string]any) (string, error) {
	missing := map[string]bool{}
	missingNames(text, values, missing)
	if len(missing) > 0 {
		return "", &PromptCompileError{Missing: sortedKeys(missing)}
	}
	return placeholderRe.ReplaceAllStringFunc(text, func(m string) string {
		name := placeholderRe.FindStringSubmatch(m)[1]
		return asText(values[name])
	}), nil
}

func messageContent(m Message) string {
	s, _ := m["content"].(string)
	return s
}

// Compile fills every {{name}} placeholder and returns the text (a text
// prompt) or a new message list (a chat prompt; each content compiled, other
// fields untouched). Every missing name is in one *PromptCompileError; extra
// values are ignored. A value that is not a string renders as JSON.stringify
// renders it. The span in ctx is stamped with this prompt.
func (p *Prompt) Compile(ctx context.Context, values map[string]any) (any, error) {
	if p.Type == "chat" {
		return p.CompileMessages(ctx, values)
	}
	return p.CompileText(ctx, values)
}

// CompileText is Compile for a text prompt.
func (p *Prompt) CompileText(ctx context.Context, values map[string]any) (string, error) {
	out, err := compileText(p.Text, values)
	if err != nil {
		return "", err
	}
	p.Stamp(trace.SpanFromContext(ctx))
	return out, nil
}

// CompileMessages is Compile for a chat prompt.
func (p *Prompt) CompileMessages(ctx context.Context, values map[string]any) ([]Message, error) {
	missing := map[string]bool{}
	for _, m := range p.Messages {
		missingNames(messageContent(m), values, missing)
	}
	if len(missing) > 0 {
		return nil, &PromptCompileError{Missing: sortedKeys(missing)}
	}
	out := make([]Message, 0, len(p.Messages))
	for _, m := range p.Messages {
		nm := Message{}
		for k, v := range m {
			nm[k] = v
		}
		if c, ok := m["content"].(string); ok {
			nm["content"], _ = compileText(c, values)
		}
		out = append(out, nm)
	}
	p.Stamp(trace.SpanFromContext(ctx))
	return out, nil
}

// Attributes are the span attributes this prompt stamps (none for a fallback).
func (p *Prompt) Attributes() []attribute.KeyValue {
	if p == nil || p.IsFallback {
		return nil
	}
	out := []attribute.KeyValue{attribute.String(keyPromptName, p.Name), attribute.Int(keyPromptVersion, p.Version)}
	if p.Label != "" {
		out = append(out, attribute.String(keyPromptLabel, p.Label))
	}
	if p.Rollout != nil {
		out = append(out, attribute.String(keyPromptCohort, p.Rollout.Cohort))
	}
	return out
}

// Stamp stamps sp with this prompt (sbo.prompt.*).
func (p *Prompt) Stamp(sp trace.Span) {
	if sp == nil || !sp.IsRecording() {
		return
	}
	if a := p.Attributes(); len(a) > 0 {
		sp.SetAttributes(a...)
	}
}

func copyMessages(in []Message) []Message {
	out := make([]Message, 0, len(in))
	for _, m := range in {
		nm := Message{}
		for k, v := range m {
			nm[k] = v
		}
		out = append(out, nm)
	}
	return out
}

// Fallback is the prompt GetPrompt returns from PromptOptions.Fallback.
func fallbackPrompt(name string, body any) *Prompt {
	switch b := body.(type) {
	case []Message:
		return &Prompt{Name: name, Type: "chat", Messages: copyMessages(b), Variables: placeholders(jsJSON(b, false)), IsFallback: true, Source: "fallback"}
	case string:
		return &Prompt{Name: name, Type: "text", Text: b, Variables: placeholders(b), IsFallback: true, Source: "fallback"}
	}
	s := fmt.Sprint(body)
	return &Prompt{Name: name, Type: "text", Text: s, Variables: placeholders(s), IsFallback: true, Source: "fallback"}
}

// parsePrompt reads a registry answer.
func parsePrompt(body any, sideName, label string) (*Prompt, error) {
	m, ok := body.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: the registry answered without a JSON object", ErrPromptFetch)
	}
	name, nameOK := m["name"].(string)
	version, verOK := jsonInt(m["version"])
	typ, _ := m["type"].(string)
	p := &Prompt{Name: name, Version: int(version), Type: typ, Label: label, Source: sideName}
	ok = nameOK && verOK
	text := ""
	switch {
	case ok && typ == "text":
		s, isStr := m["prompt"].(string)
		ok = isStr
		p.Text, text = s, s
	case ok && typ == "chat":
		arr, isArr := m["prompt"].([]any)
		ok = isArr
		for _, e := range arr {
			mm, isObj := e.(map[string]any)
			if !isObj {
				ok = false
				break
			}
			p.Messages = append(p.Messages, mm)
		}
		text = jsJSON(arr, false)
	default:
		ok = false
	}
	if !ok {
		return nil, fmt.Errorf("%w: the registry answered with a malformed prompt", ErrPromptFetch)
	}
	if cfg, isObj := m["config"].(map[string]any); isObj {
		p.Config = cfg
	} else {
		p.Config = map[string]any{}
	}
	p.Labels = []string{}
	if ls, isArr := m["labels"].([]any); isArr {
		for _, l := range ls {
			if s, isStr := l.(string); isStr {
				p.Labels = append(p.Labels, s)
			}
		}
	}
	if vs, isArr := m["variables"].([]any); isArr {
		p.Variables = []string{}
		for _, v := range vs {
			p.Variables = append(p.Variables, jsonText(v))
		}
	} else {
		p.Variables = placeholders(text)
	}
	p.ResolvedBy, p.Digest = jsonText(m["resolved_by"]), jsonText(m["digest"])
	p.CommitMessage, p.CreatedAt = jsonText(m["commit_message"]), jsonText(m["created_at"])
	p.Rollout = parseRollout(m["rollout"])
	return p, nil
}

func parseRollout(v any) *PromptRollout {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	salt, saltOK := m["salt"].(string)
	cohort, _ := m["cohort"].(string)
	if !saltOK || !sidesWithRoute[cohort] {
		return nil
	}
	num := func(k string) int {
		n, _ := jsonInt(m[k])
		return int(n)
	}
	return &PromptRollout{BaseVersion: num("base_version"), CandidateVersion: num("candidate_version"), Percent: num("percent"), Cohort: cohort, Key: jsonText(m["key"]), Salt: salt}
}

// --- prompts.md v2: the cohort key and the rollout bucket ------------------------

const sideAll = "all"

// cohortHash is the lowercase hex SHA-256 of v: what the SDK sends as
// user_hash / session_hash (the raw id never leaves the SDK).
func cohortHash(v string) string {
	h := sha256.Sum256([]byte(v))
	return hex.EncodeToString(h[:])
}

// rolloutBucket is uint32_be(sha256(salt + "|" + subject)[0:4]) % 100.
func rolloutBucket(salt, subject string) int {
	h := sha256.Sum256([]byte(salt + "|" + subject))
	return int(binary.BigEndian.Uint32(h[:4]) % 100)
}

type cohort struct {
	subject string
	query   []queryParam
}

func cohortOf(ctx context.Context, selector, user, sessionID string) cohort {
	if strings.HasPrefix(selector, "version:") {
		return cohort{}
	}
	cur := CurrentAttributes(ctx)
	u := user
	if u == "" {
		u, _ = cur["user"].(string)
	}
	if u != "" {
		h := cohortHash(u)
		return cohort{"user:" + h, []queryParam{{"user_hash", h}}}
	}
	s := sessionID
	if s == "" {
		s, _ = cur["session_id"].(string)
	}
	if s != "" {
		h := cohortHash(s)
		return cohort{"session:" + h, []queryParam{{"session_hash", h}}}
	}
	return cohort{}
}

func sideOf(p *Prompt) string {
	if p.Rollout != nil {
		return p.Rollout.Cohort
	}
	return sideAll
}

type promptGroup struct{ endpoint, name, selector string }

type promptKey struct {
	promptGroup
	side string
}

type promptEntry struct {
	prompt     *Prompt
	etag       string
	fetched    time.Time
	refreshing bool
	query      []queryParam // the cohort key that filled it
}

type promptCacheT struct {
	mu      sync.Mutex
	entries map[promptKey]*promptEntry
	logAt   time.Time
}

var promptCache = &promptCacheT{entries: map[promptKey]*promptEntry{}}

func (c *promptCacheT) clear() {
	c.mu.Lock()
	c.entries = map[promptKey]*promptEntry{}
	c.mu.Unlock()
}

func (c *promptCacheT) get(k promptKey) (*promptEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[k]
	if !ok {
		return nil, false
	}
	cp := *e
	return &cp, true
}

func (c *promptCacheT) drop(k promptKey) {
	c.mu.Lock()
	delete(c.entries, k)
	c.mu.Unlock()
}

// sideFor: bucket with a cached rollout's salt and percent, else "all".
func (c *promptCacheT) sideFor(g promptGroup, co cohort) string {
	c.mu.Lock()
	var ro *PromptRollout
	for k, e := range c.entries {
		if k.promptGroup == g && e.prompt.Rollout != nil {
			ro = e.prompt.Rollout
			break
		}
	}
	c.mu.Unlock()
	switch {
	case ro == nil:
		return sideAll
	case co.subject == "":
		return "unkeyed"
	case rolloutBucket(ro.Salt, co.subject) < ro.Percent:
		return "candidate"
	default:
		return "base"
	}
}

// store keeps an answer under the side it names; a changed rollout drops the
// other sides.
func (c *promptCacheT) store(g promptGroup, p *Prompt, etag string, q []queryParam) {
	sig := p.Rollout.signature()
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, e := range c.entries {
		if k.promptGroup == g && e.prompt.Rollout.signature() != sig {
			delete(c.entries, k)
		}
	}
	c.entries[promptKey{g, sideOf(p)}] = &promptEntry{prompt: p, etag: etag, fetched: time.Now(), query: q}
}

func (c *promptCacheT) claimRefresh(k promptKey) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[k]
	if !ok || e.refreshing {
		return false
	}
	e.refreshing = true
	return true
}

func (c *promptCacheT) touch(k promptKey) {
	c.mu.Lock()
	if e, ok := c.entries[k]; ok {
		e.fetched = time.Now()
	}
	c.mu.Unlock()
}

func (c *promptCacheT) endRefresh(k promptKey) {
	c.mu.Lock()
	if e, ok := c.entries[k]; ok {
		e.refreshing = false
	}
	c.mu.Unlock()
}

func (c *promptCacheT) logFailure(msg string) {
	c.mu.Lock()
	now := time.Now()
	due := now.Sub(c.logAt) >= time.Minute
	if due {
		c.logAt = now
	}
	c.mu.Unlock()
	if due {
		logf(slog.LevelWarn, "prompt revalidation failed, serving the cached copy: %s", msg)
	}
}

// PromptOptions are GetPrompt's options.
type PromptOptions struct {
	// Label (production, the default, or staging) or Version (a positive
	// integer); not both.
	Label   string
	Version int
	// CacheTTL is how long a fetched prompt is fresh (default Init's
	// PromptCacheTTL; negative means 0).
	CacheTTL time.Duration
	// Fallback (a string or []Message) is returned, unversioned and stamping
	// nothing, when nothing is cached and the fetch fails.
	Fallback any
	// User and SessionID key a staged rollout (default: the trace's end user,
	// else its session). Only their SHA-256 is sent.
	User, SessionID string
}

func promptSelector(label string, version int) (string, []queryParam, string, error) {
	if label != "" && version != 0 {
		return "", nil, "", fmt.Errorf("%w: GetPrompt takes Label or Version, not both", ErrInvalidArgument)
	}
	if version != 0 {
		if version < 1 {
			return "", nil, "", fmt.Errorf("%w: version must be a positive integer, got %d", ErrInvalidArgument, version)
		}
		v := strconv.Itoa(version)
		return "version:" + v, []queryParam{{"version", v}}, "", nil
	}
	if label == "" {
		label = LabelProduction
	}
	if label != LabelProduction && label != LabelStaging {
		return "", nil, "", fmt.Errorf("%w: label must be one of production, staging, got %q", ErrInvalidArgument, label)
	}
	return "label:" + label, []queryParam{{"label", label}}, label, nil
}

func fetchPrompt(ctx context.Context, sd side, name string, query []queryParam, etag string) *response {
	var h map[string]string
	if etag != "" {
		h = map[string]string{"If-None-Match": etag}
	}
	return sd.call(ctx, "GET", "prompt", nil, query, h, map[string]string{"name": name})
}

func promptNotFound(r *response) bool {
	return (r.status == 404 || r.status == 501) && (notFoundCodes[r.errorCode()] || r.errorCode() == "")
}

func revalidatePrompt(k promptKey, sd side, name string, query []queryParam, label string) {
	defer promptCache.endRefresh(k)
	e, ok := promptCache.get(k)
	if !ok {
		return
	}
	q := append(append([]queryParam(nil), query...), e.query...)
	resp := fetchPrompt(context.Background(), sd, name, q, e.etag)
	switch {
	case resp.status == 304:
		promptCache.touch(k)
	case resp.status == 200:
		p, err := parsePrompt(resp.body, sd.name, label)
		if err != nil {
			promptCache.logFailure(err.Error())
			return
		}
		if sideOf(p) != k.side {
			promptCache.drop(k) // this key's side changed
		}
		promptCache.store(k.promptGroup, p, resp.header("Etag"), e.query)
	case promptNotFound(resp):
		promptCache.drop(k)
	default:
		promptCache.logFailure(resp.describe())
	}
}

// GetPrompt fetches prompt name by label (production by default) or version
// from the registry of the destination chosen at Init (the gateway for online,
// the machine for local; both tries the gateway, then the machine). It is
// cached for CacheTTL; after that the cached copy is returned at once and
// revalidated in the background with If-None-Match. With nothing cached and a
// failed fetch, Fallback is returned; without one the error wraps
// ErrPromptNotFound or ErrPromptFetch (and, when the org's plan refused the
// fetch, the *PlanRefusalError: errors.Is(err, ErrPlanRequired)). The span
// in ctx is stamped with the prompt's name and version.
func GetPrompt(ctx context.Context, name string, o PromptOptions) (*Prompt, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !promptNameRe.MatchString(name) {
		return nil, fmt.Errorf("%w: prompt name %q must match %s", ErrInvalidArgument, name, promptNameRe)
	}
	selector, query, label, err := promptSelector(o.Label, o.Version)
	if err != nil {
		return nil, err
	}
	co := cohortOf(ctx, selector, o.User, o.SessionID)
	ttl := o.CacheTTL
	if ttl == 0 {
		ttl = DefaultPromptCacheTTL
		if s := CurrentSettings(); s != nil {
			ttl = s.PromptCacheTTL
		}
	}
	if ttl < 0 {
		ttl = 0
	}
	span := trace.SpanFromContext(ctx)
	var errs []string
	var refused *PlanRefusalError
	notFound := true
	targets := sides(nil)
	if len(targets) == 0 {
		errs = append(errs, unavailableReason(nil))
		notFound = false
	}
	for _, sd := range targets {
		g := promptGroup{sd.name + ":" + sd.base, name, selector}
		k := promptKey{g, promptCache.sideFor(g, co)}
		if e, ok := promptCache.get(k); ok {
			if time.Since(e.fetched) >= ttl && promptCache.claimRefresh(k) {
				go revalidatePrompt(k, sd, name, query, label)
			}
			e.prompt.Stamp(span)
			return e.prompt, nil
		}
		resp := fetchPrompt(ctx, sd, name, append(append([]queryParam(nil), query...), co.query...), "")
		if resp.status == 200 {
			p, err := parsePrompt(resp.body, sd.name, label)
			if err != nil {
				errs = append(errs, sd.name+": "+strings.TrimPrefix(err.Error(), ErrPromptFetch.Error()+": "))
				notFound = false
				continue
			}
			promptCache.store(g, p, resp.header("Etag"), co.query)
			p.Stamp(span)
			return p, nil
		}
		if promptNotFound(resp) {
			msg := resp.describe()
			if resp.status == 501 || resp.errorCode() == "" {
				msg = "this server has no prompt registry"
			}
			errs = append(errs, sd.name+": "+msg)
			continue
		}
		notFound = false
		if refused == nil {
			refused = resp.planRefusal()
		}
		errs = append(errs, sd.name+": "+resp.describe())
	}
	if o.Fallback != nil {
		return fallbackPrompt(name, o.Fallback), nil
	}
	detail := strings.Join(errs, "; ")
	if detail == "" {
		detail = "no destination"
	}
	if notFound {
		return nil, fmt.Errorf("%w: prompt %q (%s): %s", ErrPromptNotFound, name, selector, detail)
	}
	err = fmt.Errorf("%w: prompt %q (%s): %s", ErrPromptFetch, name, selector, detail)
	if refused != nil {
		// The org's plan refused it: still ErrPromptFetch, and errors.As
		// finds the *PlanRefusalError.
		return nil, &withPlanRefusal{err: err, refusal: refused}
	}
	return nil, err
}
