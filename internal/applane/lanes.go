package applane

import (
	"net/url"
	"strconv"
	"strings"
)

// Lane kinds: the client shape an upstream speaks, which decides the client
// base URL a lane is advertised at.
const (
	// KindOpenAI is api.openai.com: an OpenAI client's base URL ends in /v1.
	KindOpenAI = "openai"
	// KindAnthropic is api.anthropic.com: an Anthropic client's base URL is
	// the lane root (the SDK adds /v1/messages).
	KindAnthropic = "anthropic"
	// KindOpenRouter is openrouter.ai (OpenAI-compatible, base URL /v1).
	KindOpenRouter = "openrouter"
	// KindGemini is generativelanguage.googleapis.com.
	KindGemini = "gemini"
	// KindOpenAICompatible is any other host: an OpenAI-compatible server is
	// the common case, so the client base URL ends in /v1.
	KindOpenAICompatible = "openai_compatible"
)

// hostKind is the lane-kind table, matched on the upstream host exactly.
var hostKind = map[string]string{
	"api.openai.com":                    KindOpenAI,
	"api.anthropic.com":                 KindAnthropic,
	"openrouter.ai":                     KindOpenRouter,
	"generativelanguage.googleapis.com": KindGemini,
}

// includeUsageHosts are the upstream hosts known to accept
// stream_options.include_usage on a chat-completions stream (APPLANE-2). A
// third-party OpenAI-compatible server may reject the field, so it is
// injected nowhere else.
var includeUsageHosts = map[string]bool{
	"api.openai.com": true,
	"openrouter.ai":  true,
}

// IncludeUsageHost reports whether an upstream host takes the injection.
func IncludeUsageHost(host string) bool {
	return includeUsageHosts[strings.ToLower(strings.TrimSpace(host))]
}

// KindOf returns the lane kind of an upstream base URL (KindOpenAICompatible
// for any host the table does not name, or an unparseable URL).
func KindOf(upstream string) string {
	u, err := url.Parse(strings.TrimSpace(upstream))
	if err != nil {
		return KindOpenAICompatible
	}
	if k, ok := hostKind[strings.ToLower(u.Hostname())]; ok {
		return k
	}
	return KindOpenAICompatible
}

// LaneRoot is the lane's root on the proxy: http://127.0.0.1:<port>/up/<id>.
// The lane is loopback-only (decision 8), so the advertised host is always
// the loopback address.
func LaneRoot(port int, id string) string {
	return "http://127.0.0.1:" + strconv.Itoa(port) + "/up/" + id
}

// ClientBaseURL is the base URL a model client of the lane's kind is given:
// the lane root plus /v1 for an OpenAI-shaped client, the lane root for an
// Anthropic client, /v1beta for a Gemini client.
func ClientBaseURL(port int, id, kind string) string {
	root := LaneRoot(port, id)
	switch kind {
	case KindAnthropic:
		return root
	case KindGemini:
		return root + "/v1beta"
	default:
		return root + "/v1"
	}
}

// ValidLaneID reports whether id can name an app lane: 1 to 64 characters
// of [a-z0-9_-], not the reserved virtual lane "auto". The id is a path
// segment of the lane's base URL, so it must never need escaping.
func ValidLaneID(id string) bool {
	if id == "" || len(id) > 64 || id == "auto" {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

// ValidUpstream reports whether raw is an upstream a lane may forward to:
// an absolute https URL, or http to a loopback host (a local model server).
// The value is the host root without the version suffix, like the fixed
// upstreams; a query or fragment is refused.
func ValidUpstream(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		h := strings.ToLower(u.Hostname())
		return h == "localhost" || h == "127.0.0.1" || h == "::1"
	}
	return false
}

// defaultUpstreams are the upstreams a well-known lane id gets when the user
// adds it without naming one (`observer apps lane add openai`).
var defaultUpstreams = map[string]string{
	"openai":     "https://api.openai.com",
	"anthropic":  "https://api.anthropic.com",
	"openrouter": "https://openrouter.ai/api",
	"gemini":     "https://generativelanguage.googleapis.com",
}

// DefaultUpstream returns the upstream a well-known lane id defaults to.
func DefaultUpstream(id string) (string, bool) {
	u, ok := defaultUpstreams[id]
	return u, ok
}

// Lane is one app lane as the CLI and the dashboard list it (S5).
type Lane struct {
	// ID is the lane id: the /up/<id> path segment.
	ID string `json:"id"`
	// Upstream is the host root the lane forwards to.
	Upstream string `json:"upstream"`
	// Kind is the client shape (KindOpenAI, KindAnthropic, ...).
	Kind string `json:"kind"`
	// BaseURL is the lane root on the proxy.
	BaseURL string `json:"base_url"`
	// ClientBaseURL is the base URL a model client of the lane's kind is
	// given (an OpenAI client's ends in /v1).
	ClientBaseURL string `json:"client_base_url"`
	// Models is the lane's model allow-list; empty means every model.
	Models []string `json:"models"`
	// ModelsFrom says where the list came from: "lane", "*" (the list for
	// every lane) or "" (no list).
	ModelsFrom string `json:"models_from"`
}

// List returns the app lanes of an upstreams table, sorted by id.
func List(upstreams map[string]string, models map[string][]string, port int) []Lane {
	ids := make([]string, 0, len(upstreams))
	for id := range upstreams {
		ids = append(ids, id)
	}
	sortStrings(ids)
	out := make([]Lane, 0, len(ids))
	for _, id := range ids {
		kind := KindOf(upstreams[id])
		l := Lane{
			ID:            id,
			Upstream:      upstreams[id],
			Kind:          kind,
			BaseURL:       LaneRoot(port, id),
			ClientBaseURL: ClientBaseURL(port, id, kind),
			Models:        []string{},
		}
		if pats, ok := models[id]; ok {
			l.Models, l.ModelsFrom = append([]string{}, pats...), "lane"
		} else if pats, ok := models[AllLanesKey]; ok {
			l.Models, l.ModelsFrom = append([]string{}, pats...), AllLanesKey
		}
		out = append(out, l)
	}
	return out
}

// sortStrings sorts in place (insertion sort: a lane table is small).
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// Where a lane's app caps count spend from (the S5 body's cap_spend, and
// `observer apps lane list`).
const (
	// CapSpendRecorded: the recorded app spend ([observability] on), plus
	// the lane's own calls the store has not caught up with yet.
	CapSpendRecorded = "recorded"
	// CapSpendProcess: [observability] is off, so there is no recorded app
	// spend to read; a cap counts only the calls this daemon made since it
	// started.
	CapSpendProcess = "process"
)

// CapSpendProcessNote says what CapSpendProcess means for the user.
const CapSpendProcessNote = "observability is off, so the app caps count only the calls this daemon made since it started; a daemon restart starts every cap window again (turn on [observability] to count the recorded spend)"

// CapSpendSource is where the lanes' app caps count spend from under a
// config's [observability] enabled.
func CapSpendSource(observabilityEnabled bool) string {
	if observabilityEnabled {
		return CapSpendRecorded
	}
	return CapSpendProcess
}
