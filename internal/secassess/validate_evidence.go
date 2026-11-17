package secassess

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// The parts of rows V3, V5 and V6 that read a pen test finding's evidence
// fields (depth plan W5b): the indicator and its condition, and the structured
// reproduction requests. Row V14 (evidence.go) reads what these leave.

// v3Evidence caps the lists an indicator's condition and a reproduction request
// carry. Past a cap the entries are left out and counted.
func v3Evidence(v *validator, f *PTFinding) {
	if f.Indicator != nil && f.Indicator.When != nil {
		w := f.Indicator.When
		w.BodyContains = trimNested(v, "findings.indicator.when.body_contains", w.BodyContains, maxSmallList)
		w.BodyNotContains = trimNested(v, "findings.indicator.when.body_not_contains", w.BodyNotContains, maxSmallList)
		w.HeaderPresent = trimNested(v, "findings.indicator.when.header_present", w.HeaderPresent, maxSmallList)
		w.HeaderAbsent = trimNested(v, "findings.indicator.when.header_absent", w.HeaderAbsent, maxSmallList)
		w.HeaderContains = trimNested(v, "findings.indicator.when.header_contains", w.HeaderContains, maxSmallList)
	}
	for i := range f.Reproduction {
		if r := f.Reproduction[i].Request; r != nil {
			r.Headers = trimNested(v, "findings.reproduction.headers", r.Headers, maxPerItemList)
		}
	}
}

// cleanIndicator checks a finding's indicator: both probe ids must be item ids,
// and the condition's texts are redacted, cleaned and capped. An indicator with
// neither id is dropped; a condition with nothing left is dropped (the finding
// then has no condition and its evidence says so).
func (v *validator) cleanIndicator(path string, f *PTFinding) {
	ind := f.Indicator
	if ind == nil {
		return
	}
	v.unreadable(path+".indicator", "indicator", ind.Unread)
	ind.Unread = ""
	ind.Control = v.probeID(ind.Control)
	ind.Attack = v.probeID(ind.Attack)
	if ind.When != nil {
		ind.When = v.cleanMatch(path+".indicator.when", ind.When)
	}
	if ind.Control == "" && ind.Attack == "" && ind.When == nil {
		f.Indicator = nil
	}
}

// cleanMatch cleans an indicator's condition and returns nil for one that holds
// nothing after cleaning.
func (v *validator) cleanMatch(path string, m *PTMatch) *PTMatch {
	v.unreadable(path, "condition", m.Unread)
	m.Unread = ""
	was := !m.Empty()
	if m.Status != 0 && (m.Status < 100 || m.Status > 599) {
		v.issue("V5", "indicator_status_dropped", SevDropped, path, "The response status of the condition is not a status code from 100 to 599, so it was left out.")
		m.Status = 0
	}
	m.BodyContains = v.matchTexts(path, m.BodyContains)
	m.BodyNotContains = v.matchTexts(path, m.BodyNotContains)
	m.HeaderPresent = v.headerNames(path, m.HeaderPresent)
	m.HeaderAbsent = v.headerNames(path, m.HeaderAbsent)
	var contains []PTHeader
	for _, h := range m.HeaderContains {
		h.Name = strings.TrimSpace(h.Name)
		text, long := v.matchText(path, h.Value)
		if long {
			continue
		}
		h.Value = text
		if !ValidHeaderName(h.Name) || h.Value == "" {
			v.issue("V5", "indicator_header_dropped", SevDropped, path, "A header condition has no valid header name or no text, so it was left out.")
			continue
		}
		// A cookie value in the text is a value the log never holds: the
		// condition is kept in the form the log can hold (headers.go, the H
		// rows) and the reader is told, once per condition.
		if hidden := HiddenConditionText(h.Name, h.Value); hidden != h.Value {
			v.issue("V5", "indicator_value_hidden", SevWarn, path, "A header condition named a cookie's value; the log keeps no such value (it reads [REDACTED]), so the condition was kept as the cookie's name and attributes and the value itself is not checked.")
			h.Value = hidden
		}
		contains = append(contains, h)
	}
	m.HeaderContains = contains
	if m.Empty() {
		if was {
			v.issue("V6", "indicator_condition_empty", SevDropped, path, "Nothing was left of the condition after checking it, so the finding has none.")
		}
		return nil
	}
	return m
}

// unreadable records a part of an evidence field that did not read as the
// documented shape (lenient.go) and was left out: one counted issue, the rest
// of the finding stays and its evidence says what is missing. what is the field
// ("request", "condition", "indicator") and part the unread part, one of the
// fixed words the reader sets (never the agent's text).
func (v *validator) unreadable(path, what, part string) {
	switch {
	case part == "":
	case part == what:
		v.issue("V5", "evidence_shape_dropped", SevDropped, path, "The "+what+" is not in the documented shape (an object, see the result model), so it was left out.")
	default:
		v.issue("V5", "evidence_shape_dropped", SevDropped, path, "The "+part+" of the "+what+" is not in the documented shape, so it was left out.")
	}
}

// matchTexts cleans the texts of a condition and drops the ones that are empty
// or too long (matchText).
func (v *validator) matchTexts(path string, in []string) []string {
	var out []string
	for _, s := range in {
		if t, long := v.matchText(path, s); !long && t != "" {
			out = append(out, t)
		}
	}
	return out
}

// matchText redacts and cleans one text of a condition. A text over
// capMatchText characters is left out, not cut: a shortened "must contain" is a
// weaker condition and a shortened "must not contain" a stricter one, so the
// text the agent wrote is kept whole or not at all. long is true for a text
// that was left out (counted as an issue); an empty text comes back empty.
func (v *validator) matchText(path, s string) (text string, long bool) {
	t := v.redactClean(s, 1<<20)
	if utf8.RuneCountInString(t) > capMatchText {
		v.issue("V5", "indicator_text_dropped", SevDropped, path, fmt.Sprintf("A text of the condition is longer than %d characters, so it was left out (a shortened text would say something else).", capMatchText))
		return "", true
	}
	return t, false
}

// headerNames keeps the header names that are plain names.
func (v *validator) headerNames(path string, in []string) []string {
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if !ValidHeaderName(s) {
			v.issue("V5", "indicator_header_dropped", SevDropped, path, "The header name "+clip(s, 30)+" is not a plain header name, so it was left out.")
			continue
		}
		out = append(out, s)
	}
	return out
}

// cleanRequest checks one reproduction request and returns the form that is
// kept: the method upper-cased and from the closed list, the path and query in
// the restricted character set, the headers from the allow-list with a
// credential's value never kept, a body of at most two kilobytes. A request that
// is not a method and a path is left out (the step stays, with no request).
func (v *validator) cleanRequest(path string, r *PTRequest) *PTRequest {
	if r == nil {
		return nil
	}
	v.unreadable(path, "request", r.Unread)
	method := strings.ToUpper(strings.TrimSpace(r.Method))
	pth := v.cleanText(r.Path, capRequestPath+1, "request")
	switch {
	case method == "" && pth == "" && r.Body == "":
		return nil
	case !EnumRequestMethod.Has(method):
		v.issue("V5", "request_dropped", SevDropped, path, fmt.Sprintf("The request method %q is not one of the accepted methods, so the request was left out.", clip(method, 20)))
		return nil
	case !ValidRequestPath(pth):
		v.issue("V5", "request_dropped", SevDropped, path, "The request path is not a path and query in the accepted characters (percent-encode anything else), so the request was left out.")
		return nil
	}
	out := &PTRequest{Method: method, Path: pth, Body: v.cleanText(r.Body, capRequestBody, "request body")}
	for _, h := range r.Headers {
		name := strings.TrimSpace(h.Name)
		if !ValidHeaderName(name) || !EnumRequestHeader.Has(strings.ToLower(name)) {
			v.issue("V5", "request_header_dropped", SevDropped, path, "The request header "+clip(name, 30)+" is not one the reproduction accepts, so it was left out.")
			continue
		}
		out.Headers = append(out.Headers, PTHeader{Name: name, Value: v.headerValue(name, h.Value)})
	}
	return out
}

// headerValue is the value a reproduction keeps of a header: a credential's
// value is never kept (an Authorization header keeps its scheme word), any
// other is redacted, cleaned and capped.
func (v *validator) headerValue(name, value string) string {
	if !EnumSecretHeader.Has(strings.ToLower(name)) {
		return v.cleanText(value, capHeaderValue, "request header")
	}
	if strings.EqualFold(name, "authorization") {
		if scheme, _, ok := strings.Cut(strings.TrimSpace(value), " "); ok && len(scheme) <= 16 && ValidHeaderName(scheme) {
			return scheme + " [REDACTED]"
		}
	}
	return "[REDACTED]"
}
