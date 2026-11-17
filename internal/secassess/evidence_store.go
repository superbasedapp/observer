package secassess

// The stored form of the request helper's log (depth plan W5b). The helper's
// own log stays in the run folder, a file the agent can write; what the
// dashboard shows is a copy Observer made at validation: the records the model
// cites, passed through Observer's redactor and the fence-safe cleaner again,
// capped field by field. The copy is node-local side data, never in the
// database and never on the organization wire.

// The caps of the texts of a stored record, in characters. The helper keeps a
// kilobyte of a request body or a response body and redacts what it can; these
// bound what a hand-written line could carry.
const (
	capStoredPath        = 2048
	capStoredText        = 1024
	capStoredLabel       = 128
	capStoredHeaderName  = 128
	capStoredHeaderValue = 1024
	capStoredHeaders     = 64
)

// StoredProbe returns a record as it is kept: every text redacted, cleaned and
// capped, the lists never nil. A header whose name says it carries a credential
// keeps no value (CredentialHeaderName), and every other header value is
// redacted as the line "Name: value", so a pattern that needs the name sees
// it. The record's numbers and flags are kept as they are (the parse already
// bounded them).
func StoredProbe(r ProbeRecord, redact func(string) string) ProbeRecord {
	r, _ = RedactValue(r, redact)
	r.V = 0
	r.ID, r.TS, r.Role, r.WSTG = clean(r.ID, 12), clean(r.TS, 40), clean(r.Role, 10), clean(r.WSTG, 8)
	r.Method, r.Refused = clean(r.Method, 16), clean(r.Refused, 20)
	r.Replay = clean(r.Replay, 48)
	r.Account, r.Note = clean(r.Account, capStoredLabel), clean(r.Note, capStoredText)
	r.Path, r.RedirectTo = clean(r.Path, capStoredPath), clean(r.RedirectTo, capStoredPath)
	r.Error = clean(r.Error, capStoredText)
	r.ReqBodyExcerpt, r.BodyExcerpt = clean(r.ReqBodyExcerpt, capStoredText), clean(r.BodyExcerpt, capStoredText)
	r.ReqHeaders, r.RespHeaders = storedHeaders(r.ReqHeaders, redact), storedHeaders(r.RespHeaders, redact)
	return r
}

// ShownProbes is the display pass over stored records: the same header rule
// as StoredProbe, then every string through redact. It returns copies, and how
// many strings the redactor changed. A nil redact (hiding is off) returns the
// records as they are.
func ShownProbes(in []ProbeRecord, redact func(string) string) ([]ProbeRecord, int) {
	if redact == nil || len(in) == 0 {
		return in, 0
	}
	out := make([]ProbeRecord, len(in))
	hidden := 0
	for i, r := range in {
		r.ReqHeaders, r.RespHeaders = hiddenHeaders(r.ReqHeaders, redact), hiddenHeaders(r.RespHeaders, redact)
		var n int
		out[i], n = RedactValue(r, redact)
		hidden += n
	}
	return out, hidden
}

// storedHeaders cleans and caps a header list, hiding what a header's name
// says is a credential; a header with no name is left out.
func storedHeaders(in []ProbeHeader, redact func(string) string) []ProbeHeader {
	out := make([]ProbeHeader, 0, min(len(in), capStoredHeaders))
	for _, h := range in {
		if len(out) == capStoredHeaders {
			break
		}
		if n := clean(h.N, capStoredHeaderName); n != "" {
			out = append(out, ProbeHeader{N: n, V: clean(hiddenHeaderValue(n, h.V, redact), capStoredHeaderValue)})
		}
	}
	return out
}

// StoredProbes returns the log records the model cites (CitedProbes), in the
// log's order, in their stored form. A cited id the log does not hold is left
// out; the model's own words about it stay in the model.
func StoredProbes(doc *PentestDoc, log ProbeLog, redact func(string) string) []ProbeRecord {
	if doc == nil {
		return nil
	}
	byID := log.byID()
	var out []ProbeRecord
	for _, id := range CitedProbes(doc) {
		if r := byID[id]; r != nil {
			out = append(out, StoredProbe(*r, redact))
		}
	}
	return out
}
