package secassess

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// The request helper's log (depth plan W5b). A pen test or red team run is
// handed a small helper script, probe.py, that Observer wrote into the run
// folder; the agent sends its requests through it and the helper appends one
// JSON line per request to probes.jsonl. This file is the pure side of that
// log: the record's shape, the parse that checks the log reads like one the
// helper wrote, and the facts a validation takes from the service.
//
// What the log is, said once: a file in the live, agent-writable project tree.
// The agent runs as the same user, with python and an editor, and no Observer
// process sits between the helper and the target, so the log is a record the
// agent could have written by hand. Observer does not call it authentic. What
// it does is described under row V14 (evidence.go): the helper's bytes are
// compared with the ones Observer wrote, the log must read like one the helper
// wrote, and a finding needs a differential indicator over it.

// The helper's file names inside the run folder.
const (
	FileProbeHelper = "probe.py"
	FileProbeConfig = "probe.json"
	FileProbeLog    = "probes.jsonl"
)

// ProbeConfigSchema is the schema id written in probe.json.
const ProbeConfigSchema = "observer.probe.v1"

// ProbeRecordVersion is the version of a log line.
const ProbeRecordVersion = 1

// MaxProbeLogBytes is the most bytes of probes.jsonl Observer reads. A log over
// it is "too large" and backs nothing: with the budget a pen test is held to
// (at most a few thousand requests of about two kilobytes) the helper does not
// reach it.
const MaxProbeLogBytes = 16 << 20

// maxProbeLines bounds how many log lines are looked at.
const maxProbeLines = 100000

// maxProbeLine bounds one log line.
const maxProbeLine = 64 << 10

// The helper modes a run records at launch (Run.Helper): on (the helper was
// written into the run folder), off (the probe_helper setting was off, nothing
// was written) and withheld (python3 was not seen in the box's standard
// folders, so nothing was written). A run recorded before the helper existed
// has no mode and reads as off.
const (
	HelperOn       = "on"
	HelperOff      = "off"
	HelperWithheld = "withheld"
)

// The refusal codes of the helper, as it writes them into a record.
var probeRefusals = Enum{"off_target", "budget", "bad_path", "bad_header", "bad_method", "body_too_large", "bad_config", "lockout"}

// ProbeRefusals lists the helper's refusal codes.
func ProbeRefusals() []string { return append([]string(nil), probeRefusals...) }

// ProbeHeader is one header of a logged request or response.
type ProbeHeader struct {
	N string `json:"n"`
	V string `json:"v"`
}

// ProbeRecord is one line of probes.jsonl: a request the agent sent through the
// helper (or one the helper refused), with the response the helper saw. Every
// text in it was redacted by the helper when it was written (best effort), and
// again by Observer when the stored copy was made.
type ProbeRecord struct {
	V       int    `json:"v,omitempty"`
	ID      string `json:"id"`
	TS      string `json:"ts"`
	Role    string `json:"role"`
	WSTG    string `json:"wstg"`
	Account string `json:"account"`
	Note    string `json:"note"`

	Method         string        `json:"method"`
	Path           string        `json:"path"`
	ReqHeaders     []ProbeHeader `json:"req_headers"`
	ReqBodyBytes   int           `json:"req_body_bytes"`
	ReqBodyExcerpt string        `json:"req_body_excerpt"`

	// Sent: the helper made the request (a connection that failed is sent with
	// an error); Refused names the rule it refused the request under.
	Sent    bool   `json:"sent"`
	Refused string `json:"refused"`
	Error   string `json:"error"`
	Status  int    `json:"status"`

	RespHeaders []ProbeHeader `json:"resp_headers"`
	// BodyBytes is how much of the body the helper read (at most its cap),
	// BodyTruncated that the body was longer than that, BodyExcerpt the first
	// kilobyte of it, redacted.
	BodyBytes       int    `json:"body_bytes"`
	BodyTruncated   bool   `json:"body_truncated"`
	BodyExcerpt     string `json:"body_excerpt"`
	MS              int    `json:"ms"`
	Hops            int    `json:"hops"`
	RedirectTo      string `json:"redirect_to"`
	RedirectBlocked bool   `json:"redirect_blocked"`
	// Cost is how many HTTP requests the invocation made (one plus the redirects
	// it followed); the budget counts it.
	Cost int `json:"cost"`
	// Replay is the finding id the request replays (probe.py --replay, depth plan
	// W7.2): the helper writes it only for a request it sent from a retest's
	// stored set, and no other record has the key.
	Replay string `json:"replay,omitempty"`
}

// Backs reports whether the record is a request that reached the target and got
// a response: the only kind of record a finding or a coverage row can lean on.
func (r ProbeRecord) Backs() bool { return r.Sent && r.Refused == "" && r.Status > 0 }

// ProbeLog is a parsed probes.jsonl.
type ProbeLog struct {
	Records []ProbeRecord
	// Problem is "" when the log reads like one the helper wrote; else the first
	// thing that does not (one of the Log* words below).
	Problem string
}

// The words ProbeLog.Problem takes.
const (
	// LogBadLine: a line is blank, too long or is not one JSON record of the
	// helper's shape.
	LogBadLine = "bad_line"
	// LogBadVersion: a record names a version other than the helper's.
	LogBadVersion = "bad_version"
	// LogBadID: a record's id is not "p" and its line number, so a line was
	// removed, added or moved.
	LogBadID = "bad_id"
	// LogBadTime: a record's time is not a time, or is before the line above.
	LogBadTime = "bad_time"
	// LogBadField: a record holds a value the helper never writes (a refusal code
	// it does not have, a refused record that was sent, a role it does not take).
	LogBadField = "bad_field"
	// LogTooLong: more lines than Observer looks at.
	LogTooLong = "too_long"
)

// ParseProbeLog reads probes.jsonl. It never fails: a log that does not read
// like the helper's carries a Problem and the records read up to it. The check
// is structural, and a log written by hand with the same structure passes it
// (see the comment at the top of this file).
func ParseProbeLog(data []byte) ProbeLog {
	var log ProbeLog
	var prev time.Time
	rest := data
	for n := 1; len(rest) > 0; n++ {
		line := rest
		if i := bytes.IndexByte(rest, '\n'); i >= 0 {
			line, rest = rest[:i], rest[i+1:]
		} else {
			rest = nil
		}
		if n > maxProbeLines {
			log.Problem = LogTooLong
			return log
		}
		line = bytes.TrimSuffix(line, []byte{'\r'})
		rec, problem := parseProbeLine(line, n, &prev)
		if problem != "" {
			log.Problem = problem
			return log
		}
		log.Records = append(log.Records, rec)
	}
	return log
}

// parseProbeLine reads one line, the nth, against the time of the line before.
func parseProbeLine(line []byte, n int, prev *time.Time) (ProbeRecord, string) {
	var rec ProbeRecord
	if len(line) == 0 || len(line) > maxProbeLine {
		return rec, LogBadLine
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rec); err != nil {
		return rec, LogBadLine
	}
	if _, err := dec.Token(); err == nil {
		return rec, LogBadLine
	}
	switch {
	case rec.V != ProbeRecordVersion:
		return rec, LogBadVersion
	case rec.ID != "p"+strconv.Itoa(n):
		return rec, LogBadID
	}
	ts, err := time.Parse(time.RFC3339Nano, rec.TS)
	if err != nil || ts.Before(*prev) {
		return rec, LogBadTime
	}
	*prev = ts
	if !probeRecordOK(rec) {
		return rec, LogBadField
	}
	return rec, ""
}

// probeLabel is what the helper accepts as a test account label (--account).
var probeLabel = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,40}$`)

// probeRecordOK is the consistency of a record's own fields. A method is one the
// helper sends; any other text is only possible in a record refused as
// bad_method, where it is free text and is redacted like any other.
func probeRecordOK(r ProbeRecord) bool {
	switch {
	case r.Role != "" && r.Role != "control" && r.Role != "attack":
		return false
	case r.WSTG != "" && !isWSTG(r.WSTG):
		return false
	case !EnumRequestMethod.Has(r.Method) && r.Refused != "bad_method":
		return false
	case r.Account != "" && !probeLabel.MatchString(r.Account):
		return false
	case r.Replay != "" && !ValidItemID(r.Replay):
		return false
	case r.Refused != "" && (!probeRefusals.Has(r.Refused) || r.Sent || r.Status != 0 || r.Cost != 0):
		return false
	case r.Refused == "" && !r.Sent:
		return false
	case r.Status < 0 || r.Status > 999 || r.Cost < 0 || r.Hops < 0 || r.BodyBytes < 0 || r.MS < 0:
		return false
	case excerptTooLong(r.BodyExcerpt, r.BodyBytes), excerptTooLong(r.ReqBodyExcerpt, r.ReqBodyBytes):
		return false
	}
	return true
}

// probeExcerptChars is how many characters of a body the helper keeps (EXCERPT in
// probe.py), counted after redaction.
const probeExcerptChars = 1024

// excerptTooLong reports whether an excerpt holds more characters than a body of
// n bytes can have produced. The helper decodes the bytes it read (one
// character per byte at most) and then redacts, which replaces at least one
// character with the ten of a marker, so a whole excerpt has at most n
// characters plus nine for each marker in it. An excerpt that was cut at the
// helper's limit is not looked at: the cut hides how long it was. This is a
// structural check and nothing more: a line edited in place to the same length,
// or to one this bound allows, reads as the helper's (the log is a file the
// agent can write, and the card says so).
func excerptTooLong(excerpt string, n int) bool {
	chars := utf8.RuneCountInString(excerpt)
	if chars >= probeExcerptChars {
		return false
	}
	return chars > n+9*strings.Count(excerpt, hiddenMarker)
}

// ProbeLogSummary counts what a log holds.
type ProbeLogSummary struct {
	Records int `json:"records"`
	Sent    int `json:"sent"`
	Refused int `json:"refused"`
	// Requests is the sum of the records' cost: the requests the target saw.
	Requests int `json:"requests"`
}

// Summary counts the log's records.
func (l ProbeLog) Summary() ProbeLogSummary {
	s := ProbeLogSummary{Records: len(l.Records)}
	for _, r := range l.Records {
		if r.Sent {
			s.Sent++
			s.Requests += r.Cost
		}
		if r.Refused != "" {
			s.Refused++
		}
	}
	return s
}

// byID indexes the records by id.
func (l ProbeLog) byID() map[string]*ProbeRecord {
	m := make(map[string]*ProbeRecord, len(l.Records))
	for i := range l.Records {
		m[l.Records[i].ID] = &l.Records[i]
	}
	return m
}

// The states of the log file as the service read it.
const (
	LogFileOK         = "ok"
	LogFileAbsent     = "absent"
	LogFileUnreadable = "unreadable"
	LogFileTooLarge   = "too_large"
	// LogFileNotRead: the run had no helper, so the log was not looked at.
	LogFileNotRead = "not_read"
	// LogFileInconsistent is the state of a log that was read and does not read
	// like one the helper wrote (ProbeLog.Problem is set).
	LogFileInconsistent = "inconsistent"
)

// ProbeFacts is what a validation takes from the run folder about the helper:
// the plain values the service read, since this package opens nothing. The zero
// value is a run with no helper.
type ProbeFacts struct {
	// Mode is the mode the run recorded at launch (HelperOn, HelperOff,
	// HelperWithheld); "" is a run recorded before the helper existed.
	Mode string
	// HelperWant and HelperHave are the SHA-256 (hex) of probe.py as Observer
	// wrote it and as it is now; ConfigWant and ConfigHave the same for
	// probe.json. A Have of "" means the file could not be read.
	HelperWant, HelperHave string
	ConfigWant, ConfigHave string
	// LogState is how the read of probes.jsonl went (the LogFile words), Log the
	// parsed lines.
	LogState string
	Log      ProbeLog
}

// The states of the helper's files.
const (
	HelperIntact     = "intact"
	HelperChanged    = "changed"
	HelperMissing    = "missing"
	HelperNotChecked = "not_checked"
)

// HelperState compares the helper's files with what Observer wrote. Only a run
// that has a helper is checked; one whose "want" hashes are unknown cannot be
// compared and reads as missing.
func (f ProbeFacts) HelperState() string {
	if f.Mode != HelperOn {
		return HelperNotChecked
	}
	switch {
	case f.HelperWant == "" || f.ConfigWant == "" || f.HelperHave == "" || f.ConfigHave == "":
		return HelperMissing
	case !strings.EqualFold(f.HelperWant, f.HelperHave) || !strings.EqualFold(f.ConfigWant, f.ConfigHave):
		return HelperChanged
	}
	return HelperIntact
}

// logState is the log's state as V14 reads it: the service's reading, except
// that a log that was read and is inconsistent says so.
func (f ProbeFacts) logState() string {
	if f.Mode != HelperOn {
		return LogFileNotRead
	}
	switch s := f.LogState; {
	case s == LogFileOK && f.Log.Problem != "":
		return LogFileInconsistent
	case s == "":
		return LogFileNotRead
	default:
		return s
	}
}
