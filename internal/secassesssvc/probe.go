package secassesssvc

import (
	"bytes"
	"crypto/sha256"
	_ "embed" // the request helper's source is embedded
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secassess"
)

// The request helper (depth plan W5b): a small Python 3 standard-library script
// Observer writes into the run folder of a penetration test or red team run
// before the agent starts, with a settings file beside it. The agent sends its
// requests to the target through it; it refuses any other address, applies the
// pace and the request budget, and logs one line per request to probes.jsonl.
//
// What the files are, said once: they sit in the live, agent-writable tree. The
// agent runs as the same user with an interpreter and an editor, so the helper
// can be edited and the log can be written by hand. Observer re-hashes both
// files at validation and compares them with the hashes it recorded when it
// wrote them (row V14); it never calls the log authentic.

//go:embed probe/probe.py
var probeSource []byte

// ProbeMaxBytes is the response read cap written to probe.json: the helper
// reads at most this much of a response and keeps a kilobyte of it.
const ProbeMaxBytes = 64 << 10

// maxProbeHelperBytes bounds what is read to hash a helper file in the run
// folder: the embedded helper is about 22 KiB, and a file far beyond that is a
// changed file whatever it holds.
const maxProbeHelperBytes = 256 << 10

// MaxProbeConfigBytes is the most bytes probe.json may hold. Only a retest gets
// near it (its stored requests ride in the file); the helper reads up to 256 KiB
// and the hash read above allows the same, so a file Observer wrote is never
// one the helper or the check cannot read whole.
const MaxProbeConfigBytes = 192 << 10

// probeOversize is the hash word of a helper file over its read cap: it never
// equals a recorded hash, so the file reads as changed.
const probeOversize = "oversize"

// WithheldReason is the sentence the plan shows when the helper is left out
// because python3 was not seen where the daemon looked. The daemon looks at
// its own machine's folders, not inside the sandbox: for a sandbox that runs
// an image of its own (a container) the answer can differ from the box's, and
// the sentence says whose folders it is.
const WithheldReason = "python3 was not found in /usr/bin, /usr/local/bin or /bin on this machine (Observer looks from the daemon, not inside the sandbox), so the request helper is left out and every finding's evidence will read No log. Install python3 on this machine to use it."

// Errors a helper write can return.
var (
	// ErrProbeRun: the run id or the target is not usable for the helper.
	ErrProbeRun = errors.New("secassesssvc: the request helper cannot be written for this run")
	// ErrProbeConfigTooLarge: the settings file, with the stored requests of a
	// retest in it, would be over MaxProbeConfigBytes. The caller refuses the
	// retest and asks for fewer findings.
	ErrProbeConfigTooLarge = errors.New("secassesssvc: the request helper's settings are too large")
	// ErrProbeExists: the run folder already holds a different probe.py or
	// probe.json than the one this launch would write.
	ErrProbeExists = errors.New("secassesssvc: the run folder already holds a different request helper file")
)

// ProbeHelperSHA256 is the SHA-256 (hex) of the embedded probe.py.
func ProbeHelperSHA256() string { return sha256Hex(probeSource) }

// ProbeHelperSize is the size of the embedded probe.py in bytes.
func ProbeHelperSize() int { return len(probeSource) }

// ProbePlan is what a launch decides about the helper.
type ProbePlan struct {
	// Mode is secassess.HelperOn, HelperOff or HelperWithheld.
	Mode string
	// Reason is the sentence for a withheld helper, "" otherwise.
	Reason string
}

// PlanProbe decides the helper for a run of a kind that probes: off when the
// setting is off, withheld when the tool inventory says python3 is absent from
// the box's standard folders, otherwise on. The inventory is the plan's own (the
// daemon looked in those folders; it never runs the tool), and a daemon that
// cannot look (not Linux) leaves python3 unknown, which does not withhold the
// helper: the agent then finds out, and a request it sends another way reads
// No log.
func PlanProbe(setting bool, tools secassess.ToolFacts) ProbePlan {
	if !setting {
		return ProbePlan{Mode: secassess.HelperOff}
	}
	if have, known := tools["python3"]; known && !have {
		return ProbePlan{Mode: secassess.HelperWithheld, Reason: WithheldReason}
	}
	return ProbePlan{Mode: secassess.HelperOn}
}

// ProbeConfig is probe.json: the helper's settings, written by Observer.
type ProbeConfig struct {
	Schema   string `json:"schema"`
	RunID    string `json:"run_id"`
	Origin   string `json:"origin"`
	Budget   int    `json:"budget"`
	PaceRPS  int    `json:"pace_rps"`
	MaxBytes int    `json:"max_bytes"`
	// Replay is a retest's stored requests by finding id (secassess.RetestBasis.ReplaySet);
	// absent for every other run, so a penetration test's file is the same bytes as before.
	Replay map[string]secassess.ReplayEntry `json:"replay,omitempty"`
}

// ProbeInput is what the two files are written from.
type ProbeInput struct {
	RunID string
	// Target is the confirmed loopback target; the helper sends to its origin
	// (scheme, host and port) and nowhere else.
	Target  secassess.Target
	Budget  int
	PaceRPS int
	// Replay is a retest's stored requests by finding id; nil for any other run.
	Replay map[string]secassess.ReplayEntry
}

// ConfigBytes is probe.json for the input: compact JSON and a newline. It is
// deterministic, so the recorded hash can be compared later.
func (in ProbeInput) ConfigBytes() ([]byte, error) {
	if !secassess.ValidRunID(in.RunID) || in.Target.Host == "" || in.Target.Port == "" || in.Budget < 1 || in.PaceRPS < 1 {
		return nil, ErrProbeRun
	}
	b, err := json.Marshal(ProbeConfig{
		Schema: secassess.ProbeConfigSchema, RunID: in.RunID, Origin: in.Target.Origin(),
		Budget: in.Budget, PaceRPS: in.PaceRPS, MaxBytes: ProbeMaxBytes, Replay: in.Replay,
	})
	if err != nil {
		return nil, fmt.Errorf("secassesssvc.ProbeInput.ConfigBytes: %w", err)
	}
	if len(b)+1 > MaxProbeConfigBytes {
		return nil, ErrProbeConfigTooLarge
	}
	return append(b, '\n'), nil
}

// ProbeFiles says what a write put in the run folder.
type ProbeFiles struct {
	// Helper and Config are the SHA-256 (hex) of probe.py and probe.json as
	// Observer wrote them; the run records them.
	Helper, Config string
}

// WriteProbeFiles writes probe.py and probe.json into the run folder under the
// project root, which must exist (PrepareRunDir makes it). Both go through
// os.Root, so a link in the project cannot move the write outside it, with
// O_CREATE|O_EXCL and mode 0600; a file that is already there is left alone
// when it holds exactly what would be written (a second attempt at one launch)
// and refused otherwise. It returns a function that removes what this call
// created (call it when the terminal does not start, before the run folder's
// own cleanup).
func WriteProbeFiles(projectRoot string, in ProbeInput) (ProbeFiles, func(), error) {
	noop := func() {}
	cfg, err := in.ConfigBytes()
	if err != nil {
		return ProbeFiles{}, noop, err
	}
	p := secassess.ResultPaths(in.RunID)
	root, err := os.OpenRoot(projectRoot)
	if err != nil {
		return ProbeFiles{}, noop, fmt.Errorf("secassesssvc.WriteProbeFiles: %w", err)
	}
	defer func() { _ = root.Close() }()
	if fi, err := root.Stat(p.Dir); err != nil || !fi.IsDir() {
		return ProbeFiles{}, noop, fmt.Errorf("secassesssvc.WriteProbeFiles: the run folder is not there: %w", ErrProbeRun)
	}
	var made []string
	remove := func() {
		r, err := os.OpenRoot(projectRoot)
		if err != nil {
			return
		}
		defer func() { _ = r.Close() }()
		for _, rel := range made {
			_ = r.Remove(rel)
		}
	}
	for _, f := range []struct {
		rel  string
		data []byte
	}{{p.ProbeHelper, probeSource}, {p.ProbeConfig, cfg}} {
		created, err := writeExclusive(root, f.rel, f.data)
		if created {
			made = append(made, f.rel)
		}
		if err != nil {
			remove()
			return ProbeFiles{}, noop, err
		}
	}
	return ProbeFiles{Helper: sha256Hex(probeSource), Config: sha256Hex(cfg)}, remove, nil
}

// writeExclusive creates rel with data (O_EXCL, 0600). A file that already
// exists with identical bytes is accepted and not reported as created; any other
// existing file is ErrProbeExists.
func writeExclusive(root *os.Root, rel string, data []byte) (created bool, err error) {
	fh, err := root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	switch {
	case err == nil:
		_, werr := fh.Write(data)
		cerr := fh.Close()
		if werr != nil || cerr != nil {
			return true, fmt.Errorf("secassesssvc.WriteProbeFiles: %w", errors.Join(werr, cerr))
		}
		return true, nil
	case errors.Is(err, fs.ErrExist):
		have, rerr := readRootFile(root, rel, int64(len(data)))
		if rerr != nil || !bytes.Equal(have, data) {
			return false, ErrProbeExists
		}
		return false, nil
	}
	return false, fmt.Errorf("secassesssvc.WriteProbeFiles: %w", err)
}

// readRootFile reads a regular file of at most max bytes under the root, with
// the same confined read the result files get (readFromRoot).
func readRootFile(root *os.Root, rel string, max int64) ([]byte, error) {
	data, _, err := readFromRoot(root, rel, max)
	return data, err
}

// ReplayedFindings lists, sorted, the finding ids a retest's request helper
// settings (probe.json in the run folder) hold stored requests for: the findings
// the retest was asked to replay, as Observer wrote them when it started. It
// is what a check that opens no database (the agent's self-check command) can
// know about them; the dashboard's validation rebuilds the same set from the
// earlier run's stored model. A folder with no readable settings, or settings
// with no replay set, lists none. The file is the agent's to change, so the
// list is advice for the agent's own check and never a basis for a stored label.
func ReplayedFindings(projectRoot, runID string) []string {
	p := secassess.ResultPaths(runID)
	if p.Dir == "" || projectRoot == "" {
		return nil
	}
	data, err := ReadResult(projectRoot, p.ProbeConfig, MaxProbeConfigBytes)
	if err != nil {
		return nil
	}
	var cfg struct {
		Replay map[string]json.RawMessage `json:"replay"`
	}
	if json.Unmarshal(data, &cfg) != nil {
		return nil
	}
	ids := make([]string, 0, len(cfg.Replay))
	for id := range cfg.Replay {
		if secassess.ValidItemID(id) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

// ReadProbeFacts reads what a validation needs from the run folder about the
// helper: the hashes of the two files now, with the ones Observer recorded when
// it wrote them, and the parsed log. A run with no helper reads nothing; a file
// that cannot be read leaves its field empty and the facts say so (a missing or
// unreadable helper is not "intact", and an unreadable log backs nothing).
func ReadProbeFacts(projectRoot string, run Run) secassess.ProbeFacts {
	f := secassess.ProbeFacts{Mode: run.Helper, HelperWant: run.HelperSHA, ConfigWant: run.ConfigSHA}
	if run.Helper != secassess.HelperOn {
		return f
	}
	p := secassess.ResultPaths(run.ID)
	if p.Dir == "" || projectRoot == "" {
		f.LogState = secassess.LogFileUnreadable
		return f
	}
	f.HelperHave = probeFileHash(projectRoot, p.ProbeHelper)
	f.ConfigHave = probeFileHash(projectRoot, p.ProbeConfig)
	data, err := ReadResult(projectRoot, p.ProbeLog, secassess.MaxProbeLogBytes)
	switch {
	case err == nil:
		f.LogState, f.Log = secassess.LogFileOK, secassess.ParseProbeLog(data)
		if tornLastLine(data, f.Log) {
			// The helper may be mid-append (a validation with Anyway on a
			// running run): one more read once its write has landed.
			time.Sleep(probeRetryWait)
			if again, rerr := ReadResult(projectRoot, p.ProbeLog, secassess.MaxProbeLogBytes); rerr == nil {
				f.Log = secassess.ParseProbeLog(again)
			}
		}
	case errors.Is(err, ErrAbsent):
		f.LogState = secassess.LogFileAbsent
	case errors.Is(err, ErrTooLarge):
		f.LogState = secassess.LogFileTooLarge
	default:
		f.LogState = secassess.LogFileUnreadable
	}
	return f
}

// probeRetryWait is how long a read of the log waits before the one retry when
// the log ends in a line that is not complete (a var so a test can set it).
var probeRetryWait = 100 * time.Millisecond

// tornLastLine reports whether the log's only fault is a last line that has no
// newline and does not parse: the shape of a read that met the helper's write.
func tornLastLine(data []byte, log secassess.ProbeLog) bool {
	return log.Problem == secassess.LogBadLine && len(data) > 0 && data[len(data)-1] != '\n'
}

// probeFileHash is the SHA-256 (hex) of a helper file in the run folder: "" when
// it is absent or cannot be read as a regular file, "oversize" past its cap.
func probeFileHash(projectRoot, rel string) string {
	data, err := ReadResult(projectRoot, rel, maxProbeHelperBytes)
	switch {
	case err == nil:
		return sha256Hex(data)
	case errors.Is(err, ErrTooLarge):
		return probeOversize
	}
	return ""
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ProbesSchema is the schema version of the stored probes.json.
const ProbesSchema = 1

// ProbesRecord is the stored copy of the log records a model cites (side file
// probes.json): redacted, cleaned and capped by Observer
// (secassess.StoredProbe), never the helper's file as written. It is
// node-local.
type ProbesRecord struct {
	Schema      int       `json:"schema"`
	RunID       string    `json:"run_id"`
	ValidatedAt time.Time `json:"validated_at"`
	// Records is how many records the log held; Cited how many the model
	// cites that the log holds. Probes holds the cited ones in log order, at
	// most what fits the side file; Truncated says some were left out for size.
	Records   int                     `json:"records"`
	Cited     int                     `json:"cited"`
	Truncated bool                    `json:"truncated,omitempty"`
	Probes    []secassess.ProbeRecord `json:"probes"`
}

// buildProbes makes the stored copy for a validated pen test or retest: the cited records
// of a log that can back something (the helper ran, is intact and the log reads
// like the helper's); nothing otherwise, and the record says how many the log
// held.
func buildProbes(rec ModelRecord, facts secassess.ProbeFacts, redact func(string) string) ProbesRecord {
	out := ProbesRecord{Schema: ProbesSchema, RunID: rec.RunID, ValidatedAt: rec.ValidatedAt, Probes: []secassess.ProbeRecord{}}
	ev := rec.Result.Report.Evidence
	if ev == nil || (rec.Result.PT == nil && rec.Result.RT == nil) || ev.Mode != secassess.HelperOn || ev.Helper != secassess.HelperIntact || ev.Log != secassess.LogFileOK {
		return out
	}
	out.Records = len(facts.Log.Records)
	var stored []secassess.ProbeRecord
	if rec.Result.PT != nil {
		stored = secassess.StoredProbes(rec.Result.PT, facts.Log, redact)
	} else {
		stored = secassess.StoredRetestProbes(rec.Result.RT, facts.Log, redact)
	}
	out.Cited = len(stored)
	out.Probes = append(out.Probes, stored...)
	return out
}

// fitProbes marshals the record to at most limit bytes, dropping cited records
// from the end until it fits (the earlier requests of a run are the ones its
// findings lean on first).
func fitProbes(rec ProbesRecord, limit int) ([]byte, ProbesRecord) {
	for {
		b, err := marshalProbes(rec)
		if err == nil && len(b) <= limit {
			return b, rec
		}
		if len(rec.Probes) == 0 {
			return nil, rec
		}
		// Halve the tail rather than dropping one record at a time.
		rec.Probes, rec.Truncated = rec.Probes[:len(rec.Probes)/2], true
	}
}

// marshalProbes is the stored copy's encoding: JSON without markup escaping, as
// the stored model is.
func marshalProbes(r ProbesRecord) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte{'\n'}), nil
}

// storeProbes writes the stored copy of a validation's cited log records (only
// for a run that has a helper). A failed write loses the copy, never the
// verdict.
func storeProbes(side *SideData, rec ModelRecord, facts secassess.ProbeFacts, redact func(string) string) {
	if side == nil || facts.Mode != secassess.HelperOn || (rec.Result.PT == nil && rec.Result.RT == nil) {
		return
	}
	blob, _ := fitProbes(buildProbes(rec, facts, redact), sideCaps[SideProbes])
	if blob != nil {
		_ = side.Put(rec.RunID, SideProbes, blob)
	}
}

// ReadProbes reads a run's stored probes. ok is false when there is none or it
// cannot be read.
func ReadProbes(side *SideData, runID string) (ProbesRecord, bool) {
	data, ok := side.Get(runID, SideProbes)
	if !ok {
		return ProbesRecord{}, false
	}
	var rec ProbesRecord
	if err := json.Unmarshal(data, &rec); err != nil || rec.RunID != runID {
		return ProbesRecord{}, false
	}
	return rec, true
}

// replayMargin is the room kept in probe.json for everything but the replay set
// (the schema, run id, origin and limits are well under it).
const replayMargin = 1 << 10

// ReplayFits reports whether a retest's stored requests fit the settings file,
// with the room the other settings need. A plan asks it before a launch so the
// developer is told to choose fewer findings, instead of the launch failing
// when the file is written.
func ReplayFits(set map[string]secassess.ReplayEntry) bool {
	b, err := json.Marshal(set)
	return err == nil && len(b)+replayMargin <= MaxProbeConfigBytes
}
