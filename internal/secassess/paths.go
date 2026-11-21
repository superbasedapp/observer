package secassess

// RunIDLen is the length of a run id: 16 lower-case hex characters.
const RunIDLen = 16

// ValidRunID reports whether s is a run id. A run id names a directory under
// ResultRoot and is a part of an imported finding's rule id, so its alphabet
// is closed.
func ValidRunID(s string) bool {
	if len(s) != RunIDLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// ResultRoot is the project-relative directory every run's directory sits in.
const ResultRoot = ".observer/assessments"

// Paths are a run's project-relative, slash-separated result paths.
type Paths struct {
	Dir      string
	Report   string
	SARIF    string
	Commands string
	// Model is the agent's assessment.json (kinds with a model contract).
	Model string
	// ProbeHelper, ProbeConfig and ProbeLog are the request helper's three
	// files (a kind that probes; the first two are written by Observer, the
	// last by the helper).
	ProbeHelper, ProbeConfig, ProbeLog string
}

// ResultPaths returns the result paths of runID ("" paths when runID is not a
// valid run id, so a caller cannot build a path from a bad id).
func ResultPaths(runID string) Paths {
	if !ValidRunID(runID) {
		return Paths{}
	}
	dir := ResultRoot + "/" + runID
	return Paths{
		Dir: dir, Report: dir + "/" + FileReport, SARIF: dir + "/" + FileSARIF, Commands: dir + "/" + FileCommands, Model: dir + "/" + FileAssessment,
		ProbeHelper: dir + "/" + FileProbeHelper, ProbeConfig: dir + "/" + FileProbeConfig, ProbeLog: dir + "/" + FileProbeLog,
	}
}
