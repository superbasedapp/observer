package secassess

import "strings"

// The prompt's section about the request helper (depth plan W5b). The helper's
// own usage text is in the script (`python3 probe.py --help`), so the prompt
// carries only what the agent must do to make a finding countable: send
// requests through it, cite the ids it prints, and name an attack request, a
// control request and the response condition that tells them apart.

// helperPromptLines are the lines of the REQUEST HELPER section. "<run dir>"
// is replaced by the run directory when the prompt is written.
var helperPromptLines = []string{
	"Send each request with `python3 <run dir>/probe.py GET /path [-H 'Name: value'] [-d BODY] --role attack|control --wstg ATHN`. It prints a probe id (p1, p2, ...) and the response, refuses any other address, keeps the pace and budget and logs each request.",
	"Pass --account NAME when a request tries credentials: attempts are counted per account and path. Cite the ids in coverage probes and finding evidence. For each weakness send a control request and an attack request, name them in indicator.control and indicator.attack, and put in indicator.when what holds for the attack response and not the control. A request sent another way (curl, your code) is not logged: its finding reads No log.",
	"Do not edit, copy or delete probe.py, probe.json or probes.jsonl; Observer compares them with what it wrote, and a change makes every finding read No log.",
}

// PentestHelperLines are the prompt lines for the request helper; nil for a
// kind with no helper.
func PentestHelperLines(runDir string) []string {
	fill := strings.NewReplacer("<run dir>", runDir)
	out := make([]string, len(helperPromptLines))
	for i, l := range helperPromptLines {
		out[i] = fill.Replace(l)
	}
	return out
}

// retestHelperPromptLines are the lines of the REQUEST HELPER section of a
// retest (depth plan W7.2): the helper replays the stored requests itself, so
// the section says how to ask for a replay and how to cite what it logged.
var retestHelperPromptLines = []string{
	"Send requests only with `python3 <run dir>/probe.py` (its --help lists the options). `python3 <run dir>/probe.py --replay ID` sends the stored requests of finding ID in order. It prints a probe id (p1, p2, ...) and the response, refuses any other address, keeps the pace and budget and logs each request. A request sent another way is not logged, and its result reads No log.",
	"Cite probe ids in the result model: attack is the replayed request that shows the weakness, control an ordinary request sent with `probe.py GET /path --role control` that should not. Do not edit, copy or delete probe.py, probe.json or probes.jsonl; Observer compares them with what it wrote, and a change makes every result read No log.",
}

// RetestHelperLines are the prompt lines for the request helper of a retest.
func RetestHelperLines(runDir string) []string {
	fill := strings.NewReplacer("<run dir>", runDir)
	out := make([]string, len(retestHelperPromptLines))
	for i, l := range retestHelperPromptLines {
		out[i] = fill.Replace(l)
	}
	return out
}
