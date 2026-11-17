package secassess

import "strings"

// The tool inventory of a penetration test (depth plan W4.3): what a pen test
// may use inside the box, which of it Observer's guard asks about, and what the
// agent does without it.

// ToolRow is one tool a pen test may use inside the box.
type ToolRow struct {
	ID      string
	Purpose string
	// Command is the executable name looked up in the box.
	Command string
	// Guarded says Observer's guard rule R-179 asks the developer before the
	// tool is run against a target.
	Guarded bool
	// Fallback is what the agent does without the tool.
	Fallback string
	// NotInPrompt keeps the row out of the prompt's inventory lines (the
	// "Tools Observer saw" and "Not seen there" lines): the dashboard's Tools
	// table, the Guarded column, the presence check and the drift test still
	// carry it. See the comment on ToolRows for why a row is kept out.
	NotInPrompt bool
}

// scannerFallback is what the agent does without a scanner.
const scannerFallback = "without it, use curl or python3 against the target"

// ToolRows is the tool table: the always-available basics first, then the
// scanners.
//
// The Guarded rows mirror EXACTLY the keys of R-179's scanner list
// (internal/policy/rules_network.go, scannerBases) that name an executable in a
// standard directory: nmap, masscan, zmap, rustscan, naabu, unicornscan,
// hping3, nikto, nuclei, sqlmap, and, since the guard lane's D33 extension,
// ffuf, gobuster, feroxbuster, hydra, wfuzz and zaproxy. This package may not
// import the policy package, so the match is held by a test in the dashboard
// package that evaluates "<tool> http://localhost:3000" through the policy
// engine for every row and asserts R-179 fires for exactly the rows marked
// Guarded, and that every well-known scanner R-179 asks about has a row.
//
// zap.sh and zap-baseline.py are the other two keys of that list. They are
// launcher scripts of the zaproxy row's tool that live in ZAP's own install
// folder, not in the standard directories the presence check looks in, so a
// row for either would report "not found" for a box that has ZAP. The zaproxy
// row's purpose names them, and the same test asserts R-179 asks about both.
//
// A scanner R-179 does not list is NOT in this table on purpose: it would be
// unguarded here, and a fuzzer or a credential guesser makes thousands of
// requests against a budget of hundreds. If the guard lane extends R-179 again,
// add the rows then with Guarded true, and the drift test will name any row
// this column no longer matches.
//
// The six rows the D33 extension added (ffuf, gobuster, feroxbuster, hydra,
// wfuzz, zaproxy) are NotInPrompt: they are in the table, guarded and shown to
// the developer, but the prompt's inventory lines do not name them. The reason
// is the prompt budget. TestPromptBudget holds every kind under a 22 KiB pin
// (plan 3.8), which leaves two KiB under the 24 KiB argument cap, and the red
// team task stood only 17 bytes under that pin. Naming the six in the "saw"
// line costs 52 bytes, which put it 35 over. The prompt already says that
// Observer looked from the daemon and not from inside the box and to run
// `command -v <tool>` before relying on any tool, and that a scanner is an
// option, never a requirement, so a tool the line does not name is not read as
// absent; and R-179 asks about the six whether the prompt names them or not.
// Before these go back into the prompt, or anything else is added to it, read
// the worst sizes TestPromptBudget logs: the red team task has almost no margin.
//
// git is not a penetration-testing tool and is not listed.
var ToolRows = []ToolRow{
	{ID: "curl", Purpose: "send HTTP requests and read status lines, headers and bodies", Command: "curl", Fallback: "without it, use python3 (http.client)"},
	{ID: "python3", Purpose: "write small scripts with the standard library (http.client, json)", Command: "python3", Fallback: "without it, use curl"},
	{ID: "node", Purpose: "write small scripts with the built-in fetch", Command: "node", Fallback: "without it, use curl or python3"},
	{ID: "nmap", Purpose: "port and service scan", Command: "nmap", Guarded: true, Fallback: scannerFallback},
	{ID: "masscan", Purpose: "fast port scan", Command: "masscan", Guarded: true, Fallback: scannerFallback},
	{ID: "zmap", Purpose: "single-port scan of many addresses", Command: "zmap", Guarded: true, Fallback: scannerFallback},
	{ID: "rustscan", Purpose: "fast port scan that hands open ports to nmap", Command: "rustscan", Guarded: true, Fallback: scannerFallback},
	{ID: "naabu", Purpose: "port scan", Command: "naabu", Guarded: true, Fallback: scannerFallback},
	{ID: "unicornscan", Purpose: "port and protocol scan", Command: "unicornscan", Guarded: true, Fallback: scannerFallback},
	{ID: "hping3", Purpose: "crafted packet probes", Command: "hping3", Guarded: true, Fallback: scannerFallback},
	{ID: "nikto", Purpose: "web server scan for known risky files and settings", Command: "nikto", Guarded: true, Fallback: scannerFallback},
	{ID: "nuclei", Purpose: "template-driven weakness scan", Command: "nuclei", Guarded: true, Fallback: scannerFallback},
	{ID: "sqlmap", Purpose: "automated SQL injection testing", Command: "sqlmap", Guarded: true, Fallback: scannerFallback},
	{ID: "ffuf", Purpose: "web content and parameter fuzzing", Command: "ffuf", Guarded: true, Fallback: scannerFallback, NotInPrompt: true},
	{ID: "gobuster", Purpose: "directory, file and name brute forcing", Command: "gobuster", Guarded: true, Fallback: scannerFallback, NotInPrompt: true},
	{ID: "feroxbuster", Purpose: "recursive content discovery", Command: "feroxbuster", Guarded: true, Fallback: scannerFallback, NotInPrompt: true},
	{ID: "hydra", Purpose: "login guessing against a service", Command: "hydra", Guarded: true, Fallback: scannerFallback, NotInPrompt: true},
	{ID: "wfuzz", Purpose: "web request fuzzing", Command: "wfuzz", Guarded: true, Fallback: scannerFallback, NotInPrompt: true},
	{ID: "zaproxy", Purpose: "OWASP ZAP web application scan, also run as zap.sh or zap-baseline.py", Command: "zaproxy", Guarded: true, Fallback: scannerFallback, NotInPrompt: true},
}

// ToolFacts says which commands the dashboard found in the box's standard
// directories (true present, false absent); a command not in the map is
// unknown.
type ToolFacts map[string]bool

// ToolInventoryLines are the prompt lines for the tools: the ones Observer saw,
// the ones it did not (with what to do instead, grouped where the advice is the
// same), the words about scanners, and the reminder that Observer looked from
// the daemon and not from inside the box. A tool the facts do not mention, and
// a row marked NotInPrompt, is left out of the first two lines.
func ToolInventoryLines(f ToolFacts) []string { return inventoryLines(ToolRows, f) }

// inventoryLines is ToolInventoryLines over the given rows, so a test can feed
// it a row of its own without changing the table.
func inventoryLines(rows []ToolRow, f ToolFacts) []string {
	var present []string
	var order []string
	groups := map[string][]string{}
	for _, r := range rows {
		if r.NotInPrompt {
			continue
		}
		have, known := f[r.Command]
		switch {
		case !known:
		case have:
			present = append(present, r.Command)
		default:
			if _, seen := groups[r.Fallback]; !seen {
				order = append(order, r.Fallback)
			}
			groups[r.Fallback] = append(groups[r.Fallback], r.Command)
		}
	}
	var out []string
	if len(present) > 0 {
		out = append(out, "Tools Observer saw in the box's standard directories: "+strings.Join(present, ", ")+".")
	}
	if len(order) > 0 {
		parts := make([]string, len(order))
		for i, fb := range order {
			parts[i] = strings.Join(groups[fb], ", ") + " (" + fb + ")"
		}
		out = append(out, "Not seen there: "+strings.Join(parts, "; ")+".")
	}
	out = append(out,
		"Network and vulnerability scanners may need the developer's answer (R-179): the guard may ask, and a refusal is final. A scanner is an option, never a requirement.",
		"Observer looked from the daemon, not inside the box: run `command -v <tool>` before you rely on a tool.",
	)
	return out
}
