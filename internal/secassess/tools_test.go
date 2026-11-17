package secassess

import (
	"sort"
	"strings"
	"testing"
)

// toolR179 is a COPY of the keys of scannerBases in internal/policy/rules_network.go
// (R-179, "network / vulnerability scanner") that name an executable the table
// looks for; zap.sh and zap-baseline.py are the other two keys and are covered
// by the zaproxy row (toolR179Aliases). This package may not import the policy
// package; the real pin is the drift test in the dashboard package, which
// evaluates "<tool> http://localhost:3000" through the policy engine for every
// ToolRows entry. This copy keeps the table honest between those runs.
var toolR179 = []string{
	"nmap", "masscan", "zmap", "rustscan", "naabu", "unicornscan", "hping3", "nikto", "nuclei", "sqlmap",
	"ffuf", "gobuster", "feroxbuster", "hydra", "wfuzz", "zaproxy",
}

// toolR179Aliases are the R-179 keys that are launchers of a listed tool and
// have no row of their own, each with the row that covers it.
var toolR179Aliases = map[string]string{"zap.sh": "zaproxy", "zap-baseline.py": "zaproxy"}

func TestToolRowsTable(t *testing.T) {
	ids, cmds := map[string]bool{}, map[string]bool{}
	for _, r := range ToolRows {
		t.Run(r.ID, func(t *testing.T) {
			if r.ID == "" || ids[r.ID] || r.Command == "" || cmds[r.Command] {
				t.Fatalf("row %+v has an empty or repeated id or command", r)
			}
			ids[r.ID], cmds[r.Command] = true, true
			if strings.TrimSpace(r.Purpose) == "" || strings.TrimSpace(r.Fallback) == "" {
				t.Errorf("row %s lacks a purpose or a fallback", r.ID)
			}
			if clean(r.Command, 40) != r.Command || strings.ContainsAny(r.Command, " /\\") {
				t.Errorf("command %q is not a bare executable name", r.Command)
			}
			mCheckWords(t, "tool row "+r.ID, r.Purpose+" "+r.Fallback)
		})
	}
	if ids["git"] {
		t.Error("git is not a penetration-testing tool")
	}
}

func TestToolRowsGuardedMirrorsR179(t *testing.T) {
	var guarded []string
	for _, r := range ToolRows {
		if r.Guarded {
			guarded = append(guarded, r.Command)
		}
	}
	want := append([]string(nil), toolR179...)
	sort.Strings(guarded)
	sort.Strings(want)
	if strings.Join(guarded, ",") != strings.Join(want, ",") {
		t.Errorf("the Guarded rows are %v, R-179 lists %v", guarded, want)
	}
	// The basics are never guarded; a scanner row says what to do without it.
	for _, r := range ToolRows {
		switch r.Command {
		case "curl", "python3", "node":
			if r.Guarded {
				t.Errorf("%s is Guarded", r.Command)
			}
		}
		if r.Guarded && r.Fallback != "without it, use curl or python3 against the target" {
			t.Errorf("scanner %s fallback is %q", r.Command, r.Fallback)
		}
	}
	// A tool R-179 does not list is not in the table (if the guard lane extends
	// R-179 again, the rows are added then, with Guarded true).
	for _, name := range []string{"zap-cli", "wpscan", "dirb", "dirbuster", "dirsearch", "medusa", "john", "hashcat"} {
		for _, r := range ToolRows {
			if r.Command == name {
				t.Errorf("%s is in the table but R-179 does not list it", name)
			}
		}
	}
	// An alias has no row: its purpose is said in the row that covers it, which
	// is Guarded and names the alias.
	for alias, cover := range toolR179Aliases {
		found := false
		for _, r := range ToolRows {
			if r.Command == alias {
				t.Errorf("%s is a launcher of %s and has no row of its own", alias, cover)
			}
			if r.Command == cover {
				found = true
				if !r.Guarded || !strings.Contains(r.Purpose, alias) {
					t.Errorf("the %s row is not Guarded or does not name %s: %+v", cover, alias, r)
				}
			}
		}
		if !found {
			t.Errorf("%s is covered by the %s row, which is missing", alias, cover)
		}
	}
}

// toolFactsAll returns facts with every row set to have.
func toolFactsAll(have bool) ToolFacts {
	f := ToolFacts{}
	for _, r := range ToolRows {
		f[r.Command] = have
	}
	return f
}

func TestToolInventoryLines(t *testing.T) {
	const scannerLine = "Network and vulnerability scanners may need the developer's answer (R-179): the guard may ask, and a refusal is final. A scanner is an option, never a requirement."
	const lookLine = "Observer looked from the daemon, not inside the box: run `command -v <tool>` before you rely on a tool."
	cases := []struct {
		name    string
		facts   ToolFacts
		must    []string
		mustNot []string
	}{
		{
			"every tool present", toolFactsAll(true),
			[]string{"Tools Observer saw in the box's standard directories: curl, python3, node, nmap, masscan, zmap, rustscan, naabu, unicornscan, hping3, nikto, nuclei, sqlmap.", scannerLine, lookLine},
			[]string{"Not seen there"},
		},
		{
			"every tool absent", toolFactsAll(false),
			[]string{"Not seen there: curl (without it, use python3 (http.client)); python3 (without it, use curl); node (without it, use curl or python3); nmap, masscan, zmap, rustscan, naabu, unicornscan, hping3, nikto, nuclei, sqlmap (without it, use curl or python3 against the target).", scannerLine, lookLine},
			[]string{"Tools Observer saw"},
		},
		{
			"python3 absent, the rest of the basics present",
			ToolFacts{"curl": true, "python3": false, "node": true},
			[]string{"standard directories: curl, node.", "Not seen there: python3 (without it, use curl).", scannerLine, lookLine},
			[]string{"nmap"},
		},
		{
			"node absent",
			ToolFacts{"curl": true, "python3": true, "node": false},
			[]string{"standard directories: curl, python3.", "Not seen there: node (without it, use curl or python3)."},
			nil,
		},
		{
			"a scanner present and one absent",
			ToolFacts{"curl": true, "nmap": true, "nikto": false},
			[]string{"standard directories: curl, nmap.", "Not seen there: nikto (without it, use curl or python3 against the target)."},
			[]string{"python3 (", ", python3", "node"},
		},
		{
			"unknown commands are left out",
			ToolFacts{"curl": true, "mystery": true, "dirsearch": false},
			[]string{"standard directories: curl."},
			[]string{"mystery", "dirsearch", "Not seen"},
		},
		{
			"a row kept out of the prompt is left out, present or absent",
			ToolFacts{"curl": true, "nmap": true, "ffuf": true, "hydra": false, "zaproxy": true},
			[]string{"standard directories: curl, nmap."},
			[]string{"ffuf", "hydra", "zaproxy", "Not seen"},
		},
		{"no facts at all", nil, []string{scannerLine, lookLine}, []string{"Tools Observer saw", "Not seen there"}},
		{"empty facts", ToolFacts{}, []string{scannerLine, lookLine}, []string{"Tools Observer saw", "Not seen there"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lines := ToolInventoryLines(tc.facts)
			all := strings.Join(lines, "\n")
			for _, m := range tc.must {
				if !strings.Contains(all, m) {
					t.Errorf("lines lack %q:\n%s", m, all)
				}
			}
			for _, m := range tc.mustNot {
				if strings.Contains(all, m) {
					t.Errorf("lines carry %q:\n%s", m, all)
				}
			}
			for _, l := range lines {
				if strings.ContainsAny(l, "\r\n") || strings.TrimSpace(l) == "" {
					t.Errorf("line is empty or has a break: %q", l)
				}
				mCheckWords(t, "inventory line", l)
			}
			// The two closing lines are always there, last, in this order.
			if n := len(lines); n < 2 || lines[n-2] != scannerLine || lines[n-1] != lookLine {
				t.Errorf("the scanner and look lines are not the last two: %q", lines)
			}
		})
	}
}

// toolNotInPrompt are the six rows the D33 extension of R-179 added: in the
// table and guarded, kept out of the prompt's inventory lines to hold the red
// team task under its size pin (the comment on ToolRows).
var toolNotInPrompt = []string{"ffuf", "gobuster", "feroxbuster", "hydra", "wfuzz", "zaproxy"}

func TestToolRowsNotInPrompt(t *testing.T) {
	var got []string
	for _, r := range ToolRows {
		if r.NotInPrompt {
			got = append(got, r.Command)
			if !r.Guarded {
				t.Errorf("%s is kept out of the prompt but is not Guarded", r.Command)
			}
		}
	}
	if strings.Join(got, ",") != strings.Join(toolNotInPrompt, ",") {
		t.Errorf("the NotInPrompt rows are %v, want %v", got, toolNotInPrompt)
	}
	// Whatever the facts say about them, the prompt's lines never name them,
	// and the lines are exactly what they were before the rows existed.
	for _, have := range []bool{true, false} {
		f := toolFactsAll(have)
		lines := strings.Join(ToolInventoryLines(f), "\n")
		for _, name := range toolNotInPrompt {
			if strings.Contains(lines, name) {
				t.Errorf("the inventory (present=%v) names %s", have, name)
			}
		}
		without := ToolFacts{}
		for _, r := range ToolRows {
			if !r.NotInPrompt {
				without[r.Command] = have
			}
		}
		if lines != strings.Join(ToolInventoryLines(without), "\n") {
			t.Errorf("the inventory (present=%v) differs with the six rows in the facts", have)
		}
	}
	// The field is the whole mechanism, not the names: a row of any name with it
	// set is skipped, and one without it is listed.
	rows := []ToolRow{
		{ID: "keepme", Command: "keepme", Fallback: "x"},
		{ID: "skipme", Command: "skipme", Fallback: "x", NotInPrompt: true},
	}
	if got := strings.Join(inventoryLines(rows, ToolFacts{"keepme": true, "skipme": true}), "\n"); !strings.Contains(got, "directories: keepme.") || strings.Contains(got, "skipme") {
		t.Errorf("present: %q", got)
	}
	if got := strings.Join(inventoryLines(rows, ToolFacts{"keepme": false, "skipme": false}), "\n"); !strings.Contains(got, "Not seen there: keepme (x).") || strings.Contains(got, "skipme") {
		t.Errorf("absent: %q", got)
	}
}

func TestToolInventorySize(t *testing.T) {
	// Every row present, every row absent, and a mix: all under 1 KiB.
	mixed := ToolFacts{}
	for i, r := range ToolRows {
		mixed[r.Command] = i%2 == 0
	}
	for name, f := range map[string]ToolFacts{"present": toolFactsAll(true), "absent": toolFactsAll(false), "mixed": mixed} {
		total := 0
		for _, l := range ToolInventoryLines(f) {
			total += len(l) + 1
		}
		if total >= 1<<10 {
			t.Errorf("the inventory with every row %s is %d bytes, over 1 KiB", name, total)
		}
		t.Logf("tool inventory (%s) %d bytes", name, total)
	}
}
