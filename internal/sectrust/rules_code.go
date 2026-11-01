package sectrust

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// code judges a plugin, custom tool or crushrc the agent loads and runs:
// one repository-run reason whose digest covers the file's exact bytes.
// Its source is never searched for file names (namedFiles): a plugin is
// code, not a command line, and splitting a 256 KiB source into words would
// cost a lookup per word.
func (c *checker) code(file string, data []byte) {
	sum := sha256.Sum256(data)
	c.add(Reason{
		Code: "plugin_code", File: file, Excerpt: excerpt(string(data)),
		Digest:     FileDigest("plugin_code", file, hex.EncodeToString(sum[:]), int64(len(data))),
		ownContent: string(data),
	})
}

// tasks judges a VS Code tasks.json: a task that runs when the folder
// opens is a repository-run command.
func (c *checker) tasks(file string, data []byte) {
	v, err := decode(file, data)
	if err != nil {
		c.parseError(file, data, err)
		return
	}
	m, _ := v.(map[string]any)
	list, _ := m["tasks"].([]any)
	for i, t := range list {
		tm, _ := t.(map[string]any)
		ro, _ := tm["runOptions"].(map[string]any)
		if ro == nil || ro["runOn"] != "folderOpen" {
			continue
		}
		parts := []string{fmt.Sprint(tm["command"])}
		if args, ok := tm["args"].([]any); ok {
			for _, a := range args {
				parts = append(parts, fmt.Sprint(a))
			}
		}
		c.addRun("folder_open_task", file, fmt.Sprintf("tasks.%d", i), strings.Join(parts, " "), true)
	}
}

// hiddenUnicode is the plan's item (3) detector on instruction, rule,
// skill, agent and command files (the "Rules File Backdoor" technique).
func (c *checker) hiddenUnicode(file string, data []byte) {
	if !utf8.Valid(data) {
		return
	}
	var tag, bidi, zw int
	first := ""
	runes := []rune(string(data))
	for i, r := range runes {
		switch {
		case r >= 0xE0000 && r <= 0xE007F:
			tag++
		case (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) || r == 0x200E || r == 0x200F || r == 0x061C:
			bidi++
		case r == 0x200B || r == 0x200C || r == 0x2060 || r == 0x180E || (r == 0xFEFF && i > 0):
			zw++
		case r == 0x200D:
			// A zero-width joiner between two symbol-range runes is an
			// emoji sequence.
			if i > 0 && i+1 < len(runes) && runes[i-1] >= 0x2000 && runes[i+1] >= 0x2000 {
				continue
			}
			zw++
		default:
			continue
		}
		if first == "" {
			first = fmt.Sprintf("U+%04X at rune %d", r, i)
		}
	}
	// The digest covers the file's exact bytes: an accepted file asks again
	// when it changes.
	sum := sha256.Sum256(data)
	value := fmt.Sprintf("file:sha256:%s:%d", hex.EncodeToString(sum[:]), len(data))
	switch {
	case tag > 0:
		c.add(Reason{Code: "hidden_unicode_tag", File: file, Excerpt: fmt.Sprintf("%d tag characters, first %s", tag, first), value: value})
	case bidi > 0:
		c.add(Reason{Code: "hidden_unicode_bidi", File: file, Excerpt: fmt.Sprintf("%d bidi controls, first %s", bidi, first), value: value})
	case zw > 0:
		c.add(Reason{Code: "hidden_unicode_zero_width", File: file, Excerpt: fmt.Sprintf("%d zero-width characters, first %s", zw, first), value: value})
	}
}

// indicatorRow words a command; it never decides a level.
type indicatorRow struct {
	word string
	re   *regexp.Regexp
}

// indicatorTable is the ordered wording table (the JSP-7 indicator list).
var indicatorTable = []indicatorRow{
	{"downloads with curl or wget", regexp.MustCompile(`(?i)\b(curl|wget)\b|invoke-webrequest|\biwr\b`)},
	{"pipes into a shell", regexp.MustCompile(`(?i)\|\s*(ba|z|da)?sh\b|\|\s*iex\b`)},
	{"decodes base64", regexp.MustCompile(`(?i)\bbase64\b|frombase64string`)},
	{"runs an encoded PowerShell command", regexp.MustCompile(`(?i)\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{16,}`)},
	{"evaluates code from a string", regexp.MustCompile(`(?i)\beval\b|invoke-expression|\biex\b|python3?\s+-c\b|node\s+-e\b|perl\s+-e\b|ruby\s+-e\b`)},
	{"opens a raw network socket", regexp.MustCompile(`(?i)/dev/tcp/|\bnc\s+-|\bncat\b|\bsocat\b`)},
	{"names a URL", regexp.MustCompile(`(?i)https?://`)},
	{"touches a credential file", regexp.MustCompile(`(?i)\.ssh/|\.aws/credentials|\.npmrc|\.netrc|\.git-credentials|\.docker/config\.json`)},
	{"installs persistence", regexp.MustCompile(`(?i)\bcrontab\b|\blaunchctl\b|\bsystemctl\b|\bschtasks\b|\bosascript\b`)},
}

// indicators words a command with every indicator row it matches.
func indicators(cmd string) []string {
	var out []string
	for _, r := range indicatorTable {
		if r.re.MatchString(cmd) {
			out = append(out, r.word)
		}
	}
	return out
}

func sortStrings(s []string) { sort.Strings(s) }
