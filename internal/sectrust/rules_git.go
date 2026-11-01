package sectrust

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"
)

// gitKey is one parsed .git/config entry.
type gitKey struct {
	section string // lower-cased
	sub     string // as written (subsections are case-sensitive)
	name    string // lower-cased
	value   string
}

// full is the dotted key as git prints it.
func (k gitKey) full() string {
	if k.sub != "" {
		return k.section + "." + k.sub + "." + k.name
	}
	return k.section + "." + k.name
}

// gitRule is one row of the .git/config key table; the first matching row
// raises its code. defines, when set, names the driver the key defines.
type gitRule struct {
	code    string
	match   func(k gitKey) bool
	defines bool
}

// gitCommandKeys run a command named in the value.
var gitCommandKeys = map[string]bool{
	"core.sshcommand": true, "core.pager": true, "core.editor": true, "sequence.editor": true,
	"core.askpass": true, "diff.external": true, "uploadpack.packobjectshook": true, "core.gitproxy": true,
}

// gitRules is the ordered .git/config table. These keys can only reach the
// check on a tree that arrived by archive, copy or an agent's edit: a fresh
// git clone writes its own .git/config (plan section 5.1, revision 2.4
// change (e)).
var gitRules = []gitRule{
	{code: "git_fsmonitor", match: func(k gitKey) bool {
		v := strings.ToLower(k.value)
		return k.full() == "core.fsmonitor" && v != "" && v != "false" && v != "true"
	}},
	{code: "git_hookspath", match: func(k gitKey) bool { return k.full() == "core.hookspath" }},
	{code: "git_command_key", match: func(k gitKey) bool { return gitCommandKeys[k.section+"."+k.name] && k.sub == "" }},
	{code: "git_filter_driver", defines: true, match: func(k gitKey) bool {
		return k.section == "filter" && (k.name == "clean" || k.name == "smudge" || k.name == "process") && !strings.HasPrefix(k.value, "git-lfs ")
	}},
	{code: "git_diff_driver", defines: true, match: func(k gitKey) bool {
		return k.section == "diff" && k.sub != "" && (k.name == "textconv" || k.name == "command")
	}},
	{code: "git_merge_driver", defines: true, match: func(k gitKey) bool {
		return k.section == "merge" && k.sub != "" && k.name == "driver"
	}},
	{code: "git_alias_shell", match: func(k gitKey) bool { return k.section == "alias" && strings.HasPrefix(k.value, "!") }},
	{code: "git_alias_bypass", match: func(k gitKey) bool {
		v := strings.ToLower(k.value)
		return k.section == "alias" && (strings.Contains(v, "--no-verify") || strings.Contains(v, "hookspath"))
	}},
	{code: "git_credential_helper", match: func(k gitKey) bool { return k.section == "credential" && k.name == "helper" }},
	{code: "git_include", match: func(k gitKey) bool { return k.section == "include" || k.section == "includeif" }},
}

var reGitSection = regexp.MustCompile(`^\[\s*([A-Za-z0-9.-]+)(?:\s+"((?:[^"\\]|\\.)*)")?\s*\]`)

// parseGitConfig reads the entries of a git config file (a small subset of
// git's syntax: sections, subsections, key = value; enough for the table).
func parseGitConfig(data []byte) []gitKey {
	var out []gitKey
	section, sub := "", ""
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), MaxFileBytes)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if m := reGitSection.FindStringSubmatch(line); m != nil {
			section, sub = strings.ToLower(m[1]), m[2]
			if i := strings.IndexByte(section, '.'); i > 0 && sub == "" {
				section, sub = section[:i], m[1][i+1:]
			}
			line = strings.TrimSpace(line[len(m[0]):])
			if line == "" {
				continue
			}
		}
		k, v, _ := strings.Cut(line, "=")
		out = append(out, gitKey{
			section: section, sub: sub,
			name:  strings.ToLower(strings.TrimSpace(k)),
			value: strings.Trim(strings.TrimSpace(v), `"`),
		})
	}
	return out
}

// gitConfig judges the repository's .git/config.
func (c *checker) gitConfig(file string, data []byte) {
	for _, k := range parseGitConfig(data) {
		for _, r := range gitRules {
			if !r.match(k) {
				continue
			}
			if r.defines {
				if c.gitDefined == nil {
					c.gitDefined = map[string]string{}
				}
				c.gitDefined[k.section+"."+k.sub] += k.full() + "=" + k.value + "\x00"
			}
			c.add(Reason{Code: r.code, File: file, Key: k.full(), Excerpt: excerpt(k.value), value: k.value})
			break
		}
	}
}

var reGitAttrDriver = regexp.MustCompile(`(?:^|\s)(filter|diff|merge)=([A-Za-z0-9_.-]+)`)

// builtinDrivers are driver names git or git-lfs provide; they run nothing
// the repository chose.
var builtinDrivers = map[string]bool{
	"filter.lfs": true, "diff.lfs": true, "merge.lfs": true,
	"merge.union": true, "merge.binary": true, "merge.text": true,
	"diff.ada": true, "diff.bash": true, "diff.bibtex": true, "diff.cpp": true, "diff.csharp": true,
	"diff.css": true, "diff.dts": true, "diff.elixir": true, "diff.fortran": true, "diff.fountain": true,
	"diff.golang": true, "diff.html": true, "diff.java": true, "diff.kotlin": true, "diff.markdown": true,
	"diff.matlab": true, "diff.objc": true, "diff.pascal": true, "diff.perl": true, "diff.php": true,
	"diff.python": true, "diff.ruby": true, "diff.rust": true, "diff.scheme": true, "diff.tex": true,
	"diff.astextplain": true,
}

// gitAttributes records the drivers a .gitattributes file names.
func (c *checker) gitAttributes(file string, data []byte) {
	for _, m := range reGitAttrDriver.FindAllStringSubmatch(string(data), -1) {
		name := m[1] + "." + m[2]
		if builtinDrivers[name] {
			continue
		}
		if c.gitAttr == nil {
			c.gitAttr = map[string]string{}
		}
		if _, ok := c.gitAttr[name]; !ok {
			c.gitAttr[name] = file
		}
	}
}

// finishGit raises gitattributes_driver_defined for every driver a
// .gitattributes file names that .git/config defines.
func (c *checker) finishGit() {
	names := make([]string, 0, len(c.gitAttr))
	for n := range c.gitAttr {
		names = append(names, n)
	}
	sortStrings(names)
	for _, n := range names {
		if def := c.gitDefined[n]; def != "" {
			c.add(Reason{Code: "gitattributes_driver_defined", File: c.gitAttr[n], Key: n, Excerpt: "driver defined in .git/config", value: def})
		}
	}
}
