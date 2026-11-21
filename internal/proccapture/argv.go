package proccapture

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

// Argv placeholders. Stable strings: they are hashed, so changing one
// re-keys every rollup group.
const (
	phUUID = "<uuid>"
	phHex  = "<hex>"
	phNum  = "<n>"
	phTmp  = "<tmp>"
)

// templateRule is one row of the argv templating table, applied in order to
// every whitespace-separated token. Each row is a test case in argv_test.go.
type templateRule struct {
	name string
	re   *regexp.Regexp
	repl string
}

// tmpMarkers are the temp-directory path fragments (lowercased, forward
// slashes) whose whole token becomes <tmp>: a temp path differs per run and
// carries no meaning for grouping.
var tmpMarkers = []string{
	"/tmp/", "/var/tmp/", "/dev/shm/", "/appdata/local/temp/", "/windows/temp/", "/var/folders/",
}

// templateRules: UUIDs first (they contain hex and digit runs), then long hex
// ids, then decimal numbers. Distinct words, subcommands and package paths
// are untouched, so `go test ./internal/store` and `go test ./internal/db`
// stay two templates.
var templateRules = []templateRule{
	{
		name: "uuid",
		re:   regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
		repl: phUUID,
	},
	{
		// A hex run of 8 or more with at least one digit and one letter is an
		// id (a commit, a container id, a hash), not a word.
		name: "hex id",
		re:   regexp.MustCompile(`(?i)\b(?:[0-9a-f]*[0-9][0-9a-f]*[a-f][0-9a-f]*|[0-9a-f]*[a-f][0-9a-f]*[0-9][0-9a-f]*)\b`),
		repl: phHex,
	},
	{
		name: "number",
		re:   regexp.MustCompile(`[0-9]+`),
		repl: phNum,
	},
}

// Template returns argv with its volatile parts replaced by placeholders:
// UUIDs, hex ids of 8 or more characters, decimal numbers and temp paths.
// Whitespace is collapsed to single spaces. Pure and deterministic.
func Template(argv string) string {
	fields := strings.Fields(argv)
	for i, tok := range fields {
		fields[i] = templateToken(tok)
	}
	return strings.Join(fields, " ")
}

func templateToken(tok string) string {
	low := strings.ToLower(strings.ReplaceAll(tok, `\`, "/"))
	for _, m := range tmpMarkers {
		if strings.Contains(low, m) || strings.HasPrefix(low, strings.TrimPrefix(m, "/")) {
			return phTmp
		}
	}
	for _, r := range templateRules {
		if r.name == "hex id" {
			tok = r.re.ReplaceAllStringFunc(tok, func(s string) string {
				if len(s) < 8 {
					return s
				}
				return phHex
			})
			continue
		}
		tok = r.re.ReplaceAllString(tok, r.repl)
	}
	return tok
}

// TemplateHash is the rollup key for an argv: a short sha256 of
// exe + Template(argv). The executable is part of the key so the same
// arguments under two programs never share a group.
func TemplateHash(exe, argv string) string {
	h := sha256.Sum256([]byte(NormalizeExe(exe) + "\x00" + Template(argv)))
	return hex.EncodeToString(h[:8])
}
