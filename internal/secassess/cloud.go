package secassess

import (
	"slices"
	"strings"
)

// CloudClass is how ClassifyCloudCommand sorts one line of commands.txt.
type CloudClass string

// The classes.
const (
	// CloudReadOnly: a verb the read-only boundary allows (list, describe,
	// get, show and their kin).
	CloudReadOnly CloudClass = "read_only"
	// CloudSecretMaterial: a command that, by its words, returns secret
	// material even when its verb reads.
	CloudSecretMaterial CloudClass = "secret_material"
	// CloudMutating: a verb that creates, changes, deletes or runs something.
	CloudMutating CloudClass = "mutating"
	// CloudUnknown: not a cloud CLI Observer reads, or a line it cannot read.
	CloudUnknown CloudClass = "unknown"
)

// CloudCounts is the classified commands.txt, by class.
type CloudCounts struct {
	ReadOnly       int `json:"read_only"`
	SecretMaterial int `json:"secret_material"`
	Mutating       int `json:"mutating"`
	Unknown        int `json:"unknown"`
}

// Total is every counted line.
func (c CloudCounts) Total() int { return c.ReadOnly + c.SecretMaterial + c.Mutating + c.Unknown }

// Crossed reports whether the list holds a command outside the read-only
// boundary: a mutating one or one that returns secret material. An unknown
// line is not counted as crossing (Observer cannot tell), only shown.
func (c CloudCounts) Crossed() bool { return c.Mutating > 0 || c.SecretMaterial > 0 }

// secretWords make a command secret-material by its words, whatever its verb.
var secretWords = []string{
	"secret", "password", "passwd", "decrypt", "access-token", "get-token", "private-key",
	"get-login", "with-decryption", "session-token", "get-credentials", "print-identity-token",
	"credentials",
}

// cloudCLI is one row of the CLI table: the program, the verbs it reads with
// and the verbs it changes things with. A verb is matched as the whole word
// or by its prefix up to a dash ("describe-instances" has prefix "describe").
type cloudCLI struct {
	Base      string
	ReadVerb  []string
	WriteVerb []string
	// ValuedFlags take the next word as their value (skipped when finding
	// the verb).
	ValuedFlags []string
	// Pick says which positional is the verb.
	Pick pickMode
}

// pickMode says how a CLI's verb is found among its positional words.
type pickMode int

const (
	// pickFirst: the first word is the verb (kubectl get ...).
	pickFirst pickMode = iota
	// pickSecond: the second word is (aws <service> <operation>).
	pickSecond
	// pickLastMatch: the last word that is a known verb (az and gcloud put
	// resource names after the verb).
	pickLastMatch
)

func secondWord(pos []string) string {
	if len(pos) < 2 {
		return ""
	}
	return pos[1]
}

func firstWord(pos []string) string {
	if len(pos) == 0 {
		return ""
	}
	return pos[0]
}

// verb returns the command's verb word, "" when there is none.
func (c cloudCLI) verb(pos []string) string {
	switch c.Pick {
	case pickSecond:
		return secondWord(pos)
	case pickLastMatch:
		for i := len(pos) - 1; i >= 0; i-- {
			if verbMatches(pos[i], c.WriteVerb) || verbMatches(pos[i], c.ReadVerb) {
				return pos[i]
			}
		}
		return ""
	default:
		return firstWord(pos)
	}
}

// cloudCLIs is the table, one row per CLI Observer reads. A CLI with no row is
// "unknown".
var cloudCLIs = []cloudCLI{
	{
		Base:        "aws",
		ReadVerb:    []string{"list", "describe", "get", "head", "lookup", "search", "ls", "batch-get"},
		WriteVerb:   []string{"create", "delete", "put", "update", "modify", "terminate", "run", "start", "stop", "reboot", "attach", "detach", "authorize", "revoke", "tag", "untag", "invoke", "cp", "mv", "rm", "sync", "deploy", "enable", "disable", "set", "add", "remove", "associate", "disassociate", "register", "deregister", "import", "restore", "reset", "rotate", "send", "publish", "apply", "execute", "assume"},
		ValuedFlags: []string{"--profile", "--region", "--output", "--query", "--endpoint-url", "--filters", "--max-items", "--page-size"},
		Pick:        pickSecond,
	},
	{
		Base:        "az",
		ReadVerb:    []string{"list", "show", "get", "exists", "check"},
		WriteVerb:   []string{"create", "delete", "update", "set", "add", "remove", "start", "stop", "restart", "deploy", "assign", "purge", "login", "invoke", "run", "import", "restore", "regenerate", "move", "upgrade"},
		ValuedFlags: []string{"--subscription", "--resource-group", "-g", "--output", "-o", "--query", "--name", "-n"},
		Pick:        pickLastMatch,
	},
	{
		Base:        "gcloud",
		ReadVerb:    []string{"list", "describe", "get", "read", "search"},
		WriteVerb:   []string{"create", "delete", "update", "set", "add", "remove", "start", "stop", "deploy", "enable", "disable", "import", "restore", "resize", "reset", "move", "submit", "run", "execute", "call", "login", "revoke"},
		ValuedFlags: []string{"--project", "--format", "--filter", "--zone", "--region", "--limit", "--impersonate-service-account"},
		Pick:        pickLastMatch,
	},
	{
		Base:        "kubectl",
		ReadVerb:    []string{"get", "describe", "top", "version", "api-resources", "api-versions", "explain", "logs", "events", "cluster-info", "view", "get-contexts", "current-context"},
		WriteVerb:   []string{"apply", "create", "delete", "patch", "replace", "edit", "scale", "rollout", "exec", "cp", "run", "expose", "label", "annotate", "taint", "drain", "cordon", "uncordon", "set", "autoscale", "debug", "attach", "port-forward", "proxy"},
		ValuedFlags: []string{"-n", "--namespace", "--context", "--cluster", "-o", "--output", "-l", "--selector", "-f", "--kubeconfig"},
		Pick:        pickFirst,
	},
	{
		Base:      "terraform",
		ReadVerb:  []string{"show", "output", "validate", "version", "providers", "graph", "plan", "fmt"},
		WriteVerb: []string{"apply", "destroy", "import", "taint", "untaint", "state", "workspace", "init", "refresh", "login", "force-unlock"},
		Pick:      pickFirst,
	},
}

// verbMatches reports whether verb is one of the table verbs, whole or as a
// dash-separated prefix.
func verbMatches(verb string, set []string) bool {
	for _, v := range set {
		if verb == v || strings.HasPrefix(verb, v+"-") {
			return true
		}
	}
	return false
}

// shellRisk reports a line whose real command cannot be read: command
// chaining, substitution or redirection, or a pipe into something that runs
// what it is handed.
func shellRisk(line string) bool {
	if strings.ContainsAny(line, ";`><") || strings.Contains(line, "&&") || strings.Contains(line, "||") || strings.Contains(line, "$(") {
		return true
	}
	if _, right, ok := strings.Cut(line, "|"); ok {
		for _, w := range strings.Fields(right) {
			switch w {
			case "sh", "bash", "zsh", "xargs", "eval", "source", "python", "python3", "node", "perl", "ruby":
				return true
			}
		}
	}
	return false
}

// commandWords are the words of the cloud command on a line: the part before
// a pipe, without leading VAR=value words and a leading sudo or env.
func commandWords(line string) []string {
	cmd, _, _ := strings.Cut(line, "|")
	words := strings.Fields(cmd)
	for len(words) > 0 && (strings.Contains(words[0], "=") && !strings.HasPrefix(words[0], "-") || words[0] == "sudo" || words[0] == "env") {
		words = words[1:]
	}
	return words
}

// programBase is a command word reduced to the program name: lower case,
// without its directory and without a .exe suffix.
func programBase(word string) string {
	base := strings.ToLower(word)
	if i := strings.LastIndexAny(base, "/\\"); i >= 0 {
		base = base[i+1:]
	}
	return strings.TrimSuffix(base, ".exe")
}

// cliFor is the table row of a program, nil when Observer reads no such CLI.
func cliFor(base string) *cloudCLI {
	for i := range cloudCLIs {
		if cloudCLIs[i].Base == base {
			return &cloudCLIs[i]
		}
	}
	return nil
}

// positionals are the lower-cased positional words among args: flags are
// skipped, and so is the value of a flag the row says takes one.
func (c cloudCLI) positionals(args []string) []string {
	var pos []string
	for i := 0; i < len(args); i++ {
		a := strings.ToLower(args[i])
		if !strings.HasPrefix(a, "-") {
			pos = append(pos, a)
			continue
		}
		if !strings.Contains(a, "=") && slices.Contains(c.ValuedFlags, a) {
			i++
		}
	}
	return pos
}

// namesSecretMaterial reports a line that, by its words, returns secret
// material. A list or describe verb returns metadata, not values, unless the
// line asks for decryption; any other verb that names secret material is
// secret material.
func namesSecretMaterial(lower, verb string) bool {
	if verbMatches(verb, []string{"list", "describe"}) && !strings.Contains(lower, "decrypt") {
		return false
	}
	for _, w := range secretWords {
		if strings.Contains(lower, w) {
			return true
		}
	}
	return false
}

// subcommandRule is a CLI whose first word groups verbs (kubectl config and
// kubectl auth): the class of the second word decides.
type subcommandRule struct {
	// Base and Group name the CLI and its grouping word.
	Base, Group string
	// ReadWords are the second words that only read; every other second word
	// of the group changes something.
	ReadWords []string
	// ReadVerbs says the CLI row's own read verbs are read words too.
	ReadVerbs bool
}

// subcommandRules is the table of grouped verbs: kubectl config view,
// get-contexts and current-context read (use-context and set-* change the local
// config); kubectl auth can-i reads.
var subcommandRules = []subcommandRule{
	{Base: "kubectl", Group: "config", ReadVerbs: true},
	{Base: "kubectl", Group: "auth", ReadWords: []string{"can-i"}},
}

// classifyVerb is the class of a verb under a CLI row: a grouped verb is read
// through its rule, then the row's write verbs, then its read verbs.
func classifyVerb(row *cloudCLI, verb string, pos []string) CloudClass {
	if verb == "" {
		return CloudUnknown
	}
	for _, r := range subcommandRules {
		if r.Base != row.Base || r.Group != verb {
			continue
		}
		second := secondWord(pos)
		if slices.Contains(r.ReadWords, second) || (r.ReadVerbs && verbMatches(second, row.ReadVerb)) {
			return CloudReadOnly
		}
		return CloudMutating
	}
	switch {
	case verbMatches(verb, row.WriteVerb):
		return CloudMutating
	case verbMatches(verb, row.ReadVerb):
		return CloudReadOnly
	}
	return CloudUnknown
}

// ClassifyCloudCommand sorts one command line of commands.txt. It is a
// heuristic over the agent's own list (a table of verbs per CLI): it reads
// what the line says, never what the CLI does, and it is not a trace.
func ClassifyCloudCommand(line string) CloudClass {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return ""
	}
	if shellRisk(line) {
		return CloudUnknown
	}
	words := commandWords(line)
	if len(words) == 0 {
		return CloudUnknown
	}
	row := cliFor(programBase(words[0]))
	if row == nil {
		return CloudUnknown
	}
	pos := row.positionals(words[1:])
	verb := row.verb(pos)
	cmd, _, _ := strings.Cut(line, "|")
	if namesSecretMaterial(strings.ToLower(cmd), verb) {
		return CloudSecretMaterial
	}
	return classifyVerb(row, verb, pos)
}

// CountCloudCommands classifies every non-blank, non-comment line of a
// commands.txt body.
func CountCloudCommands(body string) CloudCounts {
	var c CloudCounts
	for _, line := range strings.Split(body, "\n") {
		switch ClassifyCloudCommand(line) {
		case CloudReadOnly:
			c.ReadOnly++
		case CloudSecretMaterial:
			c.SecretMaterial++
		case CloudMutating:
			c.Mutating++
		case CloudUnknown:
			c.Unknown++
		}
	}
	return c
}
