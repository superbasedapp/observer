package policy

import "strings"

// The delete table: which shell commands remove files, under which flag,
// whether they remove whole trees, and WHICH of their operands they
// remove. It is the one owner of "is this unit a delete" (Module rule 5:
// an ordered rule table, walked top-down, one test row per row in
// rules_destructive_test.go). R-101 and R-102 judge the recursive targets
// it returns through dangerousDeleteTarget and the anchor path; R-103
// reads its mass-deletion column; classifyWrite and R-114 read which words
// a unit destroys.
//
// Before this table (guard-deletes lane, 2026-11-24) a delete was
// recognised by command name only (rm, Remove-Item, rd/rmdir, del/erase),
// so `rsync -a --delete src/ ~`, `shred -u`, `tar --remove-files`, `find -ok
// rm` and `unlink` never reached R-101, and `find ~ -delete` reached only
// R-103's ask while `rm -rf ~` was denied.

// deleteRow is one row of deleteTable.
type deleteRow struct {
	// name labels the row in tests and docs.
	name string
	// bases are the canonical command bases (Command.Base) the row applies to.
	bases []string
	// flag names the switch that makes the invocation a delete, for
	// reasons (R-103); "" for a command that always deletes.
	flag string
	// deletes reports whether this invocation removes files at all: the
	// dialect or flag that makes the command a delete (shred -u, rsync
	// --delete, tar --remove-files, find -delete). nil means always, unless
	// execs is set.
	deletes func(*Command) bool
	// execs returns the command lines the invocation runs for each file it
	// visits (find -exec, -execdir, -ok, -okdir). The row also applies when
	// one of them, its exec-prefix wrappers stripped, is a delete this table
	// names that removes more than empty directories (`find ~ -ok rm {} ;`,
	// `-exec busybox rm`, `-exec unlink`).
	execs func(*Command) [][]string
	// recursive reports whether the targets are removed as whole trees, the
	// shape R-101 and R-102 judge. nil means never.
	recursive func(*Command) bool
	// targets returns the operands the invocation removes.
	targets func(*Command) []operand
	// everyWord marks a command every word of which names a path it
	// destroys (rm and its siblings): classifyWrite reads every token of the
	// unit as written, and R-114 none of them, the rule from before the table.
	everyWord bool
	// alsoWrites marks targets the command fills as well as prunes (rsync
	// --delete copies into the destination it deletes from), so R-114 still
	// reads them as writes.
	alsoWrites bool
	// emptyOnly marks a command that removes only empty directories (POSIX
	// rmdir): a delete for the write rules, never a mass deletion.
	emptyOnly bool
	// walk marks a command that walks the tree under each target and removes
	// what its expression selects (find): a mass deletion (R-103's ask). A
	// target names where the walk starts, not what is removed, so R-102's
	// project-root arm leaves it to R-103. R-101 still judges the start: a
	// walk that deletes from the home directory or a root is denied like
	// `rm -rf` of it.
	walk bool
	// listed reports inputs read from a file the guard cannot see (tar -T):
	// a mass deletion (R-103's ask) that allow_paths cannot clear, because
	// what it removes is not on the command line.
	listed func(*Command) bool
}

// deleteTable is walked top-down; every row whose bases name the unit and
// whose condition holds contributes its targets (one invocation can delete
// through more than one flag: `rsync --delete --remove-source-files`).
var deleteTable = []deleteRow{
	{
		name: "rm", bases: []string{"rm"},
		recursive: rmRecursive, targets: everyOperand, everyWord: true,
	},
	{
		// PowerShell: -Recurse prefix-matched at >=1 ("-r"); no other
		// Remove-Item parameter starts with r.
		name: "Remove-Item", bases: []string{"remove-item"},
		recursive: func(c *Command) bool { return psHasParam(c, "recurse", 1) },
		targets:   everyOperand, everyWord: true,
	},
	{
		name: "cmd rd / rmdir", bases: []string{"rd", "rmdir"}, deletes: inDialect(DialectCmd),
		recursive: cmdSlashS, targets: everyOperand, everyWord: true,
	},
	{
		// POSIX rmdir removes only empty directories.
		name: "rmdir", bases: []string{"rd", "rmdir"}, deletes: notDialect(DialectCmd),
		targets: everyOperand, everyWord: true, emptyOnly: true,
	},
	{
		// del/erase are cmd builtins; elsewhere the words are not a delete.
		name: "cmd del / erase", bases: []string{"del", "erase"}, deletes: inDialect(DialectCmd),
		recursive: cmdSlashS, targets: everyOperand, everyWord: true,
	},
	{
		// unlink(1) removes one name; it never recurses (a directory fails).
		name: "unlink", bases: []string{"unlink"},
		targets: everyOperand, everyWord: true,
	},
	{
		// shred overwrites its files (a write, writeBases) and with -u /
		// --remove[=HOW] removes them. It never recurses.
		name: "shred -u", bases: []string{"shred"}, flag: "-u",
		deletes: shredRemoves, targets: shredOperands,
	},
	{
		// --delete and its -before/-during/-delay/-after/-excluded/
		// -missing-args forms and the --del alias prune the destination of
		// whatever the source lacks, removing whole directories. rsync
		// refuses them without -r, -a or -d, so a delete flag is read as a
		// recursive delete of the destination whatever else the line says.
		name: "rsync --delete", bases: []string{"rsync"}, flag: "--delete",
		deletes: rsyncDeletes, recursive: always, targets: rsyncDestination, alsoWrites: true,
	},
	{
		// --remove-source-files (its old name --remove-sent-files) removes
		// every source file it transferred: the tree under a source with -r
		// or -a, the named files otherwise.
		name: "rsync --remove-source-files", bases: []string{"rsync"}, flag: "--remove-source-files",
		deletes: rsyncRemovesSources, recursive: rsyncRecursive, targets: rsyncSources,
	},
	{
		// GNU tar --remove-files removes each input after archiving it,
		// directories included, unless --no-recursion. Inputs are read
		// relative to the -C in force where they appear.
		name: "tar --remove-files", bases: []string{"tar"}, flag: "--remove-files",
		deletes: tarRemoves, recursive: tarRecursive, targets: tarInputs, listed: tarListed,
	},
	{
		// find walks the tree under each start path; -delete, or an exec
		// action running a delete, removes what the expression selects.
		name: "find -delete / -exec rm", bases: []string{"find"}, flag: "-delete",
		deletes: findDeletes, execs: findExecs, recursive: always, targets: findStartPaths,
		walk: true,
	},
}

// deleteRowsByBase indexes deleteTable by base, keeping row order.
var deleteRowsByBase = func() map[string][]int {
	out := map[string][]int{}
	for i, r := range deleteTable {
		for _, b := range r.bases {
			out[b] = append(out[b], i)
		}
	}
	return out
}()

// deleteBases are the bases of the deleteTable rows keep accepts (nil:
// every row). The unknown-prefix fallback re-judges from any of them
// (unknownprefix.go) and treats only the everyWord ones, whose words are
// all paths and never a command to run, as commands it knows.
func deleteBases(keep func(*deleteRow) bool) map[string]bool {
	out := map[string]bool{}
	for i := range deleteTable {
		if keep != nil && !keep(&deleteTable[i]) {
			continue
		}
		for _, b := range deleteTable[i].bases {
			out[b] = true
		}
	}
	return out
}

// deleteMatch is one row that applies to a unit, and the flag or action
// that made it apply (for reasons).
type deleteMatch struct {
	row *deleteRow
	via string
}

// deletion is what deleteTable says about one unit: the rows that apply.
// The zero value is "not a delete".
type deletion struct {
	cmd     *Command
	matches []deleteMatch
}

// deleteTarget is one operand a unit removes, and whether the row that
// removes it walks a tree from it (deleteRow.walk).
type deleteTarget struct {
	operand
	walk bool
}

// deletionOf walks deleteTable for cmd.
func deletionOf(cmd *Command) deletion {
	if cmd == nil {
		return deletion{}
	}
	d := deletion{cmd: cmd}
	for _, i := range deleteRowsByBase[cmd.Base] {
		r := &deleteTable[i]
		if r.deletes == nil && r.execs == nil {
			d.matches = append(d.matches, deleteMatch{row: r})
			continue
		}
		if r.deletes != nil && r.deletes(cmd) {
			d.matches = append(d.matches, deleteMatch{row: r, via: r.flag})
			continue
		}
		if r.execs == nil {
			continue
		}
		for _, line := range r.execs(cmd) {
			if via := execDeletes(cmd, line); via != "" {
				d.matches = append(d.matches, deleteMatch{row: r, via: via})
				break
			}
		}
	}
	return d
}

// execDeletes reports, as "<action> <base>", whether one command line an
// exec action runs (its first word is the action) is a delete this table
// names that removes more than empty directories; "" otherwise.
func execDeletes(cmd *Command, line []string) string {
	if len(line) < 2 {
		return ""
	}
	rest, _, _ := stripWrappers(line[1:], cmd.Dialect)
	if len(rest) == 0 {
		return ""
	}
	sub := &Command{Base: canonicalBase(rest[0], cmd.Dialect), Argv: rest, Dialect: cmd.Dialect}
	if d := deletionOf(sub); d.ok() && !d.emptyOnly() {
		return line[0] + " " + sub.Base
	}
	return ""
}

// ok reports whether the unit deletes anything.
func (d deletion) ok() bool { return len(d.matches) > 0 }

// emptyOnly reports whether every row that applies removes only empty
// directories.
func (d deletion) emptyOnly() bool {
	for _, m := range d.matches {
		if !m.row.emptyOnly {
			return false
		}
	}
	return d.ok()
}

// recursiveTargets returns the operands removed as whole trees, in row
// order: the ones R-101 and R-102 judge.
func (d deletion) recursiveTargets() []deleteTarget {
	var out []deleteTarget
	for _, m := range d.matches {
		if m.row.recursive == nil || !m.row.recursive(d.cmd) {
			continue
		}
		for _, op := range m.row.targets(d.cmd) {
			out = append(out, deleteTarget{operand: op, walk: m.row.walk})
		}
	}
	return out
}

// removes reports whether the unit destroys the word tok: any word of an
// everyWord command, else a word some row names as a target.
func (d deletion) removes(tok string) bool {
	return d.targetsWord(tok, func(*deleteRow) bool { return true })
}

// alsoWritten reports whether tok is a target the command fills as well as
// prunes (deleteRow.alsoWrites).
func (d deletion) alsoWritten(tok string) bool {
	return d.targetsWord(tok, func(r *deleteRow) bool { return r.alsoWrites })
}

// targetsWord reports whether a row that keep accepts names tok.
func (d deletion) targetsWord(tok string, keep func(*deleteRow) bool) bool {
	for _, m := range d.matches {
		if !keep(m.row) {
			continue
		}
		if m.row.everyWord {
			return true
		}
		for _, op := range m.row.targets(d.cmd) {
			if op.word(d.cmd) == tok {
				return true
			}
		}
	}
	return false
}

// lostTarget reports whether a recursive target is a word that was nothing
// but a command substitution (Command.lostArgs, NF-2). For an everyWord
// command any such word counts, an option's value included (`Remove-Item
// -Path:$(x) -Recurse`, `-Exclude $(x)`): the parse does not tell an
// operand from a value there, which can only ask more. For the others only
// a word the table names as a recursive target does (`rsync -a --delete
// $(ls) ./out/` copies from the computed word and deletes in ./out/).
func (d deletion) lostTarget() bool {
	if len(d.cmd.lostArgs) == 0 {
		return false
	}
	for _, m := range d.matches {
		if m.row.everyWord && m.row.recursive != nil && m.row.recursive(d.cmd) {
			return true
		}
	}
	for _, t := range d.recursiveTargets() {
		if t.arg > 0 && d.cmd.lostArg(t.arg) {
			return true
		}
	}
	return false
}

// massReason returns R-103's reason when the unit removes a set the guard
// cannot list (a tree walk, a file list, or names fed by xargs); ""
// otherwise.
func (d deletion) massReason() string {
	for _, m := range d.matches {
		switch {
		case m.row.walk:
			return strings.TrimSpace(d.cmd.Base+" "+m.via) + " mass deletion"
		case m.row.listed != nil && m.row.listed(d.cmd):
			return strings.TrimSpace(d.cmd.Base+" "+m.via) + " of the files a list names: mass deletion"
		}
	}
	if d.ok() && !d.emptyOnly() && hasWrapper(d.cmd, "xargs") {
		return d.cmd.Base + " fed by xargs"
	}
	return ""
}

// fromList reports whether some row removes inputs read from a file the
// guard cannot see (deleteRow.listed).
func (d deletion) fromList() bool {
	for _, m := range d.matches {
		if m.row.listed != nil && m.row.listed(d.cmd) {
			return true
		}
	}
	return false
}

// targets returns every operand some row removes, recursive or not.
func (d deletion) targets() []operand {
	var out []operand
	for _, m := range d.matches {
		out = append(out, m.row.targets(d.cmd)...)
	}
	return out
}

// --- row predicates and target selectors ---------------------------------

// always is a row predicate that holds for every invocation.
func always(*Command) bool { return true }

// inDialect and notDialect gate a row on the unit's shell dialect.
func inDialect(d Dialect) func(*Command) bool {
	return func(c *Command) bool { return c.Dialect == d }
}

func notDialect(d Dialect) func(*Command) bool {
	return func(c *Command) bool { return c.Dialect != d }
}

// cmdSlashS is cmd.exe's /S (rd /s, del /s).
func cmdSlashS(c *Command) bool { return cmdHasFlag(c, "s") }

// everyOperand selects every positional operand (Command.positionalOperands).
func everyOperand(c *Command) []operand { return c.positionalOperands() }

// hasGNULong reports a GNU long option in flag position, spelled in full or
// by a prefix of at least minLen bytes, bare or with "=VALUE". getopt_long
// takes any unambiguous prefix, so `rm --rec ~` is `rm --recursive ~`;
// minLen is the shortest prefix that names only this option.
func hasGNULong(c *Command, full string, minLen int) bool {
	for _, t := range c.flagTokens() {
		name, _, _ := strings.Cut(t, "=")
		if len(name) >= minLen && len(name) <= len(full) && strings.HasPrefix(full, name) {
			return true
		}
	}
	return false
}

// rmRecursive: -r, -R, or GNU --recursive (any prefix from "--r": rm has
// no other long option starting with r).
func rmRecursive(c *Command) bool {
	return c.HasShortFlag('r', 'R') || hasGNULong(c, "--recursive", len("--r"))
}

// shredRemoves: -u (in any cluster) or --remove[=HOW] (any prefix from
// "--re"; --random-source starts "--ra").
func shredRemoves(c *Command) bool {
	return c.HasShortFlag('u') || hasGNULong(c, "--remove", len("--re"))
}

// shredOpts is shred's option grammar: -n and -s take a value.
var shredOpts = optSpec{
	valued:  setOf("-n", "-s", "--iterations", "--size", "--random-source"),
	cluster: true,
}

// shredOperands are shred's file operands.
func shredOperands(c *Command) []operand {
	_, idx := walkOptionIndexes(c, shredOpts)
	return c.operandsAt(idx)
}

// rsyncOpts is rsync's option grammar: the options that take a value (a
// separate value would otherwise read as an operand and move the
// destination).
var rsyncOpts = optSpec{
	valued: setOf("-e", "-f", "-B", "-T", "-M", "-@",
		"--rsh", "--filter", "--exclude", "--include", "--exclude-from", "--include-from", "--files-from",
		"--block-size", "--max-delete", "--max-size", "--min-size", "--max-alloc", "--partial-dir", "--temp-dir",
		"--compare-dest", "--copy-dest", "--link-dest", "--backup-dir", "--suffix", "--chmod", "--chown",
		"--usermap", "--groupmap", "--timeout", "--contimeout", "--bwlimit", "--log-file", "--log-file-format",
		"--out-format", "--password-file", "--port", "--sockopts", "--rsync-path", "--iconv", "--checksum-choice",
		"--cc", "--compress-choice", "--zc", "--compress-level", "--zl", "--skip-compress", "--modify-window",
		"--outbuf", "--remote-option", "--write-batch", "--read-batch", "--only-write-batch", "--protocol",
		"--info", "--debug", "--stderr", "--address", "--early-input", "--checksum-seed", "--copy-as",
		"--stop-after", "--stop-at", "--time-limit"),
	cluster: true,
}

// rsyncDeletes: --del or any --delete* option.
func rsyncDeletes(c *Command) bool {
	for _, t := range c.flagTokens() {
		name, _, _ := strings.Cut(t, "=")
		if name == "--del" || strings.HasPrefix(name, "--delete") {
			return true
		}
	}
	return false
}

// rsyncRemovesSources: --remove-source-files or its old name.
func rsyncRemovesSources(c *Command) bool {
	return c.HasLongFlag("--remove-source-files", "--remove-sent-files")
}

// rsyncRecursive: -r, -a (archive implies -r), --recursive, --archive.
func rsyncRecursive(c *Command) bool {
	return c.HasShortFlag('r', 'a') || c.HasLongFlag("--recursive", "--archive")
}

// rsyncOperands are rsync's path operands, in order, and which of them are
// remote ([user@]host:path, host::module, rsync://...): what rsync removes
// there is not on this machine, so a remote operand counts for its
// position and is never a target. A drive-letter path (C:\x) is local.
func rsyncOperands(c *Command) (ops []operand, remote []bool) {
	_, idx := walkOptionIndexes(c, rsyncOpts)
	ops = c.operandsAt(idx)
	remote = make([]bool, len(ops))
	for k, op := range ops {
		remote[k] = rsyncRemote(op.text)
	}
	return ops, remote
}

// rsyncDestination is the last operand when there are at least two (one
// operand only lists it).
func rsyncDestination(c *Command) []operand {
	ops, remote := rsyncOperands(c)
	n := len(ops)
	if n < 2 || remote[n-1] {
		return nil
	}
	return ops[n-1:]
}

// rsyncSources are every local operand but the last, when there are at
// least two.
func rsyncSources(c *Command) []operand {
	ops, remote := rsyncOperands(c)
	var out []operand
	for k := 0; k+1 < len(ops); k++ {
		if !remote[k] {
			out = append(out, ops[k])
		}
	}
	return out
}

// rsyncRemote reports an rsync remote operand: rsync://..., or a colon
// before any path separator that is not a drive letter.
func rsyncRemote(op string) bool {
	if strings.HasPrefix(op, "rsync://") {
		return true
	}
	i := strings.IndexByte(op, ':')
	if i <= 0 {
		return false
	}
	if j := strings.IndexAny(op, `/\`); j >= 0 && j < i {
		return false
	}
	return i != 1 || !isASCIILetter(op[0])
}

// --- tar -----------------------------------------------------------------

// tarShortValued are GNU tar's short options that take an argument.
const tarShortValued = "bCfFgHIKLNTVX"

// tarLongValued are GNU tar's long options whose value may be the next
// word (exact spellings; the four that change what is removed are read by
// prefix in tarLong).
var tarLongValued = setOf("--file", "--exclude", "--exclude-from", "--format", "--owner", "--group",
	"--mode", "--mtime", "--transform", "--xform", "--use-compress-program", "--label", "--newer",
	"--newer-mtime", "--after-date", "--listed-incremental", "--tape-length", "--blocking-factor",
	"--record-size", "--suffix", "--to-command", "--index-file", "--volno-file", "--info-script",
	"--new-volume-script", "--rsh-command", "--rmt-command", "--level", "--strip-components",
	"--exclude-tag", "--exclude-tag-under", "--exclude-tag-all", "--starting-file", "--quoting-style",
	"--quote-chars", "--no-quote-chars", "--checkpoint-action", "--pax-option", "--sort", "--owner-map",
	"--group-map", "--hole-detection", "--exclude-ignore", "--exclude-ignore-recursive")

// tarLongRows are the tar long options that change what --remove-files
// removes, with the shortest prefix getopt_long reads as them alone, and
// the short letter they act as ('A' for --add-file, which names one input).
var tarLongRows = []struct {
	full   string
	minLen int
	letter byte
}{
	{"--directory", len("--dir"), 'C'}, // --diff starts "--di"
	{"--files-from", len("--files"), 'T'},
	{"--add-file", len("--ad"), 'A'},
}

// tarRemoves: --remove-files (any prefix from "--rem") outside extract mode
// (where the operands are member names, and the option does nothing).
func tarRemoves(c *Command) bool {
	return hasGNULong(c, "--remove-files", len("--rem")) && !tarExtracts(c)
}

// tarRecursive: tar recurses into directories unless --no-recursion.
func tarRecursive(c *Command) bool {
	return !hasGNULong(c, "--no-recursion", len("--no-rec"))
}

// tarInputs are the inputs tar archives (and, under --remove-files,
// removes).
func tarInputs(c *Command) []operand {
	ins, _ := tarScan(c)
	return ins
}

// tarListed reports an input list read from a file (-T, --files-from),
// whose names the guard cannot see.
func tarListed(c *Command) bool {
	_, listed := tarScan(c)
	return listed
}

// tarScan reads tar's argv: the input operands and --add-file values, each
// read relative to the -C / --directory in force where it appears (a
// relative -C is relative to the one before it), and whether an input list
// comes from a file. It understands the old dashless mode word (`tar cf
// x.tar dir`: each value-taking letter takes the next word), getopt
// clusters (`-cf x.tar`, `-Cdir`) and "--".
func tarScan(c *Command) (ins []operand, listed bool) {
	var dir operand
	apply := func(letter byte, v operand) {
		switch letter {
		case 'C':
			if dir.text != "" && !tarAbsolute(v.text) {
				v = joinOperand(dir, v)
			}
			dir = v
		case 'T':
			listed = true
		case 'A':
			ins = append(ins, tarInput(dir, v)...)
		}
	}
	argv := c.Argv
	i := 1
	if len(argv) > 1 && tarOldMode(argv[1]) {
		j := 2
		for k := 0; k < len(argv[1]); k++ {
			if strings.IndexByte(tarShortValued, argv[1][k]) >= 0 && j < len(argv) {
				apply(argv[1][k], c.operandAt(j, argv[j], 0))
				j++
			}
		}
		i = j
	}
	rest := false
	for ; i < len(argv); i++ {
		t := argv[i]
		switch {
		case rest || !c.isFlagToken(t):
			ins = append(ins, tarInput(dir, c.operandAt(i, t, 0))...)
		case t == "--":
			rest = true
		case strings.HasPrefix(t, "--"):
			name, val, eq := strings.Cut(t, "=")
			letter, known := tarLongLetter(name)
			if !known && !tarLongValued[name] {
				continue
			}
			var v operand
			switch {
			case eq:
				v = c.operandAt(i, val, len(name)+1)
			case i+1 < len(argv):
				i++
				v = c.operandAt(i, argv[i], 0)
			default:
				continue
			}
			apply(letter, v)
		default:
			i = tarCluster(c, i, apply)
		}
	}
	return ins, listed
}

// tarCluster reads one short-option cluster at argv[i] (`-czf x.tar`,
// `-Cdir`): the first value-taking letter takes the rest of the word or,
// when nothing follows it, the next word. It returns the index of the last
// word it consumed.
func tarCluster(c *Command, i int, apply func(byte, operand)) int {
	t := c.Argv[i]
	for k := 1; k < len(t); k++ {
		if strings.IndexByte(tarShortValued, t[k]) < 0 {
			continue
		}
		if k+1 < len(t) {
			apply(t[k], c.operandAt(i, t[k+1:], k+1))
		} else if i+1 < len(c.Argv) {
			i++
			apply(t[k], c.operandAt(i, c.Argv[i], 0))
		}
		return i
	}
	return i
}

// tarLongLetter maps a long option to the letter it acts as (tarLongRows).
func tarLongLetter(name string) (byte, bool) {
	for _, r := range tarLongRows {
		if len(name) >= r.minLen && len(name) <= len(r.full) && strings.HasPrefix(r.full, name) {
			return r.letter, true
		}
	}
	return 0, false
}

// tarOldMode reports tar's old dashless mode word (`tar cf ...`): a first
// argument of letters only.
func tarOldMode(w string) bool {
	if w == "" {
		return false
	}
	for k := 0; k < len(w); k++ {
		if !isASCIILetter(w[k]) {
			return false
		}
	}
	return true
}

// tarInput places one input under the -C in force. An input that may be
// absolute once the shell expands it (`$X/y`) is judged both as written and
// under the directory.
func tarInput(dir, v operand) []operand {
	switch {
	case dir.text == "" || tarAbsolute(v.text):
		return []operand{v}
	case strings.HasPrefix(v.text, "$") || strings.HasPrefix(v.text, "%"):
		return []operand{v, joinOperand(dir, v)}
	}
	return []operand{joinOperand(dir, v)}
}

// tarAbsolute reports an input tar does not read under -C: an absolute
// path, or one the shell expands from the home directory.
func tarAbsolute(p string) bool {
	return isAbsPath(p) || strings.HasPrefix(p, "~")
}

// joinOperand joins a directory operand and a relative one into the path
// the command acts on, keeping both words' literal offsets and the
// relative word's argv index (the word the operand stands for).
func joinOperand(dir, v operand) operand {
	sep := "/"
	if strings.HasSuffix(dir.text, "/") || strings.HasSuffix(dir.text, `\`) {
		sep = ""
	} else if strings.Contains(dir.text, `\`) && !strings.Contains(dir.text, "/") {
		sep = `\`
	}
	out := operand{text: dir.text + sep + v.text, arg: v.arg}
	out.lit = append(out.lit, dir.lit...)
	for _, o := range v.lit {
		out.lit = append(out.lit, o+len(dir.text)+len(sep))
	}
	return out
}

// --- find ----------------------------------------------------------------

// findExecActions are find's actions that run a command per file.
var findExecActions = setOf("-exec", "-execdir", "-ok", "-okdir")

// findDeletes: the -delete action.
func findDeletes(c *Command) bool {
	for _, a := range c.Args() {
		if a == "-delete" {
			return true
		}
	}
	return false
}

// findExecs returns each exec action's command line, the action word first
// and the ";" or "+" terminator dropped.
func findExecs(c *Command) [][]string {
	var out [][]string
	for i := 1; i < len(c.Argv); i++ {
		if !findExecActions[c.Argv[i]] {
			continue
		}
		j := i + 1
		for j < len(c.Argv) && c.Argv[j] != ";" && c.Argv[j] != "+" {
			j++
		}
		out = append(out, c.Argv[i:j])
		i = j
	}
	return out
}

// findStartPaths are find's starting points: the words after its leading
// options (-H, -L, -P, -D LIST, -Olevel) and before the first expression
// word. With none, GNU find starts at ".".
func findStartPaths(c *Command) []operand {
	i := 1
	for i < len(c.Argv) {
		t := c.Argv[i]
		if t == "-H" || t == "-L" || t == "-P" || t == "--" || (strings.HasPrefix(t, "-O") && len(t) > 2) {
			i++
			continue
		}
		if t == "-D" {
			i += 2
			continue
		}
		break
	}
	var out []operand
	for ; i < len(c.Argv); i++ {
		t := c.Argv[i]
		if (len(t) > 1 && t[0] == '-') || t == "(" || t == ")" || t == "!" || t == "," {
			break
		}
		out = append(out, c.operandAt(i, t, 0))
	}
	if len(out) == 0 {
		out = append(out, operand{text: "."})
	}
	return out
}
