package policy

import (
	"strings"
	"sync"
)

// cwdtrack.go: which working directories, and which links created
// earlier in the same command line, a command unit can run with (pass-2
// review M2-01).
//
// THE BYPASS. The delete rules used to anchor every relative operand on
// the event's own working directory. One command line can move first:
//
//	cd ~ && rm -rf ./*            judged as <project>/*, deletes ~/*
//	pushd ~; rm -rf *             the same through the directory stack
//	(cd ~ && rm -rf .)            the same inside a subshell
//	Set-Location ~; Remove-Item -Recurse -Force *
//	ln -s ~ o && rm -rf o/*       the link does not exist yet when the
//	                              guard runs, so ResolveLinks cannot see it
//
// THE MODEL. The parser records each unit of a line as one step (a
// directory change, a link creation, or anything else) together with the
// list operator in front of it (`;`, `&&`, `||`, `|`) and the subshell
// parentheses around it. Matching then replays the steps over a small set
// of FRAMES: each frame is one way the line can have run so far (working
// directory, previous directory, directory stack, links created, and the
// last exit status). A directory change splits a frame into "it worked"
// and "it failed"; `&&` and `||` drop the frames in which the next unit
// cannot run; a POSIX subshell restores the directory on `)`. A unit is
// then judged in EVERY frame it can run in, so the result over-approximates
// what the shell can do and never under-approximates it: a frame the
// shell could not reach can only add a hit, never hide one.
//
// FAIL CLOSED. A directory change the model cannot resolve (a variable,
// a stripped command substitution, `cd -` with an inherited OLDPWD,
// `popd` past the stack this line built, a frame overflow) leaves a frame
// whose directory is UNKNOWN, and a relative recursive delete in it is
// catastrophic. An evaluated payload (eval, Invoke-Expression) that
// changes directories or creates links makes every later recursive delete
// in that frame catastrophic, because the effect is in-process and not
// modelled.
//
// Residuals (documented, not modelled): CDPATH, a directory change made
// by a script file or an interpreter program, a launcher's own working
// directory parameter (Start-Process -WorkingDirectory, wsl --cd), and
// link creation by interpreter programs.
//
// Pure: no I/O. Existing symlinks are still resolved by the injected
// Config.ResolveLinks on the final path, as before.

// seqSep is the list operator in front of a unit.
type seqSep uint8

// seqSep values.
const (
	sepSeq  seqSep = iota // start of line, `;`, newline, `&`
	sepAnd                // `&&`
	sepOr                 // `||`
	sepPipe               // `|`
)

// listSep maps a lexer list operator to its seqSep.
func listSep(op string) seqSep {
	switch op {
	case "&&":
		return sepAnd
	case "||":
		return sepOr
	default:
		return sepSeq
	}
}

// stepKind classifies what a unit does to the frame state.
type stepKind uint8

// stepKind values.
const (
	stepOther      stepKind = iota // anything else: only the exit status changes
	stepCd                         // change to arg
	stepCdHome                     // change to the home directory
	stepCdBack                     // change to the previous directory (`cd -`)
	stepPushd                      // push the current directory, change to arg
	stepPushdKeep                  // push arg without changing (`pushd -n`, Push-Location alone)
	stepPushdSwap                  // `pushd` with no operand: swap with the stack top
	stepPopd                       // change to the stack top and pop it
	stepDirUnknown                 // a directory change whose destination cannot be known
	stepLink                       // creates links (ln -s, mklink, New-Item -ItemType SymbolicLink, mount --bind)
	stepCopyLink                   // mv / cp / Move-Item / Copy-Item / Rename-Item: may move a same-command link
	stepOpaque                     // eval-style payload that changes directories or creates links
)

// Bounds. Every overflow fails closed (an opaque frame).
const (
	maxFrames      = 64
	maxSameCmdLink = 32
	maxSubshell    = 16
	maxLinkHops    = 8
)

// linkSpec is one link a link-creating unit makes, before resolution.
type linkSpec struct {
	// at is where the link is created; !hasAt means "in the working
	// directory, named after the target" (`ln -s TARGET`).
	at    operand
	hasAt bool
	// intoDir: the link is created INSIDE at, named after the target.
	// maybeDir: at may be an existing directory, so both readings count.
	intoDir, maybeDir bool
	target            operand
	// targetFromCwd: a relative target is resolved against the working
	// directory (ln -r, junctions, bind mounts) rather than the link's
	// own directory (a plain symlink).
	targetFromCwd bool
	// unknown: the target cannot be resolved statically.
	unknown bool
}

// copySpec is a move/copy/rename that carries a same-command link along.
type copySpec struct {
	srcs []operand
	dst  operand
	// intoDir / maybeDir as in linkSpec; sibling: dst is a new NAME in
	// the source's directory (Rename-Item).
	intoDir, maybeDir, sibling bool
}

// seqStep is one unit of a line as the frame model sees it.
type seqStep struct {
	kind          stepKind
	sep           seqSep
	opens, closes int
	dialect       Dialect
	// arg is the directory operand of a directory change; argUnknown
	// marks one that cannot be resolved (a stripped substitution).
	arg        operand
	argUnknown bool
	links      []linkSpec
	copy       *copySpec
	// raw is the unit's text, quoted in a reason that names the step.
	raw string
	// assigns are the NAME=value words of a unit that is nothing but
	// assignments (`http_proxy=x;`). Such a unit yields no Command, so
	// this is the only record that it ran: it sets shell variables, and
	// an already-exported one changes the environment every later command
	// inherits (R-171's exemption reads it, FR-SEC-3).
	assigns []string
}

// unitSeq is the step sequence of one parsed line (one parseDepth call).
// Commands point into it (Command.seq/seqPos). A nested payload's
// sequence starts from the frames of its wrapper's position in the
// parent; parentPos -1 means anywhere in the parent (a substitution).
type unitSeq struct {
	parent    *unitSeq
	parentPos int
	dialect   Dialect
	steps     []seqStep
	// active is true once a step that can move the working directory or
	// create a link is recorded; a chain with no active sequence keeps
	// the event's own directory and the legacy code path.
	active bool

	mu       sync.Mutex
	cached   bool
	cacheEnv cwdEnv
	// before[i] holds the frames reaching step i (parentheses applied,
	// list operator not yet), before[len(steps)] the frames after the
	// last step.
	before [][]cwdFrame
}

// cwdEnv is what frame replay needs from the evaluation.
type cwdEnv struct {
	home string // Config.Home
	base string // Event.Cwd, else Event.ProjectRoot
}

// runStatus is a frame's last exit status.
type runStatus uint8

// runStatus values.
const (
	statusOK runStatus = iota
	statusFail
	statusUnknown
)

// dirRef is one directory: a normalized path, "" for "no anchor" (an
// event with neither cwd nor project root, judged literally as before),
// or unknown.
type dirRef struct {
	path    string
	unknown bool
	// why is the step that left an unknown directory ("" otherwise); it
	// feeds the reason text only and is not part of a frame's identity.
	why string
}

// sameCmdLink is a link created earlier in the line, resolved.
type sameCmdLink struct {
	path    string
	target  string
	unknown bool
	// via is the unit that created the link (reason text only).
	via string
}

// dirState is the part of a frame a POSIX subshell saves and restores.
type dirState struct {
	cwd       dirRef
	prev      dirRef
	prevKnown bool // false: OLDPWD comes from the environment (unknown)
	stack     []dirRef
	// stackClosed: the stack holds only what this line pushed. False
	// means entries beyond it come from the shell and are unknown.
	stackClosed bool
	// failPath: this state is reachable only because an earlier directory
	// change FAILED and the line carried on (a `;` after `cd build`).
	// failVia is that step (reason text only).
	failPath bool
	failVia  string
}

// cwdFrame is one way the line can have run so far.
type cwdFrame struct {
	dirState
	subs   []dirState
	links  []sameCmdLink
	opaque bool
	// opaqueVia is the step that made the frame opaque (reason text only).
	opaqueVia string
	status    runStatus
}

// add records the step for a unit: cmds holds the unit's own Command
// first and then every Command nested inside it (empty when the unit
// produced none, e.g. a bare assignment).
func (s *unitSeq) add(u unit, cmds []Command) {
	st := seqStep{kind: stepOther, sep: u.sep, opens: u.opens, closes: u.closes, dialect: s.dialect}
	if len(cmds) == 0 {
		for _, w := range u.words {
			if isEnvAssign(w) {
				st.assigns = append(st.assigns, w)
			}
		}
	}
	if len(cmds) > 0 {
		st.dialect = cmds[0].Dialect
		st.raw = cmds[0].Raw
		classifyStep(&st, &cmds[0])
		// An evaluator's payload, and a PowerShell script block
		// (psblock.go), run in the caller's shell: a directory change or
		// link inside them persists but is not modelled.
		if st.kind == stepOther && (evalBases[cmds[0].Base] || cmds[0].scriptBlock) {
			for i := 1; i < len(cmds); i++ {
				var nst seqStep
				classifyStep(&nst, &cmds[i])
				if nst.kind != stepOther && nst.kind != stepCopyLink {
					st.kind = stepOpaque
					break
				}
			}
		}
	}
	if u.hadSub {
		// A stripped substitution can leave a directory change with NO
		// operand (`cd $(mktemp -d)` lexes as a bare `cd`), which would
		// read as "go home" or a stack swap. Its destination is simply
		// unknown, whatever shape the stripped words take.
		if movesDir[st.kind] && st.kind != stepOpaque {
			st.kind = stepDirUnknown
		}
		// Raw lost the substitution; show that one was there.
		st.raw = strings.TrimSpace(st.raw) + " $(...)"
		st.argUnknown = true
		for i := range st.links {
			st.links[i].unknown = true
		}
	}
	if st.kind != stepOther && st.kind != stepCopyLink {
		s.active = true
	}
	s.steps = append(s.steps, st)
}

// evalBases are the in-process evaluators: a directory change inside
// their payload persists in the caller's shell.
var evalBases = map[string]bool{"eval": true, "invoke-expression": true, "iex": true}

// chainActive reports whether this sequence or any enclosing one moves a
// working directory or creates a link.
func (s *unitSeq) chainActive() bool {
	for q := s; q != nil; q = q.parent {
		if q.active {
			return true
		}
	}
	return false
}

// framesAt returns the frames in which the unit at pos can run; pos -1
// (or out of range) means anywhere in the line.
func (s *unitSeq) framesAt(env cwdEnv, pos int) []cwdFrame {
	b := s.simulate(env)
	if pos < 0 || pos >= len(s.steps) {
		var all []cwdFrame
		for _, fs := range b {
			all = append(all, fs...)
		}
		return dedupFrames(all)
	}
	var out []cwdFrame
	for _, f := range b[pos] {
		if runsAfter(f.status, s.steps[pos].sep) != runNever {
			out = append(out, f)
		}
	}
	return out
}

// simulate replays the steps once per evaluation environment.
func (s *unitSeq) simulate(env cwdEnv) [][]cwdFrame {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cached && s.cacheEnv == env {
		return s.before
	}
	cur := s.initial(env)
	b := make([][]cwdFrame, len(s.steps)+1)
	for i := range s.steps {
		st := &s.steps[i]
		cur = applyParens(cur, st, s.dialect)
		b[i] = cur
		cur = advance(env, cur, st)
	}
	b[len(s.steps)] = cur
	s.before, s.cacheEnv, s.cached = b, env, true
	return b
}

// initial is the frame set the sequence starts from.
func (s *unitSeq) initial(env cwdEnv) []cwdFrame {
	if s.parent == nil {
		return []cwdFrame{{dirState: dirState{cwd: dirRef{path: env.base}}}}
	}
	var out []cwdFrame
	for _, f := range s.parent.framesAt(env, s.parentPos) {
		// A nested shell keeps the directory, OLDPWD and links; its
		// directory stack and exit status start fresh.
		out = append(out, cwdFrame{
			dirState: dirState{
				cwd: f.cwd, prev: f.prev, prevKnown: f.prevKnown,
				failPath: f.failPath, failVia: f.failVia,
			},
			links:     f.links,
			opaque:    f.opaque,
			opaqueVia: f.opaqueVia,
		})
	}
	return dedupFrames(out)
}

// runMode is whether a unit runs in a frame.
type runMode uint8

// runMode values.
const (
	runAlways runMode = iota
	runNever
	runMaybe
)

// runsAfter decides from the frame's last status and the list operator.
func runsAfter(status runStatus, sep seqSep) runMode {
	switch sep {
	case sepAnd:
		switch status {
		case statusOK:
			return runAlways
		case statusFail:
			return runNever
		}
		return runMaybe
	case sepOr:
		switch status {
		case statusFail:
			return runAlways
		case statusOK:
			return runNever
		}
		return runMaybe
	default:
		return runAlways
	}
}

// applyParens closes then opens POSIX subshells. Other dialects run a
// parenthesised group in the same process, so a location change inside
// it persists and the parens change nothing.
func applyParens(fs []cwdFrame, st *seqStep, d Dialect) []cwdFrame {
	if (st.opens == 0 && st.closes == 0) || (d != DialectPosix && d != "") {
		return fs
	}
	out := make([]cwdFrame, 0, len(fs))
	for _, f := range fs {
		for k := 0; k < st.closes && len(f.subs) > 0; k++ {
			n := len(f.subs) - 1
			f.dirState = f.subs[n]
			f.subs = f.subs[:n:n]
		}
		for k := 0; k < st.opens; k++ {
			if len(f.subs) >= maxSubshell {
				f.opaque = true
				if f.opaqueVia == "" {
					f.opaqueVia = "subshells nested too deeply"
				}
				break
			}
			f.subs = appendDirState(f.subs, f.dirState)
		}
		out = append(out, f)
	}
	return dedupFrames(out)
}

// advance runs one step in every frame.
func advance(env cwdEnv, fs []cwdFrame, st *seqStep) []cwdFrame {
	var out []cwdFrame
	for _, f := range fs {
		switch runsAfter(f.status, st.sep) {
		case runNever:
			out = append(out, f)
		case runAlways:
			out = append(out, execStep(env, f, st)...)
		default:
			skip := f
			if st.sep == sepAnd {
				skip.status = statusFail
			} else {
				skip.status = statusOK
			}
			out = append(out, skip)
			out = append(out, execStep(env, f, st)...)
		}
	}
	return capFrames(dedupFrames(out))
}

// execStep runs one step in one frame and returns the frames it can
// leave behind (success first, then failure).
func execStep(env cwdEnv, f cwdFrame, st *seqStep) []cwdFrame {
	ok, fail := f, f
	ok.status, fail.status = statusOK, statusFail
	if movesDir[st.kind] && !fail.failPath {
		fail.failPath, fail.failVia = true, st.raw
	}
	moveTo := func(d dirRef) {
		ok.prev, ok.prevKnown = f.cwd, true
		if d.unknown && d.why == "" {
			d.why = st.raw
		}
		ok.cwd = d
	}
	switch st.kind {
	case stepCd:
		moveTo(stepDir(env, f.cwd, st))
	case stepCdHome:
		moveTo(resolveFrom(env, f.cwd, "~"))
	case stepCdBack:
		if f.prevKnown {
			moveTo(f.prev)
		} else {
			moveTo(dirRef{unknown: true, why: "`" + excerpt(st.raw) + "` (the previous directory comes from before this command)"})
		}
	case stepPushd:
		ok.stack = prependDir(f.stack, f.cwd)
		moveTo(stepDir(env, f.cwd, st))
	case stepPushdKeep:
		ok.stack = prependDir(f.stack, stepDir(env, f.cwd, st))
	case stepPushdSwap, stepPopd:
		switch {
		case len(f.stack) > 0:
			top := f.stack[0]
			if st.kind == stepPopd {
				ok.stack = append([]dirRef(nil), f.stack[1:]...)
			} else {
				ok.stack = append([]dirRef{f.cwd}, f.stack[1:]...)
			}
			moveTo(top)
		case f.stackClosed:
			return []cwdFrame{fail}
		default:
			moveTo(dirRef{unknown: true, why: "`" + excerpt(st.raw) + "` (past the directory stack this command built)"})
		}
	case stepDirUnknown:
		moveTo(dirRef{unknown: true})
	case stepOpaque:
		moveTo(dirRef{unknown: true})
		ok.opaque, ok.opaqueVia = true, st.raw
	case stepLink:
		ok.links, ok.opaque = addLinks(env, f, st.links, st.raw)
		if ok.opaque && ok.opaqueVia == "" {
			ok.opaqueVia = st.raw
		}
	case stepCopyLink:
		added := copiedLinks(env, f, st.copy)
		if len(added) == 0 {
			f.status = statusUnknown
			return []cwdFrame{f}
		}
		ok.links = appendLinks(f.links, added)
		if len(ok.links) > maxSameCmdLink {
			ok.opaque = true
			if ok.opaqueVia == "" {
				ok.opaqueVia = st.raw
			}
		}
	default: // stepOther
		f.status = statusUnknown
		return []cwdFrame{f}
	}
	return []cwdFrame{ok, fail}
}

// movesDir lists the step kinds that change the working directory, so
// their failure leaves the line on a failure branch (dirState.failPath).
var movesDir = map[stepKind]bool{
	stepCd: true, stepCdHome: true, stepCdBack: true, stepPushd: true,
	stepPushdSwap: true, stepPopd: true, stepDirUnknown: true, stepOpaque: true,
}

// stepDir resolves a directory change's operand from the frame's cwd.
func stepDir(env cwdEnv, from dirRef, st *seqStep) dirRef {
	if st.argUnknown {
		return dirRef{unknown: true}
	}
	return resolveDirOperand(env, from, st.arg, st.dialect)
}

// resolveDirOperand resolves a directory operand: unknown when it holds
// an expansion the package cannot perform, or is a bare drive spelling
// (`C:`, which names that drive's own current directory, not its root).
func resolveDirOperand(env cwdEnv, from dirRef, op operand, d Dialect) dirRef {
	if len(shellExpansions(op.text, op.lit, d)) > 0 || isBareDrive(op.text) {
		return dirRef{unknown: true}
	}
	return resolveFrom(env, from, op.text)
}

// isBareDrive reports a drive letter with no path ("C:").
func isBareDrive(s string) bool {
	return len(s) == 2 && s[1] == ':' && isASCIILetter(s[0])
}

// resolveFrom resolves text against a directory the way resolvePath
// does, keeping "no anchor" and unknown distinct.
func resolveFrom(env cwdEnv, from dirRef, text string) dirRef {
	p := expandHome(text, env.home)
	if isAbsPath(p) || strings.HasPrefix(p, "~") {
		return dirRef{path: normPath(p)}
	}
	if from.unknown {
		return dirRef{unknown: true}
	}
	if from.path == "" {
		return dirRef{}
	}
	return dirRef{path: normPath(strings.TrimRight(from.path, `/\`) + "/" + p)}
}

// placeFrom is resolveFrom for a link location: a relative location in
// an anchorless frame keeps its literal form, which is also how an
// anchorless delete operand is judged. ok is false when it is unknown.
func placeFrom(env cwdEnv, from dirRef, text string) (string, bool) {
	d := resolveFrom(env, from, text)
	switch {
	case d.unknown:
		return "", false
	case d.path == "":
		return normPath(expandHome(text, env.home)), true
	}
	return d.path, true
}

// parentDir returns the directory part of a normalized path.
func parentDir(p string) string {
	i := strings.LastIndexByte(p, '/')
	switch {
	case i < 0:
		return ""
	case i == 0:
		return "/"
	case i == 2 && p[1] == ':':
		return p[:3]
	}
	return p[:i]
}

// joinPath joins a normalized directory and a relative tail.
func joinPath(dir, tail string) string {
	if dir == "" {
		return normPath(tail)
	}
	return normPath(strings.TrimRight(dir, "/") + "/" + tail)
}

// addLinks resolves a link step's specs in a frame. The second result
// is true when a link could not be placed or the per-frame bound is
// exceeded (fail closed).
func addLinks(env cwdEnv, f cwdFrame, specs []linkSpec, via string) ([]sameCmdLink, bool) {
	var added []sameCmdLink
	opaque := f.opaque
	for _, sp := range specs {
		tgtText := expandHome(sp.target.text, env.home)
		var places []string
		if !sp.hasAt {
			p, ok := placeFrom(env, f.cwd, baseName(normPath(tgtText)))
			if !ok {
				opaque = true
				continue
			}
			places = append(places, p)
		} else {
			at, ok := placeFrom(env, f.cwd, sp.at.text)
			if !ok || len(shellExpansions(sp.at.text, sp.at.lit, DialectPosix)) > 0 {
				opaque = true
				continue
			}
			inner := joinPath(at, baseName(normPath(tgtText)))
			switch {
			case sp.intoDir:
				places = append(places, inner)
			case sp.maybeDir:
				places = append(places, at, inner)
			default:
				places = append(places, at)
			}
		}
		unknown := sp.unknown || len(shellExpansions(sp.target.text, sp.target.lit, DialectPosix)) > 0
		for _, p := range places {
			l := sameCmdLink{path: p, unknown: unknown, via: via}
			if !unknown {
				switch {
				case isAbsPath(tgtText) || strings.HasPrefix(tgtText, "~"):
					l.target = normPath(tgtText)
				case sp.targetFromCwd:
					t, ok := placeFrom(env, f.cwd, tgtText)
					l.target, l.unknown = t, !ok
				default:
					l.target = joinPath(parentDir(p), tgtText)
				}
			}
			added = append(added, l)
		}
	}
	links := appendLinks(f.links, added)
	if len(links) > maxSameCmdLink {
		opaque = true
	}
	return links, opaque
}

// copiedLinks returns the links a move/copy/rename carries: a source
// that IS a same-command link makes its destination one too.
func copiedLinks(env cwdEnv, f cwdFrame, cp *copySpec) []sameCmdLink {
	if cp == nil || len(f.links) == 0 {
		return nil
	}
	var out []sameCmdLink
	for _, src := range cp.srcs {
		sp, ok := placeFrom(env, f.cwd, src.text)
		if !ok {
			continue
		}
		var hit *sameCmdLink
		for i := len(f.links) - 1; i >= 0; i-- {
			if pathsEqual(f.links[i].path, sp) {
				hit = &f.links[i]
				break
			}
		}
		if hit == nil {
			continue
		}
		var dsts []string
		if cp.sibling {
			dsts = append(dsts, joinPath(parentDir(sp), cp.dst.text))
		} else if dp, ok := placeFrom(env, f.cwd, cp.dst.text); ok {
			inner := joinPath(dp, baseName(sp))
			switch {
			case cp.intoDir:
				dsts = append(dsts, inner)
			case cp.maybeDir:
				dsts = append(dsts, dp, inner)
			default:
				dsts = append(dsts, dp)
			}
		}
		for _, d := range dsts {
			out = append(out, sameCmdLink{path: d, target: hit.target, unknown: hit.unknown, via: hit.via})
		}
	}
	return out
}

// throughSameCmdLinks maps p through the frame's same-command links,
// following chains up to maxLinkHops. through is false when p is under
// none of them; unknown is true when it is under one whose target is
// unknown (or the chain does not end).
func throughSameCmdLinks(p string, links []sameCmdLink) (sub string, unknown, through bool) {
	if p == "" || len(links) == 0 {
		return p, false, false
	}
	cur := normPath(p)
	for hop := 0; hop < maxLinkHops; hop++ {
		matched := false
		for i := len(links) - 1; i >= 0; i-- {
			l := links[i]
			if !isUnder(cur, l.path) {
				continue
			}
			if l.unknown {
				return "", true, true
			}
			lp := normPath(l.path)
			rest := ""
			if len(cur) > len(lp) {
				rest = strings.TrimPrefix(cur[len(lp):], "/")
			}
			if rest == "" {
				cur = normPath(l.target)
			} else {
				cur = joinPath(l.target, rest)
			}
			matched, through = true, true
			break
		}
		if !matched {
			return cur, false, through
		}
	}
	return "", true, true
}

// unknownLinkVia returns the creating step of the latest unresolved link
// p lies under ("" when none).
func unknownLinkVia(p string, links []sameCmdLink) string {
	for i := len(links) - 1; i >= 0; i-- {
		if links[i].unknown && isUnder(p, links[i].path) {
			return links[i].via
		}
	}
	return ""
}

// --- frame set helpers -------------------------------------------------

func appendDirState(s []dirState, d dirState) []dirState {
	out := make([]dirState, len(s), len(s)+1)
	copy(out, s)
	return append(out, d)
}

func prependDir(s []dirRef, d dirRef) []dirRef {
	out := make([]dirRef, 0, len(s)+1)
	out = append(out, d)
	return append(out, s...)
}

func appendLinks(s, add []sameCmdLink) []sameCmdLink {
	if len(add) == 0 {
		return s
	}
	out := make([]sameCmdLink, 0, len(s)+len(add))
	out = append(out, s...)
	return append(out, add...)
}

// dedupFrames drops frames identical in every field.
func dedupFrames(fs []cwdFrame) []cwdFrame {
	if len(fs) < 2 {
		return fs
	}
	seen := make(map[string]bool, len(fs))
	out := fs[:0:0]
	for _, f := range fs {
		k := frameKey(f)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, f)
	}
	return out
}

// capFrames bounds the frame set. The frames past the bound collapse
// into one opaque frame with an unknown directory: fail closed.
func capFrames(fs []cwdFrame) []cwdFrame {
	if len(fs) <= maxFrames {
		return fs
	}
	out := append([]cwdFrame(nil), fs[:maxFrames-1]...)
	const why = "too many possible directories in this command"
	return append(out, cwdFrame{
		dirState: dirState{cwd: dirRef{unknown: true, why: why}},
		opaque:   true, opaqueVia: why, status: statusUnknown,
	})
}

func frameKey(f cwdFrame) string {
	var b strings.Builder
	b.WriteByte(byte('0' + f.status))
	if f.opaque {
		b.WriteByte('o')
	}
	writeDirState(&b, f.dirState)
	for _, s := range f.subs {
		b.WriteString("\x01(")
		writeDirState(&b, s)
	}
	for _, l := range f.links {
		b.WriteString("\x01L")
		b.WriteString(l.path)
		b.WriteString("\x02")
		b.WriteString(l.target)
		if l.unknown {
			b.WriteByte('?')
		}
	}
	return b.String()
}

func writeDirState(b *strings.Builder, d dirState) {
	writeDir(b, d.cwd)
	if d.prevKnown {
		b.WriteString("\x01p")
		writeDir(b, d.prev)
	}
	if d.stackClosed {
		b.WriteString("\x01c")
	}
	if d.failPath {
		b.WriteString("\x01f")
	}
	for _, s := range d.stack {
		b.WriteString("\x01s")
		writeDir(b, s)
	}
}

func writeDir(b *strings.Builder, d dirRef) {
	if d.unknown {
		b.WriteString("\x03?")
		return
	}
	b.WriteString("\x03")
	b.WriteString(d.path)
}

// --- anchors: what the delete rules consume ------------------------------

// deleteAnchor is one place a unit's relative operands can point.
type deleteAnchor struct {
	cwd     string
	unknown bool
	links   []sameCmdLink
	opaque  bool
	// plain: the event's own directory with nothing created earlier in
	// the line. A unit whose only anchor is plain is judged exactly as
	// before this model existed.
	plain bool
	// unknownVia / opaqueVia name the step behind unknown / opaque.
	unknownVia, opaqueVia string
	// failPath: EVERY frame behind this anchor is a failure branch of an
	// earlier directory change (failVia names one such step).
	failPath bool
	failVia  string
}

// deriveUnitAnchors returns the distinct anchors a unit can run with; a
// unit in a line with no directory change, link creation or chdir wrapper
// gets the single plain anchor. Rules call unitAnchors (evalmemo.go), the
// ONE entry, which derives this once per unit of an evaluation.
func deriveUnitAnchors(ctx *MatchContext, cmd *Command) []deleteAnchor {
	ev := ctx.Event
	base := ev.Cwd
	if base == "" {
		base = ev.ProjectRoot
	}
	plain := []deleteAnchor{{cwd: base, plain: true}}
	if cmd == nil {
		return plain
	}
	active := cmd.seq != nil && cmd.seq.chainActive()
	if !active && len(cmd.chdir) == 0 {
		return plain
	}
	env := cwdEnv{home: ctx.Cfg.Home, base: base}
	frames := []cwdFrame{{dirState: dirState{cwd: dirRef{path: base}}}}
	if active {
		frames = cmd.seq.framesAt(env, cmd.seqPos)
	}
	seen := make(map[string]int, len(frames))
	var out []deleteAnchor
	for _, f := range frames {
		cwd := f.cwd
		for _, op := range cmd.chdir {
			if op.text == "" {
				// An empty wrapper directory (`env -C $(x)`, `sudo -D
				// "$(x)"`: NF-2 keeps a word that was nothing but a
				// command substitution as an empty word) is unknown,
				// never the directory the unit starts in.
				cwd = dirRef{unknown: true}
			} else {
				cwd = resolveDirOperand(env, cwd, op, cmd.Dialect)
			}
			if cwd.unknown && cwd.why == "" {
				cwd.why = cmd.Raw
			}
		}
		a := deleteAnchor{
			cwd: cwd.path, unknown: cwd.unknown, links: f.links, opaque: f.opaque,
			unknownVia: cwd.why, opaqueVia: f.opaqueVia, failPath: f.failPath, failVia: f.failVia,
		}
		a.plain = !a.unknown && !a.opaque && len(a.links) == 0 &&
			(a.cwd == base || (a.cwd != "" && base != "" && pathsEqual(a.cwd, base)))
		k := frameKey(cwdFrame{dirState: dirState{cwd: cwd}, links: f.links, opaque: f.opaque})
		if i, dup := seen[k]; dup {
			// One anchor, several frames: it is a failure branch only if
			// every frame reaching it is.
			out[i].failPath = out[i].failPath && a.failPath
			continue
		}
		seen[k] = len(out)
		out = append(out, a)
	}
	if len(out) == 0 {
		return plain
	}
	return out
}

// plainOnly reports whether the anchors are exactly the legacy one.
func plainOnly(as []deleteAnchor) bool {
	return len(as) == 1 && as[0].plain
}

// resolveAt is resolveOrLiteral against an anchor.
func resolveAt(ctx *MatchContext, t string, a deleteAnchor) string {
	if rp := resolvePath(t, ctx.Cfg.Home, a.cwd, ""); rp != "" {
		return rp
	}
	return normPath(expandHome(t, ctx.Cfg.Home))
}

// anchoredPath is one place a path token can point when its unit runs.
type anchoredPath struct {
	path string
	// moved: judged from a directory an earlier step of the line changed
	// to, or through a link the line created, not from the event's own
	// directory. It feeds the reason text only.
	moved bool
}

// unitPathCandidates resolves path token t from every anchor of its unit
// (T-387, D-279 follow-up): the ONE entry the sensitive-path rows use
// (R-152..R-156, R-160, R-161, shell and inline-script alike), as
// unitAnchors is the delete rules'. Before it those rows resolved every
// relative operand from the event's own directory, so `cd ~/.aws && cat
// config`, `cd ~ && echo x >> .bashrc` and `ln -s ~/.ssh k && cat
// k/id_rsa` were judged as files inside the project.
//
// A token is judged in every resolvable state, through any link created
// earlier in the line. An anchor the model cannot place (an unresolved
// directory change, an unmodelled evaluation) or a link with an unknown
// target cannot locate a relative token, so there the token is judged
// from the event's own directory, the reading these rows always made:
// the model can add a hit, never remove one the legacy reading had,
// unless every state the unit can run in is resolved somewhere else.
// Candidates are deduplicated, order is anchor order.
func unitPathCandidates(ctx *MatchContext, anchors []deleteAnchor, t string) []anchoredPath {
	var out []anchoredPath
	seen := make(map[string]bool, len(anchors)+1)
	add := func(p string, moved bool) {
		if seen[p] {
			return
		}
		seen[p] = true
		out = append(out, anchoredPath{path: p, moved: moved})
	}
	for _, a := range anchors {
		if a.unknown || a.opaque {
			add(resolveOrLiteral(ctx, t), false)
			continue
		}
		p := resolveAt(ctx, t, a)
		if sub, unknown, through := throughSameCmdLinks(p, a.links); through {
			if unknown {
				add(p, !a.plain)
				add(resolveOrLiteral(ctx, t), false)
				continue
			}
			add(sub, true)
			continue
		}
		add(p, !a.plain)
	}
	if len(out) == 0 {
		add(resolveOrLiteral(ctx, t), false)
	}
	return out
}

// movedReason marks a sensitive-path hit judged from a moved directory or
// through a same-command link, so the operator sees why a relative
// operand named a protected location.
func movedReason(why string, moved bool) string {
	if !moved {
		return why
	}
	return why + " (from the directory or link an earlier step of this command set up)"
}

// --- step classification (table-driven) ---------------------------------

// stepClassifiers maps a canonical base to the function that reads its
// argv into a step. A base not listed is stepOther.
var stepClassifiers = map[string]func(st *seqStep, cmd *Command){
	"cd": classifyCd, "chdir": classifyCd, "set-location": classifyCd, "sl": classifyCd,
	"pushd": classifyPushd, "push-location": classifyPushd,
	"popd": classifyPopd, "pop-location": classifyPopd,
	"ln":       classifyLn,
	"mklink":   classifyMklink,
	"new-item": classifyNewItem, "ni": classifyNewItem,
	"mount": classifyMount,
	"mv":    classifyCopy, "cp": classifyCopy, "move-item": classifyCopy, "copy-item": classifyCopy,
	"rename-item": classifyRename, "rni": classifyRename,
}

// classifyStep fills st from the unit's Command.
func classifyStep(st *seqStep, cmd *Command) {
	if fn, ok := stepClassifiers[cmd.Base]; ok {
		fn(st, cmd)
	}
}

// argOperand is Argv[i] with its literal offsets.
func (c *Command) argOperand(i int) operand {
	op := operand{text: c.Argv[i]}
	if len(c.ArgvLiterals) == len(c.Argv) {
		op.lit = c.ArgvLiterals[i]
	}
	return op
}

// psArgs splits a PowerShell argv into named parameter values (keyed by
// the matched full name) and positional operands. params maps each
// valued parameter's full name to its minimum prefix length; the tables
// below keep those prefixes unambiguous, so map order cannot matter. Any
// other parameter is read as a switch (no value).
func psArgs(cmd *Command, params map[string]int) (named map[string]operand, pos []operand) {
	named = map[string]operand{}
	for i := 1; i < len(cmd.Argv); i++ {
		t := cmd.Argv[i]
		if len(t) < 2 || t[0] != '-' {
			pos = append(pos, cmd.argOperand(i))
			continue
		}
		name, val, hasColon := strings.Cut(t, ":")
		for full, minLen := range params {
			if !psParamMatches(name, full, minLen) {
				continue
			}
			switch {
			case hasColon:
				named[full] = operand{text: val}
			case i+1 < len(cmd.Argv):
				named[full] = cmd.argOperand(i + 1)
				i++
			}
			break
		}
	}
	return named, pos
}

// psLocationParams are Set-Location / Push-Location / Pop-Location's
// valued parameters.
var psLocationParams = map[string]int{"path": 3, "literalpath": 1, "stackname": 1}

// psLocation reads a PowerShell location cmdlet: the target operand (if
// any) and whether a named stack is used (not modelled).
func psLocation(cmd *Command) (target operand, has, stack bool) {
	named, pos := psArgs(cmd, psLocationParams)
	if _, ok := named["stackname"]; ok {
		return operand{}, false, true
	}
	if v, ok := named["path"]; ok {
		return v, true, false
	}
	if v, ok := named["literalpath"]; ok {
		return v, true, false
	}
	if len(pos) > 0 {
		return pos[0], true, false
	}
	return operand{}, false, false
}

// posixDirArgs splits a POSIX cd/pushd/popd argv: flags made only of
// the letters in flagLetters are skipped, `-` alone and `+N`/`-N` are
// returned as positionals for the caller to read.
func posixDirArgs(cmd *Command, flagLetters string) (pos []operand, flags string) {
	end := false
	for i := 1; i < len(cmd.Argv); i++ {
		t := cmd.Argv[i]
		if !end && t == "--" {
			end = true
			continue
		}
		if !end && len(t) > 1 && t[0] == '-' && strings.Trim(t[1:], flagLetters) == "" {
			flags += t[1:]
			continue
		}
		pos = append(pos, cmd.argOperand(i))
	}
	return pos, flags
}

// isStackIndex reports a dirs-stack index operand (`+2`, `-0`).
func isStackIndex(s string) bool {
	if len(s) < 2 || (s[0] != '+' && s[0] != '-') {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func classifyCd(st *seqStep, cmd *Command) {
	switch cmd.Dialect {
	case DialectPowerShell:
		target, has, stack := psLocation(cmd)
		switch {
		case stack:
			st.kind = stepDirUnknown
		case !has:
			// PowerShell 7 goes home; 5.1 stays. Home is the reading
			// that can make a later delete catastrophic.
			st.kind = stepCdHome
		case target.text == "-":
			st.kind = stepCdBack
		case target.text == "+":
			st.kind = stepDirUnknown
		default:
			st.kind, st.arg = stepCd, target
		}
	case DialectCmd:
		var pos []operand
		for i := 1; i < len(cmd.Argv); i++ {
			if strings.EqualFold(cmd.Argv[i], "/d") {
				continue
			}
			pos = append(pos, cmd.argOperand(i))
		}
		if len(pos) == 0 {
			return // bare `cd` prints the current directory
		}
		// cmd's cd takes the rest of the line as one path.
		parts := make([]string, len(pos))
		for i, p := range pos {
			parts[i] = p.text
		}
		st.kind, st.arg = stepCd, operand{text: strings.Join(parts, " ")}
	default:
		pos, _ := posixDirArgs(cmd, "LPe@")
		switch {
		case len(pos) == 0:
			st.kind = stepCdHome
		case len(pos) > 1:
			st.kind = stepDirUnknown // zsh `cd old new` substitution
		case pos[0].text == "-":
			st.kind = stepCdBack
		case isStackIndex(pos[0].text):
			st.kind = stepDirUnknown // zsh `cd +N`
		default:
			st.kind, st.arg = stepCd, pos[0]
		}
	}
}

func classifyPushd(st *seqStep, cmd *Command) {
	switch cmd.Dialect {
	case DialectPowerShell:
		target, has, stack := psLocation(cmd)
		switch {
		case stack:
			st.kind = stepDirUnknown
		case !has:
			st.kind, st.arg = stepPushdKeep, operand{}
		default:
			st.kind, st.arg = stepPushd, target
		}
	case DialectCmd:
		if len(cmd.Argv) < 2 {
			return // bare pushd prints the stack
		}
		st.kind, st.arg = stepPushd, cmd.argOperand(1)
	default:
		pos, flags := posixDirArgs(cmd, "n")
		keep := strings.Contains(flags, "n")
		switch {
		case len(pos) == 0 && keep:
			return
		case len(pos) == 0:
			st.kind = stepPushdSwap
		case len(pos) > 1 || isStackIndex(pos[0].text):
			st.kind = stepDirUnknown
		case keep:
			st.kind, st.arg = stepPushdKeep, pos[0]
		default:
			st.kind, st.arg = stepPushd, pos[0]
		}
	}
}

func classifyPopd(st *seqStep, cmd *Command) {
	switch cmd.Dialect {
	case DialectPowerShell:
		if _, _, stack := psLocation(cmd); stack {
			st.kind = stepDirUnknown
			return
		}
		st.kind = stepPopd
	case DialectCmd:
		st.kind = stepPopd
	default:
		pos, flags := posixDirArgs(cmd, "n")
		if len(pos) > 0 || strings.Contains(flags, "n") {
			st.kind = stepDirUnknown // popd +N / -n edit the stack, not modelled
			return
		}
		st.kind = stepPopd
	}
}

// classifyLn reads GNU/BSD `ln`. Only symbolic links count: a directory
// cannot be hard-linked, and deleting through a file hard link removes
// only that name.
func classifyLn(st *seqStep, cmd *Command) {
	o, pos := parseGNUArgs(cmd)
	if !o.flags['s'] || len(pos) == 0 {
		return
	}
	rel := o.flags['r']
	st.kind = stepLink
	if len(pos) == 1 && o.targetDir == nil {
		st.links = append(st.links, linkSpec{target: pos[0], targetFromCwd: rel})
		return
	}
	srcs, dst, intoDir, maybeDir, ok := o.destination(pos)
	if !ok {
		st.kind = stepOther
		return
	}
	for _, p := range srcs {
		st.links = append(st.links, linkSpec{at: dst, hasAt: true, intoDir: intoDir, maybeDir: maybeDir, target: p, targetFromCwd: rel})
	}
}

// gnuOpts is what parseGNUArgs reads from a GNU coreutils argv (ln, mv,
// cp): the short letters seen (long forms mapped onto them) and the
// target directory.
type gnuOpts struct {
	flags     map[byte]bool
	targetDir *operand
}

// gnuLongFlags maps the long options read here onto their short letters.
var gnuLongFlags = map[string]byte{
	"--symbolic": 's', "--relative": 'r', "--no-target-directory": 'T', "--dereference": 'L',
}

// parseGNUArgs splits a coreutils argv into options and operands,
// honouring `--`, clustered short flags and the valued -t / -S options.
func parseGNUArgs(cmd *Command) (gnuOpts, []operand) {
	o := gnuOpts{flags: map[byte]bool{}}
	var pos []operand
	end := false
	for i := 1; i < len(cmd.Argv); i++ {
		t := cmd.Argv[i]
		switch {
		case !end && t == "--":
			end = true
		case !end && strings.HasPrefix(t, "--"):
			i = o.readLong(cmd, i)
		case !end && len(t) > 1 && t[0] == '-':
			i = o.readShort(cmd, i)
		default:
			pos = append(pos, cmd.argOperand(i))
		}
	}
	return o, pos
}

// readLong reads Argv[i] as a long option and returns the last index it
// consumed.
func (o *gnuOpts) readLong(cmd *Command, i int) int {
	name, val, hasEq := strings.Cut(cmd.Argv[i], "=")
	if c, ok := gnuLongFlags[name]; ok {
		o.flags[c] = true
		return i
	}
	switch name {
	case "--target-directory":
		return o.takeTargetDir(cmd, i, val, hasEq)
	case "--suffix":
		if !hasEq {
			return i + 1
		}
	}
	return i
}

// readShort reads Argv[i] as a short-flag cluster and returns the last
// index it consumed.
func (o *gnuOpts) readShort(cmd *Command, i int) int {
	t := cmd.Argv[i]
	for k := 1; k < len(t); k++ {
		switch t[k] {
		case 't':
			if k+1 < len(t) {
				o.targetDir = &operand{text: t[k+1:]}
				return i
			}
			return o.takeTargetDir(cmd, i, "", false)
		case 'S':
			if k+1 == len(t) {
				return i + 1
			}
			return i
		default:
			o.flags[t[k]] = true
		}
	}
	return i
}

// takeTargetDir records -t / --target-directory's value.
func (o *gnuOpts) takeTargetDir(cmd *Command, i int, val string, hasEq bool) int {
	if hasEq {
		o.targetDir = &operand{text: val}
		return i
	}
	if i+1 < len(cmd.Argv) {
		op := cmd.argOperand(i + 1)
		o.targetDir = &op
		return i + 1
	}
	return i
}

// destination applies coreutils' operand rules: with -t every operand is
// a source placed inside the directory; otherwise the last operand is the
// destination, a directory when there are several sources, and possibly
// one (unless -T) when there is a single source.
func (o gnuOpts) destination(pos []operand) (srcs []operand, dst operand, intoDir, maybeDir, ok bool) {
	switch {
	case o.targetDir != nil:
		return pos, *o.targetDir, true, false, len(pos) > 0
	case len(pos) < 2:
		return nil, operand{}, false, false, false
	case len(pos) == 2:
		return pos[:1], pos[1], false, !o.flags['T'], true
	default:
		return pos[:len(pos)-1], pos[len(pos)-1], true, false, true
	}
}

// classifyMklink reads cmd's `mklink [/D | /J | /H] Link Target`. A
// hard link (/H) is a file link and does not count.
func classifyMklink(st *seqStep, cmd *Command) {
	junction := false
	var pos []operand
	for i := 1; i < len(cmd.Argv); i++ {
		t := cmd.Argv[i]
		switch strings.ToLower(t) {
		case "/h":
			return
		case "/j":
			junction = true
		case "/d":
		default:
			pos = append(pos, cmd.argOperand(i))
		}
	}
	if len(pos) < 2 {
		return
	}
	st.kind = stepLink
	st.links = append(st.links, linkSpec{at: pos[0], hasAt: true, target: pos[1], targetFromCwd: junction})
}

// newItemParams are New-Item's valued parameters used here.
var newItemParams = map[string]int{"itemtype": 2, "type": 2, "path": 2, "name": 2, "value": 2, "target": 2}

// classifyNewItem reads `New-Item -ItemType SymbolicLink|Junction`.
// Whether PowerShell keeps a relative -Target relative to the link or to
// the current location has varied by version, so both readings count.
func classifyNewItem(st *seqStep, cmd *Command) {
	named, pos := psArgs(cmd, newItemParams)
	kind := strings.ToLower(named["itemtype"].text)
	if kind == "" {
		kind = strings.ToLower(named["type"].text)
	}
	if kind != "symboliclink" && kind != "junction" {
		return
	}
	at, ok := named["path"]
	if !ok && len(pos) > 0 {
		at, pos = pos[0], pos[1:]
	}
	if n, ok := named["name"]; ok {
		if at.text == "" {
			at = n
		} else {
			at = operand{text: strings.TrimRight(at.text, `/\`) + "/" + n.text}
		}
	}
	target, ok := named["target"]
	if !ok {
		target, ok = named["value"]
	}
	if !ok && len(pos) > 0 {
		target, ok = pos[0], true
	}
	if at.text == "" || !ok {
		return
	}
	st.kind = stepLink
	st.links = append(st.links,
		linkSpec{at: at, hasAt: true, target: target, targetFromCwd: true},
		linkSpec{at: at, hasAt: true, target: target})
}

// classifyMount reads a bind mount: the destination then shows the
// source's tree, which is a link for this model.
func classifyMount(st *seqStep, cmd *Command) {
	bind := false
	var pos []operand
	for i := 1; i < len(cmd.Argv); i++ {
		t := cmd.Argv[i]
		switch {
		case t == "--bind" || t == "--rbind" || t == "-B" || t == "-R":
			bind = true
		case t == "-o" || t == "--options":
			if i+1 < len(cmd.Argv) {
				if strings.Contains(cmd.Argv[i+1], "bind") {
					bind = true
				}
				i++
			}
		case strings.HasPrefix(t, "--options="), strings.HasPrefix(t, "-o"):
			if strings.Contains(t, "bind") {
				bind = true
			}
		case t == "-t" || t == "--types" || t == "-O" || t == "--test-opts":
			i++
		case len(t) > 1 && t[0] == '-':
		default:
			pos = append(pos, cmd.argOperand(i))
		}
	}
	if !bind || len(pos) != 2 {
		return
	}
	st.kind = stepLink
	st.links = append(st.links, linkSpec{at: pos[1], hasAt: true, target: pos[0], targetFromCwd: true})
}

// copyItemParams are Move-Item / Copy-Item's valued parameters.
var copyItemParams = map[string]int{"path": 2, "literalpath": 1, "destination": 2}

// classifyCopy reads mv / cp (POSIX) and Move-Item / Copy-Item.
func classifyCopy(st *seqStep, cmd *Command) {
	if cmd.Dialect == DialectPowerShell {
		classifyPSCopy(st, cmd)
		return
	}
	o, pos := parseGNUArgs(cmd)
	if o.flags['L'] && cmd.Base == "cp" {
		return // cp -L copies what the link points at, not the link
	}
	srcs, dst, intoDir, maybeDir, ok := o.destination(pos)
	if !ok {
		return
	}
	st.kind = stepCopyLink
	st.copy = &copySpec{srcs: srcs, dst: dst, intoDir: intoDir, maybeDir: maybeDir}
}

// classifyPSCopy reads Move-Item / Copy-Item (-Path / -LiteralPath,
// -Destination, or the two positionals).
func classifyPSCopy(st *seqStep, cmd *Command) {
	named, pos := psArgs(cmd, copyItemParams)
	src, ok := named["path"]
	if !ok {
		src, ok = named["literalpath"]
	}
	if !ok && len(pos) > 0 {
		src, ok, pos = pos[0], true, pos[1:]
	}
	dst, dok := named["destination"]
	if !dok && len(pos) > 0 {
		dst, dok = pos[0], true
	}
	if !ok || !dok {
		return
	}
	st.kind = stepCopyLink
	st.copy = &copySpec{srcs: []operand{src}, dst: dst, maybeDir: true}
}

// renameItemParams are Rename-Item's valued parameters.
var renameItemParams = map[string]int{"path": 2, "literalpath": 1, "newname": 1}

// classifyRename reads Rename-Item: a new name in the source's directory.
func classifyRename(st *seqStep, cmd *Command) {
	named, pos := psArgs(cmd, renameItemParams)
	src, ok := named["path"]
	if !ok {
		src, ok = named["literalpath"]
	}
	if !ok && len(pos) > 0 {
		src, ok, pos = pos[0], true, pos[1:]
	}
	nn, nok := named["newname"]
	if !nok && len(pos) > 0 {
		nn, nok = pos[0], true
	}
	if !ok || !nok {
		return
	}
	st.kind = stepCopyLink
	st.copy = &copySpec{srcs: []operand{src}, dst: nn, sibling: true}
}

// chdirWrapperFlags are the wrapper flags that run the wrapped command
// in another directory.
var chdirWrapperFlags = map[string]map[string]bool{
	"env":  setOf("-C", "--chdir"),
	"sudo": setOf("-D", "--chdir"),
}

// wrapperChdir returns the directories a unit's leading wrappers run it
// in, outermost first (`env -C a sudo -D b cmd`).
func wrapperChdir(words []string, dialect Dialect) []operand {
	table := posixWrappers
	if dialect == DialectCmd {
		table = cmdWrappers
	}
	var dirs []operand
	for len(words) > 0 {
		base := canonicalBase(words[0], dialect)
		spec, ok := table[base]
		if !ok {
			break
		}
		rest := consumeWrapperArgs(words[1:], spec)
		own := words[1 : len(words)-len(rest)]
		if flags := chdirWrapperFlags[base]; flags != nil {
			for i := 0; i < len(own); i++ {
				t := own[i]
				name, val, hasEq := strings.Cut(t, "=")
				switch {
				case hasEq && flags[name]:
					dirs = append(dirs, operand{text: val})
				case flags[t] && i+1 < len(own):
					dirs = append(dirs, operand{text: own[i+1]})
					i++
				case base == "env" && len(t) > 2 && strings.HasPrefix(t, "-C"):
					dirs = append(dirs, operand{text: t[2:]})
				}
			}
		}
		words = rest
	}
	return dirs
}
