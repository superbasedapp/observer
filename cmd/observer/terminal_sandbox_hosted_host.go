//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote/relaymux"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// terminal_sandbox_hosted_host.go is the PTY child of a hosted run (lane
// SBX-P7): `observer sandbox-hosted-host --plan <file> -- observer
// sandbox-host <relay flags> -- observer-hosted-inner <inner launch>`. It is
// the only process that reads the provider credential and calls the vendor,
// and only for this one user-launched run (invariant I6). In order:
//
//  1. the home side's host services (the per-run socket dir, the capture
//     relay, the model proxy forward), exactly as for a local box;
//  2. the credential, read now from the keystore or the environment and
//     checked against the endpoint it is bound to (SBX-GOV-4);
//  3. the spend reservation and the teardown intent, written BEFORE the
//     create call, so a killed process leaves the truth behind;
//  4. the box, created with the vendor's own timeout, the run label and no
//     auto-pause; a lost create answer is resolved by listing the label;
//  5. the workspace (the consented manifest, re-listed and compared), the
//     in-box observer and the relay secrets uploaded, a baseline git
//     repository made of the uploaded tree, the tool installed at first
//     start where the plan says so;
//  6. the relay exec stream (relay-stdio), re-opened and re-keyed after a
//     drop, and the PTY (the vendor's own where it documents a resize, the
//     guest helper's otherwise);
//  7. transcripts pulled home on the checkpoint timer and at the end;
//  8. teardown: pull, then the box's staged diff saved home (never applied),
//     then delete, and the record goes only after the vendor confirms.

// hostedTerm is the helper's terminal: its stdio, the PTY's size, SIGWINCH
// as resizes, SIGHUP and SIGTERM as stop requests.
type hostedTerm struct {
	in      io.Reader
	out     io.Writer
	resized <-chan struct{}
	stopped <-chan string
	size    func() (uint16, uint16)
	raw     func() func()
}

// realHostedTerm builds the helper's terminal.
func realHostedTerm() (hostedTerm, func()) {
	resized := make(chan struct{}, 1)
	stopped := make(chan string, 2)
	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, unix.SIGWINCH, unix.SIGHUP, unix.SIGTERM)
	signal.Ignore(unix.SIGINT, unix.SIGQUIT)
	quit := make(chan struct{})
	go func() {
		for {
			select {
			case <-quit:
				return
			case s := <-sigs:
				if s == unix.SIGWINCH {
					select {
					case resized <- struct{}{}:
					default:
					}
					continue
				}
				select {
				case stopped <- s.String():
				default:
				}
			}
		}
	}()
	fd := int(os.Stdin.Fd()) //nolint:gosec // G115: a descriptor number
	t := hostedTerm{
		in: os.Stdin, out: os.Stdout, resized: resized, stopped: stopped,
		size: func() (uint16, uint16) {
			ws, err := unix.IoctlGetWinsize(fd, unix.TIOCGWINSZ)
			if err != nil || ws.Row == 0 || ws.Col == 0 {
				return 24, 80
			}
			return ws.Row, ws.Col
		},
		raw: func() func() {
			if !term.IsTerminal(fd) {
				return func() {}
			}
			st, err := term.MakeRaw(fd)
			if err != nil {
				return func() {}
			}
			return func() { _ = term.Restore(fd, st) }
		},
	}
	return t, func() {
		signal.Stop(sigs)
		close(quit)
	}
}

// parseHostedHostArgs reads `--plan <path> -- observer sandbox-host <flags>
// -- observer-hosted-inner <inner...>`.
func parseHostedHostArgs(args []string) (string, sandbox.HostArgs, error) {
	if len(args) < 4 || args[0] != "--plan" || args[2] != "--" {
		return "", sandbox.HostArgs{}, errors.New("usage: sandbox-hosted-host --plan <file> -- observer sandbox-host ... -- " + hostedInnerMarker + " <launch>")
	}
	rest := args[3:]
	if len(rest) < 2 || rest[1] != sandbox.HostVerb {
		return "", sandbox.HostArgs{}, errors.New("the host services are missing after --plan")
	}
	h, err := sandbox.ParseHostArgs(rest[2:])
	if err != nil {
		return "", sandbox.HostArgs{}, err
	}
	if len(h.Command) < 2 || h.Command[0] != hostedInnerMarker {
		return "", sandbox.HostArgs{}, errors.New("no inner launch after the marker")
	}
	h.Command = h.Command[1:]
	return args[1], h, nil
}

// runHostedHost is the PTY child of a hosted run.
func runHostedHost(args []string) int {
	t, done := realHostedTerm()
	defer done()
	planPath, h, err := parseHostedHostArgs(args)
	if err != nil {
		return helperFail("observer sandbox (hosted): %v", err)
	}
	plan, err := readHostedPlan(planPath)
	if err != nil {
		return helperFail("observer sandbox (hosted): %v", err)
	}
	stop, err := startHostServices(h)
	defer stop()
	if err != nil {
		return helperFail("observer sandbox (hosted): %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	run := &hostedRun{plan: plan, h: h, t: t, now: time.Now, ingest: hostedOpenIngester}
	return run.drive(ctx)
}

// hostedOpenIngester opens the node database for the transcript ingest.
func hostedOpenIngester(ctx context.Context) (hostedIngester, func(), error) {
	_, database, closeDB, err := loadConfigAndDB(ctx, daemonConfigPath())
	if err != nil {
		return nil, func() {}, err
	}
	return hostedIngestPulled(store.New(database)), closeDB, nil
}

// hostedRun is one hosted run's host-side state.
type hostedRun struct {
	plan   hostedPlanFile
	h      sandbox.HostArgs
	t      hostedTerm
	now    func() time.Time
	ingest func(ctx context.Context) (hostedIngester, func(), error)

	vendor sandboxremote.Vendor
	client sandboxremote.Client
	layout sandboxremote.BoxLayout
	rec    sandboxremote.Record
	start  time.Time
	cred   sandboxremote.Credential

	// relayLog is the run's kept relay log (terminal_sandbox_hosted_relaylog.go),
	// opened at the first relay start.
	relayLogOnce sync.Once
	relayLog     *hostedRelayLog
	// rekey: this helper re-adopts a run, so its relay replaces the box
	// record with the new keys.
	rekey bool
}

// rlog returns the run's kept relay log (nil when it cannot be opened).
func (r *hostedRun) rlog() *hostedRelayLog {
	r.relayLogOnce.Do(func() {
		r.relayLog = openHostedRelayLog(r.plan.ObserverDir, r.plan.RunID, r.cred.Secrets(), r.now)
	})
	return r.relayLog
}

func (r *hostedRun) say(format string, a ...any) {
	fmt.Fprintf(r.t.out, "\r\n[observer: "+format+"]\r\n", a...)
}

// fail prints a refusal with the credential redacted and returns the
// helper's failure code.
func (r *hostedRun) fail(format string, a ...any) int {
	msg := sandboxremote.Redact(fmt.Sprintf(format, a...), r.cred.Secrets())
	return helperFail("observer sandbox (%s): %s", r.plan.Provider, msg)
}

// drive runs the whole lifecycle and returns the run's exit status.
func (r *hostedRun) drive(ctx context.Context) int {
	v, ok := sandboxremote.VendorFor(r.plan.Provider)
	reg, regOK := hostedVendorRegs[r.plan.Provider]
	if !ok || !regOK {
		return r.fail("no driver for %s in this build", r.plan.Provider)
	}
	if r.vendor.ID == "" {
		r.vendor = v
	}
	cred, err := hostedResolveCredential(r.plan.ObserverDir, v)
	if err != nil {
		return r.fail("%v", err)
	}
	r.cred = cred
	if err := sandboxremote.CheckBindingPinned(cred, v, r.plan.Endpoint, r.plan.EndpointSPKISHA256); err != nil {
		return r.fail("%v", err)
	}
	client, err := reg.newClient(cred, r.plan.Endpoint)
	if err != nil {
		return r.fail("%v", err)
	}
	r.client = client
	r.layout = v.Layout(r.plan.Root)
	r.start = r.now()
	if f := hostedCredSetupHook; f != nil {
		if err := f(ctx, r.plan); err != nil {
			return r.fail("%v", err)
		}
		defer hostedCredTeardownHook(r.plan)
	}
	if err := r.create(ctx); err != nil {
		return r.fail("%v", err)
	}
	// From here a box exists: every exit path tears it down.
	code, err := r.runBox(ctx)
	r.teardown(context.WithoutCancel(ctx))
	if err != nil {
		return r.fail("%v", err)
	}
	return code
}

// create reserves the spend, records the intent and creates the box.
func (r *hostedRun) create(ctx context.Context) error {
	minutes := r.plan.TimeoutMinutes
	now := r.now()
	// Re-checked under the ledger lock: another run may have spent today's
	// minutes since the launch was planned; the box then gets less time,
	// never more.
	if err := hostedUpdateLedger(r.plan.ObserverDir, now, func(l *sandboxremote.Ledger) error {
		m, err := sandboxremote.PlanTimeout(minutes, r.plan.DailyBoxMinutes, l.Used(r.plan.Provider, sandboxremote.DayOf(now)))
		if err != nil {
			return err
		}
		minutes = m
		l.Reserve(r.plan.Provider, sandboxremote.DayOf(now), r.plan.RunID, minutes)
		return nil
	}); err != nil {
		return err
	}
	r.rec = sandboxremote.NewIntent(r.plan.RunID, r.plan.Provider, r.plan.Endpoint, r.plan.Region, r.plan.RunID, now, time.Duration(minutes)*time.Minute)
	// The helper's own pid (a local process id, never a secret): while it
	// lives, the run is not a leftover and cannot be deleted from the list.
	r.rec.Extra = map[string]string{hostedHelperPIDKey: strconv.Itoa(os.Getpid())}
	if err := hostedSaveRecord(r.plan.ObserverDir, r.rec); err != nil {
		return fmt.Errorf("record the create intent: %w", err)
	}
	spec := sandboxremote.BoxSpec{
		RunID: r.plan.RunID, Labels: map[string]string{sandboxremote.LabelKey: r.plan.RunID},
		Template: r.plan.Template, TimeoutSeconds: minutes * 60, Tier: vocab.Tier(r.plan.Tier), Region: r.plan.Region,
	}
	info, err := r.client.Create(ctx, spec)
	switch {
	case errors.Is(err, sandboxremote.ErrCreateUnknown):
		_ = r.rec.Apply(sandboxremote.EvCreateLost)
		_ = hostedSaveRecord(r.plan.ObserverDir, r.rec)
		r.resolveLostCreate(context.WithoutCancel(ctx))
		return fmt.Errorf("the create answer was lost; any box made under this run's label was deleted: %w", err)
	case err != nil:
		_ = r.rec.Apply(sandboxremote.EvCreateFailed)
		_ = hostedRemoveRecord(r.plan.ObserverDir, r.rec)
		// The vendor refused the create, so no box was made and nothing ran:
		// the reservation settles to zero (live run 2026-10-23, finding F13;
		// a lost create, above, keeps its charge).
		r.settleNoBox()
		if errors.Is(err, sandboxremote.ErrTemplateUnavailable) {
			rule := r.vendor.TemplateRule
			if rule == "" {
				rule = "the configured template is not one " + r.vendor.Name + " can start"
			}
			return fmt.Errorf("%s: %s refused the template %q: %s: %w", verdictHostedTool, r.vendor.Name, r.plan.Template, rule, err)
		}
		return fmt.Errorf("create the box: %w", err)
	}
	r.rec.VendorID = info.ID
	// The vendor's identifiers join the record's own keys: the helper's pid
	// stays, so a live run is never listed as a leftover nor deleted from
	// under its helper (live run 2026-10-23, finding F3: the map was
	// replaced).
	if r.rec.Extra == nil {
		r.rec.Extra = map[string]string{}
	}
	for k, v := range info.Extra {
		if k != hostedHelperPIDKey {
			r.rec.Extra[k] = v
		}
	}
	_ = r.rec.Apply(sandboxremote.EvCreateOK)
	if info.Region != "" {
		r.rec.Region = info.Region
	}
	if info.EnvdToken != "" {
		if p, err := hostedSaveBoxSecret(r.plan.ObserverDir, r.plan.RunID, info.EnvdToken); err == nil {
			r.rec.SecretFiles = append(r.rec.SecretFiles, p)
		}
	}
	if err := hostedSaveRecord(r.plan.ObserverDir, r.rec); err != nil {
		return fmt.Errorf("record the box id: %w", err)
	}
	r.say("%s box %s in %s, stops by itself after %d minutes", r.vendor.Name, info.ID, hostedRegionWords(r.vendor, r.rec.Region), minutes)
	return nil
}

// hostedRegionWords is a run's region as the terminal says it: a region the
// vendor picked is said to be the vendor's choice, never a named place
// (Modal reports no region back; live run 2026-10-23).
func hostedRegionWords(v sandboxremote.Vendor, region string) string {
	if region == "" || region == sandboxremote.ProviderChosen {
		return "a region " + v.Name + " chose (it does not report which)"
	}
	return region
}

// resolveLostCreate lists the run label: a box found is deleted (it never
// started work), none found ends the record.
func (r *hostedRun) resolveLostCreate(ctx context.Context) {
	list, err := r.client.ListByLabel(ctx, sandboxremote.LabelKey, r.plan.RunID)
	if err != nil {
		return // the record stays create_lost: the leftover list shows it
	}
	for _, b := range list {
		if derr := r.client.Delete(ctx, b.ID); derr != nil && !errors.Is(derr, sandboxremote.ErrNotFound) {
			return
		}
	}
	_ = r.rec.Apply(sandboxremote.EvNotFound)
	_ = hostedRemoveRecord(r.plan.ObserverDir, r.rec)
	r.settle()
}

// settleNoBox settles a create the vendor refused: no box, no minutes.
func (r *hostedRun) settleNoBox() {
	_ = hostedUpdateLedger(r.plan.ObserverDir, r.now(), func(l *sandboxremote.Ledger) error {
		l.Settle(r.plan.RunID, 0)
		return nil
	})
}

// settle replaces the reservation with the minutes the box ran.
func (r *hostedRun) settle() {
	ran := r.now().Sub(r.start)
	_ = hostedUpdateLedger(r.plan.ObserverDir, r.now(), func(l *sandboxremote.Ledger) error {
		l.Settle(r.plan.RunID, ran)
		return nil
	})
}

// boxEnv is the base environment of every process the run starts.
func (r *hostedRun) boxEnv() map[string]string {
	return map[string]string{
		"HOME": r.layout.Home, "LANG": "C.UTF-8", "TERM": "xterm-256color",
		"PATH": path.Dir(r.layout.Binary) + ":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}
}

// execOK runs argv in the box and requires exit 0.
func (r *hostedRun) execOK(ctx context.Context, what string, spec sandboxremote.ExecSpec) error {
	if spec.Env == nil {
		spec.Env = r.boxEnv()
	}
	p, err := r.client.Exec(ctx, r.rec.VendorID, spec)
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	defer p.Close()
	out, _ := io.ReadAll(io.LimitReader(p, 64<<10))
	code, err := p.Wait(ctx)
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if code != 0 {
		return fmt.Errorf("%s exited %d: %s", what, code, strings.TrimSpace(sandboxremote.Redact(string(out), r.cred.Secrets())))
	}
	return nil
}

// hostedBoxOwnerProbe prints the uid:gid of the box's default (non-root)
// exec user, the user the agent and git run as.
const hostedBoxOwnerProbe = `printf '%s:%s\n' "$(id -u)" "$(id -g)"`

// hostedBoxSetupScript makes the run's directories and gives them to the
// box user. Arguments: the owner (uid:gid, or "" to take the box home's
// owner), the box home, the workspace, the binary's directory, the run
// directory (made owner-only).
const hostedBoxSetupScript = `o=$1; [ -n "$o" ] || o=$(stat -c %u:%g -- "$2") || exit 1; shift 2
mkdir -p -- "$1" "$2" "$3" && chown "$o" -- "$1" "$2" "$3" && chmod 0700 -- "$3"`

// hostedBoxOwnScript gives trees to the box user without following a link.
// Arguments: the owner (as hostedBoxSetupScript), the box home, the trees.
const hostedBoxOwnScript = `o=$1; [ -n "$o" ] || o=$(stat -c %u:%g -- "$2") || exit 1; shift 2
chown -R -h "$o" -- "$@"`

// hostedOwnerRE is the shape of a uid:gid pair.
var hostedOwnerRE = regexp.MustCompile(`^[0-9]{1,10}:[0-9]{1,10}$`)

// boxOwner reads the box user's uid:gid, or "" (the scripts then take the
// owner of the box home, the earlier rule) when the box does not answer.
func (r *hostedRun) boxOwner(ctx context.Context) string {
	out, code, err := hostedExecOutput(ctx, r.client, r.rec.VendorID, []string{"sh", "-c", hostedBoxOwnerProbe}, r.boxEnv(), 256)
	if err != nil || code != 0 {
		return ""
	}
	if o := strings.TrimSpace(string(out)); hostedOwnerRE.MatchString(o) {
		return o
	}
	return ""
}

// boxArch maps uname -m to a Go architecture.
var boxArch = map[string]string{"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}

// prepare uploads the workspace, the in-box observer and the relay secrets,
// and makes the box ready to start the agent.
func (r *hostedRun) prepare(ctx context.Context) error {
	ws := r.layout.Workspace
	// The user every agent, git and guest process runs as (not root): the
	// workspace, the binary's directory and the run directory are made its
	// own, so git's ownership check accepts the repository (live run 2,
	// finding F-A: on Vercel the workspace was uid 0 while its files and
	// .git were uid 1000, git refused it and no diff came home).
	owner := r.boxOwner(ctx)
	if err := r.execOK(ctx, "prepare the box", sandboxremote.ExecSpec{
		Argv: []string{"sh", "-c", hostedBoxSetupScript, "sh", owner, r.layout.Home, ws, path.Dir(r.layout.Binary), r.layout.RunDir}, AsRoot: true,
	}); err != nil {
		return err
	}
	if err := r.checkArch(ctx); err != nil {
		return err
	}
	// The workspace as consented: the same scope, re-listed now.
	cands, repo, err := hostedListWorkspace(ctx, r.plan.Root)
	if err != nil {
		return err
	}
	home, _ := os.UserHomeDir()
	m, err := sandboxremote.PlanManifest(sandboxremote.ManifestInput{Root: r.plan.Root, Home: filepath.ToSlash(home), Repository: repo, Candidates: cands})
	if err != nil {
		return err
	}
	if m.ScopeKey != r.plan.ScopeKey {
		return errors.New("the upload scope changed since consent; launch again")
	}
	var files []sandboxremote.UploadFile
	var execs []string
	for _, f := range m.Files {
		local := filepath.Join(r.plan.Root, filepath.FromSlash(f.Path))
		fi, err := os.Lstat(local)
		if err != nil || !fi.Mode().IsRegular() {
			continue // removed or changed shape since the listing: never followed
		}
		mode := uint32(0o644)
		if fi.Mode().Perm()&0o100 != 0 {
			mode = 0o755
			execs = append(execs, path.Join(ws, f.Path))
		}
		files = append(files, sandboxremote.UploadFile{Path: path.Join(ws, f.Path), Mode: mode, Size: fi.Size(), Open: hostedOpenNoFollow(local)})
	}
	if len(files) > 0 {
		if err := r.client.WriteFiles(ctx, r.rec.VendorID, files); err != nil {
			return fmt.Errorf("upload the workspace: %w", err)
		}
	}
	if err := r.uploadBoxBinary(ctx); err != nil {
		return err
	}
	// Again after the uploads, on every row: a vendor's file write may
	// leave a directory it touched owned by root (Vercel's tar extraction
	// at the root did), so the whole tree is given back to the box user
	// before the baseline repository is made.
	if err := r.execOK(ctx, "give the workspace to the box user", sandboxremote.ExecSpec{
		Argv: []string{"sh", "-c", hostedBoxOwnScript, "sh", owner, r.layout.Home, ws, path.Dir(r.layout.Binary)}, AsRoot: true,
	}); err != nil {
		return err
	}
	for len(execs) > 0 {
		n := min(len(execs), 200)
		if err := r.execOK(ctx, "mark executables", sandboxremote.ExecSpec{Argv: append([]string{"chmod", "0755", "--"}, execs[:n]...)}); err != nil {
			return err
		}
		execs = execs[n:]
	}
	if err := r.checkBoxBinary(ctx); err != nil {
		return err
	}
	// A fresh baseline repository of the uploaded tree (history never
	// leaves the machine), so the box's staged diff is exactly its changes.
	_ = r.execOK(ctx, "baseline repository", sandboxremote.ExecSpec{Cwd: ws, Argv: []string{
		"sh", "-c",
		`command -v git >/dev/null 2>&1 || exit 0; git init -q && git add -A && git -c user.email=observer@localhost -c user.name=observer commit -q --allow-empty -m observer-baseline`,
	}})
	if len(r.plan.ToolInstall) > 0 {
		r.say("installing %s from its vendor (first start, internet tier)", r.plan.Tool)
		if err := r.execOK(ctx, "install the agent tool", sandboxremote.ExecSpec{Argv: r.plan.ToolInstall, Cwd: r.layout.Home}); err != nil {
			return fmt.Errorf("%s: %w", verdictHostedTool, err)
		}
	}
	return nil
}

// checkArch refuses a box whose architecture the in-box binary does not
// match (the running binary's own; a box_binary is checked by running it).
func (r *hostedRun) checkArch(ctx context.Context) error {
	if r.plan.BoxBinary != "" && r.plan.BoxBinary != hostedSelfBinary() {
		return nil
	}
	out, code, err := hostedExecOutput(ctx, r.client, r.rec.VendorID, []string{"uname", "-m"}, r.boxEnv(), 256)
	if err != nil || code != 0 {
		return fmt.Errorf("%s: the box's architecture could not be read", verdictHostedBoxBinary)
	}
	if got := boxArch[strings.TrimSpace(string(out))]; got != runtime.GOARCH {
		return fmt.Errorf("%s: the box is %s and this observer is linux/%s; set box_binary to a Linux observer of this version for the box", verdictHostedBoxBinary, strings.TrimSpace(string(out)), runtime.GOARCH)
	}
	return nil
}

// hostedBoxProbeArgs are the arguments of the in-box observer's self-check:
// the root command's own --version flag (there is no `version` subcommand,
// so `observer version` refused every hosted launch; live run 2026-10-23,
// finding F1). TestHostedBoxProbeArgvRunsOnTheRealTree runs them against
// the real command tree, and the fake box answers only these, so a renamed
// flag fails a test instead of a launch.
var hostedBoxProbeArgs = []string{"--version"}

// checkBoxBinary runs the in-box observer's self-check: it must report this
// version.
func (r *hostedRun) checkBoxBinary(ctx context.Context) error {
	out, code, err := hostedExecOutput(ctx, r.client, r.rec.VendorID, append([]string{r.layout.Binary}, hostedBoxProbeArgs...), r.boxEnv(), 4096)
	if err != nil || code != 0 || !strings.Contains(string(out), version) {
		return fmt.Errorf("%s: the in-box observer does not report version %s", verdictHostedBoxBinary, version)
	}
	return nil
}

// The in-box observer's upload (live run 2026-10-23, finding F8). Every row
// sent the uncompressed binary in one call, about 113 MB a box (1.1 GB over
// the run's ten boxes), and Modal's write of it failed twice with "remote
// box not found": Modal's SDK streams one file through one exec's stdin and
// reports a gRPC Unavailable, DeadlineExceeded, Unknown or Canceled on that
// exec as NotFoundError ("The Sandbox is unavailable"), so the error was a
// cut upload stream misnamed, not a box that was not ready (it had answered
// the setup and architecture execs) and not a size limit (the SDK documents
// none). Now the binary is gzip-compressed on this machine, sent in bounded
// parts, each retried after the vendor confirms the box still runs, then
// joined, decompressed and checked against its SHA-256 in the box before it
// is installed.

// hostedUploadPartSize is one part of the in-box observer's upload (a
// variable so a test splits a small binary).
var hostedUploadPartSize = 8 << 20

// hostedUploadAttempts bounds the tries of one part.
const hostedUploadAttempts = 3

// hostedUploadBackoff is the wait before a part's next try.
var hostedUploadBackoff = func(attempt int) time.Duration { return time.Duration(attempt) * 2 * time.Second }

// hostedBoxToolsProbe lists the box tools the upload uses.
const hostedBoxToolsProbe = `for t in gzip sha256sum; do command -v "$t" >/dev/null 2>&1 && echo "$t"; done; exit 0`

// hostedAssembleScript joins the parts in order, decompresses them when the
// mode is gz, checks the SHA-256 of the result and only then installs it.
// Arguments: the binary's path, the expected digest, the mode, the parts.
const hostedAssembleScript = `set -e
out=$1; want=$2; mode=$3; shift 3
tmp="$out.tmp"
rm -f -- "$tmp"
if [ "$mode" = gz ]; then cat -- "$@" | gzip -dc > "$tmp"; else cat -- "$@" > "$tmp"; fi
rm -f -- "$@"
got=$(sha256sum "$tmp" | cut -d ' ' -f 1)
if [ "$got" != "$want" ]; then rm -f -- "$tmp"; echo "observer upload: digest mismatch"; exit 3; fi
chmod 0755 "$tmp"
mv -f -- "$tmp" "$out"`

// hostedPackBinary reads the in-box observer (never through a link) and
// returns what is sent (gzip-compressed when gz) and the SHA-256 and size
// of the binary itself.
func hostedPackBinary(p string, gz bool) ([]byte, string, int64, error) {
	rc, err := hostedOpenNoFollow(p)()
	if err != nil {
		return nil, "", 0, err
	}
	defer rc.Close()
	h := sha256.New()
	var buf bytes.Buffer
	var w io.Writer = &buf
	var zw *gzip.Writer
	if gz {
		zw = gzip.NewWriter(&buf)
		w = zw
	}
	n, err := io.Copy(io.MultiWriter(h, w), rc)
	if err != nil {
		return nil, "", 0, err
	}
	if zw != nil {
		if err := zw.Close(); err != nil {
			return nil, "", 0, err
		}
	}
	return buf.Bytes(), hex.EncodeToString(h.Sum(nil)), n, nil
}

// uploadBoxBinary sends the in-box observer compressed and in parts, and
// installs it only once its digest checks out in the box.
func (r *hostedRun) uploadBoxBinary(ctx context.Context) error {
	out, code, err := hostedExecOutput(ctx, r.client, r.rec.VendorID, []string{"sh", "-c", hostedBoxToolsProbe}, r.boxEnv(), 256)
	if err != nil || code != 0 {
		return fmt.Errorf("%s: the box's tools could not be listed", verdictHostedBoxBinary)
	}
	tools := strings.Fields(string(out))
	if !slices.Contains(tools, "sha256sum") {
		return fmt.Errorf("%s: the box image has no sha256sum, so the uploaded observer cannot be checked in the box; use a template with coreutils", verdictHostedBoxBinary)
	}
	gz := slices.Contains(tools, "gzip")
	payload, sum, raw, err := hostedPackBinary(r.plan.BoxBinary, gz)
	if err != nil {
		return fmt.Errorf("%s: read the in-box observer: %w", verdictHostedBoxBinary, err)
	}
	mode := "raw"
	if gz {
		mode = "gz"
	}
	size := max(hostedUploadPartSize, 1)
	var parts []string
	for off, i := 0, 0; ; i++ {
		end := min(off+size, len(payload))
		p := fmt.Sprintf("%s.part.%03d", r.layout.Binary, i)
		if err := r.uploadPart(ctx, p, payload[off:end]); err != nil {
			return err
		}
		parts = append(parts, p)
		off = end
		if off >= len(payload) {
			break
		}
	}
	argv := append([]string{"sh", "-c", hostedAssembleScript, "sh", r.layout.Binary, sum, mode}, parts...)
	if err := r.execOK(ctx, "check the in-box observer", sandboxremote.ExecSpec{Argv: argv}); err != nil {
		return fmt.Errorf("%s: the uploaded observer did not check out in the box (%w)", verdictHostedBoxBinary, err)
	}
	r.say("the in-box observer (%.1f MiB) was sent as %.1f MiB in %d part(s) and its SHA-256 checked in the box", float64(raw)/(1<<20), float64(len(payload))/(1<<20), len(parts))
	return nil
}

// uploadPart writes one part, retried a bounded number of times; between
// tries the vendor is asked whether the box still runs, so a cut stream
// the vendor misnames as a missing box is retried and a box that is really
// gone ends the run at once.
func (r *hostedRun) uploadPart(ctx context.Context, p string, data []byte) error {
	var err error
	for attempt := 1; attempt <= hostedUploadAttempts; attempt++ {
		err = r.client.WriteFiles(ctx, r.rec.VendorID, []sandboxremote.UploadFile{{Path: p, Mode: 0o644, Size: int64(len(data)), Open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(data)), nil
		}}})
		if err == nil {
			return nil
		}
		info, gerr := r.client.Get(ctx, r.rec.VendorID)
		if errors.Is(gerr, sandboxremote.ErrNotFound) || (gerr == nil && !info.Running) {
			return fmt.Errorf("upload the in-box observer: the box is gone: %w", err)
		}
		if attempt < hostedUploadAttempts {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(hostedUploadBackoff(attempt)):
			}
		}
	}
	return fmt.Errorf("upload the in-box observer (%d tries): %w", hostedUploadAttempts, err)
}

// hostedSelfBinary is the running binary's path.
func hostedSelfBinary() string {
	p, _ := os.Executable()
	return p
}

// hostedOpenNoFollow opens a regular file without following a link.
func hostedOpenNoFollow(p string) func() (io.ReadCloser, error) {
	return func() (io.ReadCloser, error) {
		f, err := os.OpenFile(p, os.O_RDONLY|unix.O_NOFOLLOW, 0)
		if err != nil {
			return nil, err
		}
		if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
			_ = f.Close()
			return nil, fmt.Errorf("%s is not a regular file", p)
		}
		return f, nil
	}
}

// uploadSecret writes a fresh per-run secret owner-only into the box and
// returns it with its box path.
func (r *hostedRun) uploadSecret(ctx context.Context, name string) ([]byte, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, "", err
	}
	secret := []byte(hex.EncodeToString(raw))
	p := path.Join(r.layout.RunDir, name)
	if err := r.client.WriteFiles(ctx, r.rec.VendorID, []sandboxremote.UploadFile{{Path: p, Mode: 0o600, Size: int64(len(secret)), Open: func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(string(secret))), nil
	}}}); err != nil {
		return nil, "", err
	}
	if err := r.execOK(ctx, "protect the relay secret", sandboxremote.ExecSpec{Argv: []string{"chmod", "0600", "--", p}}); err != nil {
		return nil, "", err
	}
	return secret, p, nil
}

// muxKinds are the connection kinds the run's tier allows the box.
func (r *hostedRun) muxKinds() map[string]bool {
	k := map[string]bool{relaymux.KindRelay: true}
	if vocab.Tier(r.plan.Tier) != vocab.TierNone {
		k[relaymux.KindProxy] = true
	}
	return k
}

// dialHome connects a mux stream to the home side's own socket.
func (r *hostedRun) dialHome(ctx context.Context, kind string) (io.ReadWriteCloser, error) {
	name := sandboxrelayd.RelaySocketName
	if kind == relaymux.KindProxy {
		return dialHostedProxyStamped(filepath.Join(r.h.SockDir, sandbox.ProxySocketName), r.plan.RunID)
	}
	var d net.Dialer
	return d.DialContext(ctx, "unix", filepath.Join(r.h.SockDir, name))
}

// muxConn wraps a vendor process stream for the relay mux.
func muxConn(p sandboxremote.Process) *relaymux.DeadlineConn {
	return relaymux.NewDeadlineConn(relaymux.NewLineReader(p), relaymux.NewLineWriter(p), p.Close)
}

// startRelay starts the relay-stdio process and its home side.
func (r *hostedRun) startRelay(ctx context.Context, record []byte) (*relaymux.Host, sandboxremote.Process, error) {
	log := r.rlog()
	secret, sp, err := r.uploadSecret(ctx, "relay."+strconv.FormatInt(r.now().UnixNano(), 36))
	if err != nil {
		log.line("the relay secret could not be placed in the box: %v", err)
		return nil, nil, err
	}
	argv := []string{r.layout.Binary, "sandbox-guest", relayStdioFlag, "--run", r.plan.RunID, "--secret-file", sp}
	if r.rekey {
		// A re-adoption's relay carries new keys: the box record is replaced.
		argv = append(argv, guestRekeyFlag)
	}
	p, err := r.client.Exec(ctx, r.rec.VendorID, sandboxremote.ExecSpec{
		Argv: argv, Env: r.boxEnv(), Stdin: true, Stderr: log.stderrSink(),
	})
	if err != nil {
		log.line("the relay process could not be started: %v", err)
		return nil, nil, fmt.Errorf("start the relay: %w", err)
	}
	opts := relaymux.HostOptions{
		Options: relaymux.Options{RunID: r.plan.RunID, Secret: secret}, Rand: rand.Reader,
		Kinds: r.muxKinds(), Dial: r.dialHome, Record: record,
	}
	if log != nil {
		opts.Log = func(l string) { log.line("%s", l) }
	}
	h, err := relaymux.ServeHost(ctx, muxConn(p), opts)
	if err != nil {
		log.line("the relay handshake failed: %v", err)
		_ = p.Kill(ctx)
		_ = p.Close()
		return nil, nil, fmt.Errorf("the relay handshake: %w", err)
	}
	log.line("the relay process started (pid %s); waiting for its ready", p.PID())
	return h, p, nil
}

// innerArgv is the in-box launch: the guest forwarder (unchanged) then the
// observer launcher, with the host binary's path replaced by the box's.
func (r *hostedRun) innerArgv() ([]string, error) {
	inner := append([]string(nil), r.h.Command...)
	if len(inner) == 0 {
		return nil, errors.New("no inner launch")
	}
	inner[0] = r.layout.Binary
	if hostedForwardsProxy(vocab.Tier(r.plan.Tier)) {
		// The box has no config file, so the inner launcher's default port
		// (8820) is not the home proxy's; the port the guest forwarder serves
		// is carried on the launcher's own proxy flag (live run 2026-10-23,
		// finding F5).
		inner = hostedWithProxyFlag(inner, "http://127.0.0.1:"+strconv.Itoa(r.proxyPort()))
	}
	guest, err := sandbox.GuestArgv(r.layout.Binary, sandbox.NetRequest{Egress: hostedHostEgress(vocab.Tier(r.plan.Tier)), ProxyPort: r.proxyPort(), HostSocketDir: r.h.SockDir})
	if err != nil {
		return nil, err
	}
	return append(guest, inner...), nil
}

// hostedForwardsProxy reads the tier table (internal/sandbox's egress
// profiles, the same row the HOME side builds) for whether the model proxy
// is forwarded into the box.
func hostedForwardsProxy(t vocab.Tier) bool {
	p, err := sandbox.ResolveEgress(string(hostedHostEgress(t)))
	return err == nil && p.ForwardProxy
}

// hostedProxyFlags are the launcher flags that set the proxy base URL, in
// the order looked for on the inner launcher verb (read from the command
// tree: a capability of the verb, never its name).
var hostedProxyFlags = []string{"proxy", "proxy-url"}

// hostedWithProxyFlag inserts `--<flag> <url>` after the launcher verb when
// the verb has a proxy flag and the launch does not already name one.
func hostedWithProxyFlag(argv []string, baseURL string) []string {
	if len(argv) < 2 {
		return argv
	}
	cmd, _, err := newRootCmd().Find([]string{argv[1]})
	if err != nil || cmd == nil || !cmd.HasParent() {
		return argv
	}
	flag := ""
	for _, n := range hostedProxyFlags {
		if cmd.Flags().Lookup(n) != nil {
			flag = n
			break
		}
	}
	if flag == "" {
		return argv
	}
	for _, a := range argv[2:] {
		if a == "--" {
			break
		}
		for _, f := range hostedProxyFlags {
			if a == "--"+f || strings.HasPrefix(a, "--"+f+"=") {
				return argv
			}
		}
	}
	out := make([]string, 0, len(argv)+2)
	out = append(out, argv[0], argv[1], "--"+flag, baseURL)
	return append(out, argv[2:]...)
}

// proxyPort is the proxy port the inner launcher uses (the home proxy's
// number, forwarded in the box by the guest forwarder).
func (r *hostedRun) proxyPort() int {
	if i := strings.LastIndex(r.h.ProxyAddr, ":"); i >= 0 {
		if n, err := strconv.Atoi(r.h.ProxyAddr[i+1:]); err == nil {
			return n
		}
	}
	return 8820
}

// agentEnv is the agent's environment: the base, the sandbox marker, and
// under in_box_api_key custody the provider keys the launch holds.
func (r *hostedRun) agentEnv() map[string]string {
	env := r.boxEnv()
	env[sandboxEnvMarker] = "1"
	// The box's tier, so the in-box launcher says the tier's real model
	// route when it finds no proxy (live run 2, finding N2).
	env[sandbox.EnvEgress] = r.plan.Tier
	env[hostedRelayRedialEnv] = "1"
	for _, k := range r.plan.ForwardEnv {
		if v, ok := os.LookupEnv(k); ok && v != "" {
			env[k] = v
		}
	}
	if f := hostedCredEnvHook; f != nil {
		f(r.plan, env)
	}
	return env
}

// runBox prepares the box and runs the agent until it ends.
func (r *hostedRun) runBox(ctx context.Context) (int, error) {
	if err := r.prepare(ctx); err != nil {
		return 1, err
	}
	record, err := os.ReadFile(filepath.Join(r.h.SockDir, sandboxrelayd.BoxRecordName)) //nolint:gosec // G304: the host services' own per-run socket dir
	if err != nil {
		return 1, fmt.Errorf("read the box record: %w", err)
	}
	_ = r.rec.Apply(sandboxremote.EvStarted)
	// What a later re-adoption needs, none of it a secret (lane SBX-UPD).
	r.setExtra(map[string]string{sandboxremote.ExtraTier: r.plan.Tier, sandboxremote.ExtraTool: r.plan.Tool, sandboxremote.ExtraRoot: r.plan.Root})
	_ = hostedSaveRecord(r.plan.ObserverDir, r.rec)

	rctx, rcancel := context.WithCancel(ctx)
	defer rcancel()
	relayDone, relayUp := r.keepRelay(rctx, record)
	defer func() { rcancel(); <-relayDone }()
	// The agent starts only once the relay acknowledged that the box record
	// is written and its sockets listen (live run 2026-10-23, finding F2: the
	// agent started first and the in-box launch gate found no record).
	if err := waitFirstRelay(rctx, relayUp); err != nil {
		return 1, err
	}

	stopCheckpoints := r.checkpoints(rctx)
	defer stopCheckpoints()

	argv, err := r.innerArgv()
	if err != nil {
		return 1, err
	}
	restore := r.t.raw()
	defer restore()
	if r.vendor.GuestPTY {
		return r.runGuestPTY(rctx, argv)
	}
	return r.runVendorPTY(rctx, argv)
}

// hostedRelayReadyWait bounds how long one relay process may take to write
// the box record and listen (its ready), and how long the run waits for the
// first ready before it refuses to start the agent.
var hostedRelayReadyWait = 90 * time.Second

// hostedRelayRetryWait is the wait before the relay's next open after a
// failed one.
var hostedRelayRetryWait = func(attempt int) time.Duration { return time.Duration(min(attempt+1, 10)) * time.Second }

// waitFirstRelay waits for the run's first ready relay.
func waitFirstRelay(ctx context.Context, up <-chan error) error {
	select {
	case err := <-up:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(hostedRelayReadyWait):
		return fmt.Errorf("the capture relay in the box was not ready after %s, so the agent was not started (every checked action in the box would be blocked)", hostedRelayReadyWait)
	}
}

// waitRelayReady waits for one relay session's ready.
func waitRelayReady(ctx context.Context, h *relaymux.Host) error {
	select {
	case <-h.Ready():
		return nil
	case <-h.Done():
		return fmt.Errorf("the relay ended before it was ready: %w", h.Err())
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(hostedRelayReadyWait):
		return errors.New("the relay was not ready in time")
	}
}

// keepRelay runs the relay and re-opens it (a new process, a new secret, so
// new keys, within the run's own relay authentication) after a drop, while
// the run lives. The first ready relay is reported on the returned error
// channel (nil), or why none came up. A drop and a re-open are each said on
// the terminal (live run 2026-10-23, finding F7: the relay dropped mid-run
// on Modal and Vercel, the in-box hooks failed closed, and the terminal said
// nothing).
func (r *hostedRun) keepRelay(ctx context.Context, record []byte) (<-chan struct{}, <-chan error) {
	done := make(chan struct{})
	first := make(chan error, 1)
	go func() {
		defer close(done)
		up := false
		for attempt := 0; ctx.Err() == nil; attempt++ {
			h, p, err := r.startRelay(ctx, record)
			if err == nil {
				if err = waitRelayReady(ctx, h); err != nil {
					h.Close()
					_ = p.Kill(context.WithoutCancel(ctx))
					_ = p.Close()
				}
			}
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				msg := sandboxremote.Redact(err.Error(), r.cred.Secrets())
				r.rlog().line("relay attempt %d did not come up: %s", attempt+1, msg)
				if attempt > 20 {
					r.say("the capture relay could not be re-opened (%s); checked actions in the box stay blocked", msg)
					if !up {
						first <- fmt.Errorf("the capture relay did not come up: %s", msg)
					}
					return
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(hostedRelayRetryWait(attempt)):
				}
				continue
			}
			attempt = 0
			r.rlog().line("the relay is ready")
			if up {
				r.say("the capture relay is re-opened; checked actions in the box are checked again")
			} else {
				up = true
				first <- nil
			}
			select {
			case <-ctx.Done():
			case <-h.Done():
			}
			cause := h.Err()
			h.Close()
			// The old relay process is ended before a new one takes the
			// sockets.
			_ = p.Kill(context.WithoutCancel(ctx))
			_ = p.Close()
			r.rlog().flush()
			if ctx.Err() == nil {
				why := "the vendor's stream ended"
				if cause != nil {
					why = sandboxremote.Redact(cause.Error(), r.cred.Secrets())
				}
				r.rlog().line("the relay dropped (%s); re-opening it", why)
				r.say("the capture relay to the box dropped (%s); checked actions in the box are blocked until it is re-opened, which Observer is doing now", why)
			}
		}
	}()
	return done, first
}

// checkpoints pulls transcripts home on the checkpoint timer.
func (r *hostedRun) checkpoints(ctx context.Context) func() {
	every := time.Duration(max(r.plan.CheckpointMinutes, 1)) * time.Minute
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-stop:
				return
			case <-t.C:
				r.pullAndIngest(ctx)
			}
		}
	}()
	return func() { close(stop); wg.Wait() }
}

// pullAndIngest pulls the transcripts and ingests them; a failure is said
// once on the terminal and never ends the run.
func (r *hostedRun) pullAndIngest(ctx context.Context) {
	res, err := hostedPullTranscripts(ctx, r.client, r.rec.VendorID, r.plan, r.layout)
	if err != nil || len(res.Pulled) == 0 {
		return
	}
	ingest, closeDB, err := r.ingest(ctx)
	if err != nil {
		return
	}
	defer closeDB()
	_, _ = ingest(ctx, r.plan.Tool, r.plan.RunID, res.Pulled)
}

// runVendorPTY runs the agent on the vendor's own PTY (a documented
// resize), re-attaching by pid after a dropped stream where the vendor
// documents it.
func (r *hostedRun) runVendorPTY(ctx context.Context, argv []string) (int, error) {
	rows, cols := r.t.size()
	p, err := r.client.Exec(ctx, r.rec.VendorID, sandboxremote.ExecSpec{Argv: argv, Env: r.agentEnv(), Cwd: r.layout.Workspace, PTY: true, Rows: rows, Cols: cols, Stdin: true})
	if err != nil {
		return 1, fmt.Errorf("start the agent: %w", err)
	}
	r.recordPID(p.PID())
	var mu sync.Mutex
	cur := p
	current := func() sandboxremote.Process { mu.Lock(); defer mu.Unlock(); return cur }
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := r.t.in.Read(buf)
			if n > 0 {
				_, _ = current().Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		for range r.t.resized {
			rr, cc := r.t.size()
			_ = current().Resize(ctx, rr, cc)
		}
	}()
	type ended struct {
		code int
		err  error
	}
	for {
		// The copy and the wait run beside the stop channel (as runGuestPTY
		// does): SIGHUP or SIGTERM acts at once, even while the agent's
		// stream is open, so the box is torn down rather than left to its
		// timeout (the SBX-P7 merge's audit finding 2).
		cp := current()
		done := make(chan ended, 1)
		go func() {
			_, _ = io.Copy(r.t.out, cp)
			code, werr := cp.Wait(ctx)
			done <- ended{code, werr}
		}()
		var res ended
		select {
		case res = <-done:
		case reason := <-r.t.stopped:
			_ = cp.Kill(context.WithoutCancel(ctx))
			_ = cp.Close()
			return 129, fmt.Errorf("stopped (%s)", reason)
		}
		code, werr := res.code, res.err
		if werr == nil {
			return code, nil
		}
		select {
		case reason := <-r.t.stopped:
			_ = cp.Kill(context.WithoutCancel(ctx))
			return 129, fmt.Errorf("stopped (%s)", reason)
		default:
		}
		if !r.vendor.Reattach {
			r.say("the connection to the box was cut and %s documents no reattach: the run ends; resume the agent's session to continue", r.vendor.Name)
			return 1, nil
		}
		np, rerr := r.client.Reattach(ctx, r.rec.VendorID, current().PID())
		if rerr != nil {
			r.say("the connection to the box was cut and could not be re-attached: the run ends; resume the agent's session to continue")
			return 1, nil
		}
		mu.Lock()
		cur = np
		mu.Unlock()
		r.recordPID(np.PID())
		r.say("re-attached to the box (the scrollback before the cut is not replayed)")
	}
}

// setExtra merges keys into the run record's Extra (saved by the caller).
func (r *hostedRun) setExtra(kv map[string]string) {
	if r.rec.Extra == nil {
		r.rec.Extra = map[string]string{}
	}
	for k, v := range kv {
		if v != "" {
			r.rec.Extra[k] = v
		}
	}
}

// recordPID keeps the agent's vendor pid in the run's record, so a later
// `observer sandbox hosted adopt` can re-attach after the helper is gone.
func (r *hostedRun) recordPID(pid string) {
	if r.rec.Extra == nil {
		r.rec.Extra = map[string]string{}
	}
	r.rec.Extra["pty_pid"] = pid
	_ = hostedSaveRecord(r.plan.ObserverDir, r.rec)
}

// hostedTermConn is the helper's terminal as the mux's PTY end.
type hostedTermConn struct {
	in  io.Reader
	out io.Writer
}

func (c hostedTermConn) Read(b []byte) (int, error)  { return c.in.Read(b) }
func (c hostedTermConn) Write(b []byte) (int, error) { return c.out.Write(b) }
func (c hostedTermConn) Close() error                { return nil }

// runGuestPTY runs the agent on a PTY the guest helper owns (no documented
// vendor resize): the terminal and its sizes cross the mux.
func (r *hostedRun) runGuestPTY(ctx context.Context, argv []string) (int, error) {
	secret, sp, err := r.uploadSecret(ctx, "pty."+strconv.FormatInt(r.now().UnixNano(), 36))
	if err != nil {
		return 1, err
	}
	rows, cols := r.t.size()
	head := []string{
		r.layout.Binary, "sandbox-guest", relayStdioFlag, "--run", r.plan.RunID, "--secret-file", sp,
		"--pty", "--rows", strconv.Itoa(int(rows)), "--cols", strconv.Itoa(int(cols)),
	}
	keep := hostedGuestReattachOn(r.vendor)
	if keep {
		// The guest helper keeps the agent for a re-adoption when this
		// helper goes (lane SBX-UPD; the vendor keeping the process is a
		// live check, REM-13, so every row holds the flag false for now).
		// The keeper's own key comes home over the mux below and is kept
		// beside the run's record, deleted with it.
		head = append(head, guestKeepFlag)
		r.setExtra(map[string]string{sandboxremote.ExtraGuestAttach: "1"})
		r.rec.SecretFiles = append(r.rec.SecretFiles, hostedKeeperKeyPath(r.plan.ObserverDir, r.plan.RunID))
		_ = hostedSaveRecord(r.plan.ObserverDir, r.rec)
	}
	full := append(append(head, "--"), argv...)
	env := r.agentEnv()
	p, err := r.client.Exec(ctx, r.rec.VendorID, sandboxremote.ExecSpec{Argv: full, Env: env, Cwd: r.layout.Workspace, Stdin: true})
	if err != nil {
		return 1, fmt.Errorf("start the agent: %w", err)
	}
	defer p.Close()
	hopts := relaymux.HostOptions{
		Options: relaymux.Options{RunID: r.plan.RunID, Secret: secret}, Rand: rand.Reader,
		Kinds: map[string]bool{}, PTY: hostedTermConn{in: r.t.in, out: r.t.out},
		Dial: func(context.Context, string) (io.ReadWriteCloser, error) {
			return nil, errors.New("no connections on the PTY stream")
		},
	}
	if keep {
		observerDir, runID := r.plan.ObserverDir, r.plan.RunID
		hopts.KeeperKey = func(key []byte) {
			if err := hostedSaveKeeperKey(observerDir, runID, key); err != nil {
				slog.Default().Warn("sandbox: the guest PTY keeper's key could not be kept, so the run cannot be re-attached", "run", runID, "err", err)
			}
		}
	}
	h, err := relaymux.ServeHost(ctx, muxConn(p), hopts)
	if err != nil {
		_ = p.Kill(context.WithoutCancel(ctx))
		return 1, fmt.Errorf("the PTY handshake: %w", err)
	}
	defer h.Close()
	// The mux the terminal's resizes go to: the first stream's, then an
	// in-run reattach's (lane LEFT-SBX).
	var curMux atomic.Pointer[relaymux.Host]
	curMux.Store(h)
	go func() {
		for range r.t.resized {
			rr, cc := r.t.size()
			_ = curMux.Load().Resize(rr, cc)
		}
	}()
	waited := make(chan struct{})
	var code int
	var werr error
	go func() {
		code, werr = p.Wait(ctx)
		close(waited)
	}()
	select {
	case <-waited:
	case reason := <-r.t.stopped:
		_ = p.Kill(context.WithoutCancel(ctx))
		return 129, fmt.Errorf("stopped (%s)", reason)
	}
	if werr != nil {
		// In-run reattach (lane LEFT-SBX): a keeping guest helper still
		// holds the agent, so the terminal re-opens over a new exec with the
		// keeper-only key; held dark with GuestReattach until REM-13.
		if keep {
			// The first stream's mux is closed before a new one starts
			// (the LEFT-SBX merge, audit finding 8), so two muxes never
			// read the terminal's input; its deferred Close is a no-op.
			h.Close()
			if code, ok := r.reattachInRun(ctx, curMux.Store); ok {
				return code, nil
			}
		}
		r.say("the connection to the box was cut and %s documents no reattach: the run ends; resume the agent's session to continue", r.vendor.Name)
		return 1, nil
	}
	return code, nil
}

// hostedInRunReattachTries and hostedInRunReattachWait bound an in-run
// reattach: the keeper refuses an attach while it still sees the old home
// stream (no takeover), so a refusal is retried after a wait; variables for
// tests.
var (
	hostedInRunReattachTries = 3
	hostedInRunReattachWait  = 2 * time.Second
)

// hostedInRunAttach attaches the run's terminal to the agent its guest
// helper keeps (attachKeptPTY); a variable so a test can stand in for the
// vendor.
var hostedInRunAttach = func(ctx context.Context, r *hostedRun, key []byte, setMux func(*relaymux.Host)) (int, error) {
	return r.attachKeptPTY(ctx, hostedTermConn{in: r.t.in, out: r.t.out}, key, setMux)
}

// reattachInRun re-opens a cut run's terminal on the agent its guest
// helper keeps (lane LEFT-SBX, Modal and Vercel; GuestReattach, dark until
// REM-13): the keeper-only key kept at home authenticates a new
// `sandbox-guest attach` exec, which the keeper refuses while it still sees
// the old home stream (retried, bounded). ok is false when no attach took,
// and the run then ends as before.
func (r *hostedRun) reattachInRun(ctx context.Context, setMux func(*relaymux.Host)) (int, bool) {
	key, err := hostedReadKeeperKey(r.plan.ObserverDir, r.plan.RunID)
	if err != nil {
		r.say("the connection to the box was cut and the run's PTY keeper key cannot be read (%v), so the terminal cannot re-attach", err)
		return 0, false
	}
	for i := 0; i < hostedInRunReattachTries; i++ {
		if ctx.Err() != nil {
			return 0, false
		}
		r.say("the connection to the box was cut; re-attaching this terminal to the kept agent (attempt %d of %d)", i+1, hostedInRunReattachTries)
		code, err := hostedInRunAttach(ctx, r, key, setMux)
		if err == nil && code != sandboxHelperFailCode {
			return code, true
		}
		select {
		case <-ctx.Done():
			return 0, false
		case <-time.After(hostedInRunReattachWait):
		}
	}
	return 0, false
}

// Teardown deadlines (the LEFT-SBX merge, audit finding 2): the pull and
// the staged diff share hostedTeardownPullTimeout, the in-box database
// export has its own bounded hostedTeardownExportTimeout, and the vendor
// delete runs on a fresh context with hostedTeardownDeleteTimeout, so a
// slow pull or export can never use up the delete's time and leave a box
// billing until the vendor's own timeout. Variables for tests.
var (
	hostedTeardownPullTimeout   = 5 * time.Minute
	hostedTeardownExportTimeout = 3 * time.Minute
	hostedTeardownDeleteTimeout = 2 * time.Minute
)

// hostedTeardownExport is the teardown's in-box database export step; a
// variable so a test can stand in a slow export.
var hostedTeardownExport = func(ctx context.Context, r *hostedRun) { r.exportBoxDatabases(ctx) }

// teardown pulls the transcripts, saves the box's staged diff home, deletes
// the box and removes the record only after the vendor confirms.
func (r *hostedRun) teardown(ctx context.Context) {
	if r.rec.State == sandboxremote.StateRunning || r.rec.State == sandboxremote.StateCreated {
		_ = r.rec.Apply(sandboxremote.EvPullBegin)
		_ = hostedSaveRecord(r.plan.ObserverDir, r.rec)
		pctx, pcancel := context.WithTimeout(ctx, hostedTeardownPullTimeout)
		r.pullAndIngest(pctx)
		r.saveStagedDiff(pctx)
		pcancel()
		// The in-box database export (lane LEFT-SBX): consistent copies of
		// the tool's SQLite stores, pulled before the box is deleted, under
		// its own deadline; only when [terminal.sandbox.hosted].db_export
		// is on (opt-in, ruling P-141).
		if r.plan.DBExport {
			ectx, ecancel := context.WithTimeout(ctx, hostedTeardownExportTimeout)
			hostedTeardownExport(ectx, r)
			ecancel()
		}
	}
	// Earlier runs' exported copies past the workspace retention are swept
	// (ruling P-141), whether or not this run exported.
	if n, err := hostedSweepDBExports(r.plan.ObserverDir, r.plan.RunID, r.now(), r.plan.RetentionDays); n > 0 || err != nil {
		slog.Default().Info("sandbox: swept hosted database copies past the workspace retention", "removed", n, "err", err)
	}
	_ = r.rec.Apply(sandboxremote.EvDeleteSent)
	_ = hostedSaveRecord(r.plan.ObserverDir, r.rec)
	dctx, dcancel := context.WithTimeout(context.WithoutCancel(ctx), hostedTeardownDeleteTimeout)
	defer dcancel()
	if err := hostedDeleteConfirmed(dctx, r.client, r.rec.VendorID); err != nil {
		_ = r.rec.Apply(sandboxremote.EvDeleteFailed)
		r.rec.LastError = sandboxremote.Redact(err.Error(), r.cred.Secrets())
		_ = hostedSaveRecord(r.plan.ObserverDir, r.rec)
		r.say("the box %s could not be deleted (%s); it stops by itself at its timeout, and Terminals > Settings > Hosted sandboxes lists it", r.rec.VendorID, r.rec.LastError)
		return
	}
	_ = r.rec.Apply(sandboxremote.EvDeleteConfirm)
	_ = hostedRemoveRecord(r.plan.ObserverDir, r.rec)
	r.settle()
	r.say("the %s box was deleted (confirmed by %s)", r.vendor.Name, r.vendor.Name)
}

// hostedMaxDiff caps the staged diff saved home.
const hostedMaxDiff = 16 << 20

// hostedStageScript stages every change in the workspace; it exits
// hostedStageNoGit when the box has no git.
const hostedStageScript = `command -v git >/dev/null 2>&1 || exit 3; git add -A 2>&1`

// hostedStageNoGit is hostedStageScript's exit code for a box without git.
const hostedStageNoGit = 3

// saveStagedDiff runs the guest staged-diff one-shot in the box and saves
// its output home owner-only; it is never applied (untrusted input). A diff
// that cannot be saved is never dropped silently (live run 2, finding F-A):
// the reason is said on the terminal and kept on the run record.
func (r *hostedRun) saveStagedDiff(ctx context.Context) {
	out, code, err := hostedExecOutputIn(ctx, r.client, r.rec.VendorID, sandboxremote.ExecSpec{
		Cwd: r.layout.Workspace, Argv: []string{"sh", "-c", hostedStageScript}, Env: r.boxEnv(),
	}, 64<<10)
	switch {
	case err != nil:
		r.diffNotSaved("staging the changes failed: %v", err)
		return
	case code == hostedStageNoGit:
		r.diffNotSaved("the box has no git")
		return
	case code != 0:
		r.diffNotSaved("git add exited %d: %s", code, hostedFirstLine(out))
		return
	}
	// In the workspace: the guest one-shot runs git in its working directory
	// (live run 2026-10-23, finding F4: with no working directory it ran in
	// HOME, failed, and no diff came home).
	out, code, err = hostedExecOutputIn(ctx, r.client, r.rec.VendorID, sandboxremote.ExecSpec{
		Argv: []string{r.layout.Binary, "sandbox-guest", sandbox.GuestStagedDiff, sandbox.StagedDiffAll}, Env: r.boxEnv(), Cwd: r.layout.Workspace,
	}, hostedMaxDiff)
	switch {
	case err != nil:
		r.diffNotSaved("reading the staged diff failed: %v", err)
		return
	case code != 0 && code != sandbox.StagedDiffTruncatedExit:
		r.diffNotSaved("the staged diff exited %d: %s", code, hostedFirstLine(out))
		return
	case len(out) == 0:
		r.say("the box left the workspace unchanged (no diff to save)")
		return
	}
	dir := filepath.Join(hostedStateDir(r.plan.ObserverDir), "returns")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		r.diffNotSaved("the returns directory: %v", err)
		return
	}
	p := filepath.Join(dir, r.plan.RunID+".diff")
	if err := os.WriteFile(p, out, 0o600); err != nil {
		r.diffNotSaved("writing %s: %v", p, err)
		return
	}
	r.say("the box's changes are saved as a diff at %s (not applied; review, then `git apply` it in %s)", p, r.plan.Root)
}

// diffNotSaved says why the box's changes did not come home and keeps the
// reason on the run record.
func (r *hostedRun) diffNotSaved(format string, a ...any) {
	why := sandboxremote.Redact(fmt.Sprintf(format, a...), r.cred.Secrets())
	r.rec.DiffError = why
	_ = hostedSaveRecord(r.plan.ObserverDir, r.rec)
	r.say("the box's changes were NOT saved as a diff (%s); the box is deleted next, so they are lost unless the agent's session pushed them", why)
}

// hostedFirstLine is the first non-empty line of a box's output, capped.
func hostedFirstLine(b []byte) string {
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			if len(l) > 300 {
				l = l[:300]
			}
			return l
		}
	}
	return "no output"
}

// hostedStopWait bounds how long a forced delete waits for a live helper's
// own teardown.
var hostedStopWait = 2 * time.Minute

// hostedStopHelper ends a live run's helper for `observer sandbox hosted
// delete --force`: SIGTERM, whose stop path ends the agent, pulls the
// transcripts, saves the diff and deletes the box, then a bounded wait for
// the helper to exit. A pid that is not a live helper is left alone.
var hostedStopHelper = func(pid string) error {
	n, err := strconv.Atoi(pid)
	if err != nil || n <= 1 {
		return fmt.Errorf("the recorded helper pid %q is not a process id", pid)
	}
	if !hostedHelperAlive(pid) {
		return nil
	}
	if err := unix.Kill(n, unix.SIGTERM); err != nil {
		return err
	}
	for deadline := time.Now().Add(hostedStopWait); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		if !hostedHelperAlive(pid) {
			return nil
		}
	}
	return fmt.Errorf("the helper (pid %s) did not exit within %s", pid, hostedStopWait)
}

// hostedHelperAlive reports whether pid is a live sandbox-hosted-host helper
// (its /proc cmdline names the verb, so a reused pid does not count).
var hostedHelperAlive = func(pid string) bool {
	if _, err := strconv.Atoi(pid); err != nil {
		return false
	}
	b, err := os.ReadFile(filepath.Join("/proc", pid, "cmdline")) //nolint:gosec // G304: a numeric pid under /proc
	return err == nil && strings.Contains(string(b), hostedHostVerb)
}

// stderrSink is the relay process's stderr writer (nil without a log, so
// the vendor discards stderr as before).
func (l *hostedRelayLog) stderrSink() io.Writer {
	if l == nil {
		return nil
	}
	return l
}
