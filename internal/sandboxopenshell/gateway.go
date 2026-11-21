package sandboxopenshell

import (
	"fmt"
	"hash/fnv"
	"regexp"
	"strconv"
	"strings"
)

// gateway.go is the lifecycle state table of the managed local gateway
// (gateway_mode "managed", the default once lane O2 shipped: decision D2,
// OB-039). Observer runs a PRIVATE OpenShell gateway of its own: its own
// loopback port, its own config file under the row's state dir, its own
// CLI registry and PKI in a private runtime dir, never the user's gateway
// or its config. The driver (cmd/observer/terminal_sandbox_openshell_
// gateway*.go) gathers GatewayFacts and executes the action this table
// decides; this file runs nothing.
//
// The lifecycle follows the daemon restart runbook
// (docs/daemon-restart-runbook.md): the gateway is a transient systemd
// USER unit (the way the package's own user service starts it, O0-L2
// receipt 8a047f), not a child of the daemon, so a daemon stop, crash or
// restart never stops it and a live box keeps its gateway. The daemon
// stops it only when the managed mode is no longer wanted and no run
// holds it, and restarts it (an upgrade, a changed config, an unhealthy
// gateway) only when no run holds it: stopping a gateway under a live box
// would kill the box, and the reaper must never read a box "gone" because
// its gateway is restarting (it acts only on the exact not-found text from
// the pinned name and server, and the restart keeps both).

// GatewayAction is what the lifecycle table tells the driver to do.
type GatewayAction string

// The closed GatewayAction vocabulary.
const (
	// GatewayNone: nothing to do (ready, or not wanted and not running).
	GatewayNone GatewayAction = "none"
	// GatewayStart: start the private gateway (restore its PKI from the
	// keystore, render its config, start the unit, register it with the
	// private CLI registry, wait for it to authenticate).
	GatewayStart GatewayAction = "start"
	// GatewayRestart: stop the running unit and start it again (an
	// upgrade, a changed config, an unhealthy gateway); only with no live
	// run.
	GatewayRestart GatewayAction = "restart"
	// GatewayStop: stop the unit (managed mode no longer wanted, no live
	// run; or a start that overran its budget, whose Verdict then says so).
	GatewayStop GatewayAction = "stop"
	// GatewayFinish: the unit was launched and has not answered yet; look
	// again (briefly) whether it now listens and authenticates, register it
	// and record the finished start, or leave it starting (Verdict says
	// so) while its start budget lasts.
	GatewayFinish GatewayAction = "finish"
	// GatewayWait: leave it as it is for now (a live run holds it, or it
	// is still starting); the next reconcile decides again.
	GatewayWait GatewayAction = "wait"
	// GatewayRefuse: managed mode cannot run on this host; Verdict says
	// why. Nothing is started.
	GatewayRefuse GatewayAction = "refuse"
)

// The managed gateway verdicts (probe row PG). Every one refuses the row.
const (
	VerdictGatewayCustodyUnavailable = "gateway_cert_custody_unavailable"
	VerdictGatewayCustodyChanged     = "gateway_cert_custody_changed"
	VerdictGatewayNoDockerAccess     = "gateway_supervisor_no_docker_access"
	VerdictGatewayStateForeignFS     = "gateway_state_dir_foreign_fs"
	VerdictGatewayRuntimeDirUnsafe   = "gateway_runtime_dir_unsafe"
	VerdictGatewaySupervisorMissing  = "gateway_supervisor_missing"
	VerdictGatewayBinaryMissing      = "gateway_binary_missing"
	VerdictGatewayBinaryMismatch     = "gateway_binary_version_mismatch"
	VerdictGatewayBinaryUntested     = "gateway_binary_untested"
	VerdictGatewayUnitUnknown        = "gateway_unit_state_unknown"
	VerdictGatewayStarting           = "gateway_starting"
	VerdictGatewayUpgradePending     = "gateway_upgrade_pending"
	VerdictGatewayUnhealthy          = "gateway_unhealthy"
	VerdictGatewayStartFailed        = "gateway_start_failed"
	VerdictGatewayNotReady           = "gateway_not_ready"
	// VerdictGatewayUnitForeign: the unit of this install's name runs a
	// gateway from another state dir's config (a copied ~/.observer from
	// before the install-id binding, ledger row OSH-42), so it is never
	// stopped or restarted from here.
	VerdictGatewayUnitForeign = "gateway_unit_foreign"
)

// The custody values: where the held PKI and key-encryption key are.
const (
	// CustodyKeychain: the OS keychain (OS-backed encryption at rest).
	CustodyKeychain = "keychain"
	// CustodyOwnerFile: internal/keystore's hardened owner-only file store
	// under the row's state dir (gateway/keys), where no keychain is
	// usable. The files are 0600 in a 0700 dir and NOT encrypted: the PKI
	// (the CA key included) and the key-encryption key sit beside the
	// database that key protects, so against the local user they are no
	// stronger than the user's own OpenShell install (audit finding
	// O2-A1, decision OB-050).
	CustodyOwnerFile = "owner_file"
)

// CustodyFor maps a keystore backend name ("keychain", "file", ...) to a
// custody value ("" for a backend that offers none).
func CustodyFor(backend string) string {
	switch backend {
	case "keychain":
		return CustodyKeychain
	case "file":
		return CustodyOwnerFile
	}
	return ""
}

// UnitState is the private gateway unit's state as `systemctl --user
// is-active` prints it.
type UnitState string

// The closed UnitState vocabulary; the zero value is unknown.
const (
	UnitUnknown    UnitState = ""
	UnitActive     UnitState = "active"
	UnitActivating UnitState = "activating"
	UnitInactive   UnitState = "inactive"
	UnitFailed     UnitState = "failed"
)

// ParseUnitState reads the first line `systemctl --user is-active UNIT`
// prints. An unloaded transient unit prints "inactive" (exit 3); any text
// not in the vocabulary is unknown, never inactive.
func ParseUnitState(out string) UnitState {
	switch s := firstLine(strings.TrimSpace(out)); s {
	case "active", "reloading", "refreshing":
		return UnitActive
	case "activating":
		return UnitActivating
	case "inactive", "deactivating":
		return UnitInactive
	case "failed":
		return UnitFailed
	}
	return UnitUnknown
}

// running reports whether the unit holds (or is about to hold) a gateway.
func (u UnitState) running() bool { return u == UnitActive || u == UnitActivating }

// GatewayRecord is what the driver records about the gateway it started
// (the row's state dir, gateway/gateway.json). It holds no secret.
type GatewayRecord struct {
	// Name is the gateway's name in the private CLI registry (every box
	// command pins it, -g).
	Name string `json:"name"`
	// Unit is the transient user unit's name.
	Unit string `json:"unit"`
	// Port is the loopback port it listens on; it never changes while a
	// run is recorded (the pin is name plus server).
	Port int `json:"port"`
	// Server is the server the status answer names for it.
	Server string `json:"server"`
	// Version is the openshell-gateway version it was started from.
	Version string `json:"version"`
	// ConfigDigest is the digest of the config it was started with
	// (GatewayConfigDigest).
	ConfigDigest string `json:"config_digest"`
	// Starting: the unit was launched but the gateway has not yet
	// answered connected and authenticated (a first start pulls its
	// supervisor and sandbox images first; audit finding O2-V1). A record
	// written before this field existed reads false (a finished start).
	Starting bool `json:"starting,omitempty"`
	// StartedAt is when the unit was launched (unix seconds).
	StartedAt int64 `json:"started_at,omitempty"`
	// DockerHost is the DOCKER_HOST the unit was started with ("" for
	// none). A process that does not own the engine endpoint (a CLI
	// launch while the daemon runs the gateway) takes it from here, never
	// from its own environment, so two processes whose DOCKER_HOST differs
	// never restart an idle gateway back and forth (audit finding O2-W4).
	DockerHost string `json:"docker_host,omitempty"`
	// SandboxLabel is the Docker sandbox namespace the gateway was started
	// with ("" for a record written before it was set: the driver default;
	// SandboxLabelFor keeps it while a run is recorded, finding OC2-A5).
	SandboxLabel string `json:"sandbox_label,omitempty"`
}

// DefaultFirstStartBudget is how long a launched gateway may take to
// answer before its start counts as failed (seconds): long enough for a
// first image pull over a slow link (audit finding O2-V1).
const DefaultFirstStartBudget = 20 * 60

// GatewayFailedRetries is how many times the driver starts a failed unit
// again on its own before row G14a holds it for the user (audit finding
// O2-W2): a user manager that came up at boot before the system Docker
// engine, a transient failure, is retried; a unit that keeps failing is
// not started on every pass.
const GatewayFailedRetries = 3

// GatewayFailedRetryWait is the wait (seconds) before the automatic retry
// after retries earlier ones: one minute, doubling (1, 2, 4 minutes).
func GatewayFailedRetryWait(retries int) int64 {
	if retries < 0 {
		retries = 0
	}
	return int64(60) << min(retries, 8)
}

// GatewayFacts is everything the lifecycle table reads. The driver
// gathers them.
type GatewayFacts struct {
	// Wanted: the row is listed and its effective gateway mode is managed.
	Wanted bool
	// Custody is the custody the keystore offers this session
	// (CustodyKeychain, CustodyOwnerFile; any other value, "" included,
	// is no usable custody).
	Custody string
	// CustodyPinned is the custody the held record set was saved under
	// ("" when none was ever saved): a session whose keystore offers
	// another one is refused, never handed a fresh PKI (audit finding
	// O2-A5).
	CustodyPinned string
	// DockerAccess: the systemd user manager (whose process the gateway
	// unit becomes) can reach the Docker engine: its groups include the
	// docker socket's group, and no docker context it cannot follow is in
	// use (TriUnknown when it could not be read; only TriNo refuses).
	DockerAccess Tri
	// DockerAccessDetail names what is wrong for a reason.
	DockerAccessDetail string
	// StateDirLocal: the row's state dir (the gateway's config and
	// database) is on a local filesystem (GatewayStateFS).
	StateDirLocal Tri
	// StateDirFS names the state dir's filesystem for a reason.
	StateDirFS string
	// RuntimeDirPrivate: the private runtime dir (the PKI and the CLI
	// registry while the gateway runs) is a RAM filesystem owned by this
	// user with mode 0700 (GatewayRuntimeFS).
	RuntimeDirPrivate Tri
	// RuntimeDirDetail names what is wrong with it for a reason.
	RuntimeDirDetail string
	// Supervisor: `systemd-run --user` can start a transient user unit
	// (a running user manager).
	Supervisor bool
	// BinaryFound: openshell-gateway resolved to an absolute path.
	BinaryFound bool
	// BinaryUntrusted is BinaryTrust's reason when openshell-gateway or
	// the openshell CLI was found only where the user or a box could
	// replace it ("" otherwise; row G11t, ledger row OSH-44).
	BinaryUntrusted string
	// BinaryVersion and CLIVersion are the raw --version answers.
	BinaryVersion, CLIVersion string
	// Unit is the unit's state.
	Unit UnitState
	// Record is the recorded gateway (nil: none recorded).
	Record *GatewayRecord
	// WantConfigDigest is the digest of the config this install would
	// start the gateway with now.
	WantConfigDigest string
	// LiveRuns counts the runs a host helper holds (or too young to
	// judge): a gateway they use is never stopped or restarted.
	LiveRuns int
	// RecordedRuns counts every run dir that pins this gateway, abandoned
	// ones included: a gateway is never stopped while one exists, because
	// an abandoned run's box survives its gateway and only the reaper,
	// through that gateway, removes it (audit finding O2-A4, O0-A7).
	RecordedRuns int
	// UnreadableRunDirs names the run dirs whose plan this build cannot
	// read, with their ages (tracker F-032): row G2 names the ones that
	// hold the gateway, since the reaper never removes them. Names and
	// ages only, never a dir's contents.
	UnreadableRunDirs []RunDirNote
	// Healthy: the gateway answered connected and authenticated from the
	// recorded server under the recorded name (TriUnknown: not asked).
	Healthy Tri
	// CustodyDetail says why no custody is offered (row G6), for example a
	// locked keychain (audit finding O2-V3).
	CustodyDetail string
	// Now is the current time (unix seconds) and FirstStartBudget the
	// start budget (seconds; 0 is DefaultFirstStartBudget), for a start
	// still under way (rows G14b and G14c).
	Now, FirstStartBudget int64
	// FailedRetries counts the automatic retries the driver already made
	// of a failed unit in this failure episode, and FailedSince is when
	// the failure was first seen or the last retry made (unix seconds; 0
	// unknown, so no retry is due yet): rows G14r and G14a (audit finding
	// O2-W2).
	FailedRetries int
	FailedSince   int64
}

// GatewayDecision is the lifecycle table's answer: Action is what the
// driver does now, Verdict "" means the row may use the gateway once the
// action is done (the driver re-checks after it), and Rule names the row.
type GatewayDecision struct {
	Rule    string
	Action  GatewayAction
	Verdict string
	Reason  string
	// FailedRetry: the start is an automatic retry of a failed unit (row
	// G14r), which the driver counts before it starts.
	FailedRetry bool
}

// Ready reports whether the gateway may be used as it is now.
func (d GatewayDecision) Ready() bool { return d.Action == GatewayNone && d.Verdict == "" }

// gatewayCheck is the parsed state the rows read.
type gatewayCheck struct {
	f            GatewayFacts
	bin, cli     Version
	binOK, cliOK bool
	versionMoved bool
	configMoved  bool
}

// gatewayRule is one row of the lifecycle table.
type gatewayRule struct {
	id     string
	match  func(c gatewayCheck) bool
	decide func(c gatewayCheck) GatewayDecision
}

// gatewayRules is the lifecycle table, walked top-down; the first matching
// row wins. The refusals come before any action, so a host that cannot run
// a managed gateway safely never starts one.
var gatewayRules = []gatewayRule{
	{"G1 not wanted, idle, no run recorded: stop it", func(c gatewayCheck) bool {
		return !c.f.Wanted && c.f.Unit.running() && c.idle()
	}, func(gatewayCheck) GatewayDecision {
		return GatewayDecision{Action: GatewayStop}
	}},
	{"G2 not wanted, a run holds it or awaits its reap: leave it", func(c gatewayCheck) bool {
		return !c.f.Wanted && c.f.Unit.running()
	}, func(c gatewayCheck) GatewayDecision {
		return GatewayDecision{Action: GatewayWait, Reason: notWantedWaitReason(c.f)}
	}},
	{"G3 not wanted", func(c gatewayCheck) bool { return !c.f.Wanted }, func(gatewayCheck) GatewayDecision {
		return GatewayDecision{Action: GatewayNone}
	}},
	{"G4 state dir on a foreign filesystem", func(c gatewayCheck) bool { return c.f.StateDirLocal != TriYes }, func(c gatewayCheck) GatewayDecision {
		if c.f.StateDirLocal == TriNo {
			return refuse(VerdictGatewayStateForeignFS, "the managed gateway's state dir is on "+quoteOr(c.f.StateDirFS, "a foreign filesystem")+", not a local Linux filesystem (a DrvFs, 9p, FUSE or network mount, or a symbolic link to one, is refused: its owner and mode checks and the gateway's SQLite locking are not reliable there); set [terminal.sandbox.openshell].state_dir to a local path")
		}
		return refuse(VerdictGatewayStateForeignFS, "could not tell which filesystem the managed gateway's state dir is on, so it is refused")
	}},
	{"G5 runtime dir not private RAM", func(c gatewayCheck) bool { return c.f.RuntimeDirPrivate != TriYes }, func(c gatewayCheck) GatewayDecision {
		return refuse(VerdictGatewayRuntimeDirUnsafe, "while it runs, the managed gateway's certificates and keys are written only to a private RAM directory ($XDG_RUNTIME_DIR, a tmpfs owned by you with mode 0700), and that directory is not usable here"+detailSuffix(c.f.RuntimeDirDetail)+"; log in through a session that has a systemd user manager (or enable lingering)")
	}},
	{"G6 no usable custody for the PKI", func(c gatewayCheck) bool {
		return c.f.Custody != CustodyKeychain && c.f.Custody != CustodyOwnerFile
	}, func(c gatewayCheck) GatewayDecision {
		why := quoteOr(c.f.Custody, "not read")
		if c.f.CustodyDetail != "" {
			why = c.f.CustodyDetail
		}
		return refuse(VerdictGatewayCustodyUnavailable, "managed gateway mode keeps the private gateway's certificates and keys in the OS keychain, or where no keychain is usable in the keystore's owner-only file store, and neither is usable here ("+why+"); set gateway_mode = \"external\" to use your own gateway")
	}},
	{"G7 custody changed since the keys were saved", func(c gatewayCheck) bool {
		return c.f.CustodyPinned != "" && c.f.CustodyPinned != c.f.Custody
	}, func(c gatewayCheck) GatewayDecision {
		return refuse(VerdictGatewayCustodyChanged, "the private gateway's keys were saved in custody "+strconv.Quote(c.f.CustodyPinned)+" but this session's keystore offers "+quoteOr(c.f.Custody, "none")+"; Observer never makes a new PKI silently (live boxes and the gateway's database hold the old one). Use the session the keys were saved in, or, once no run uses the private gateway, start over by removing the keystore service "+GatewayKeystoreService+"'s records (in owner_file custody the files under <state dir>/gateway/keys) and the file <state dir>/gateway/custody")
	}},
	{"G8 no user unit supervisor", func(c gatewayCheck) bool { return !c.f.Supervisor }, func(gatewayCheck) GatewayDecision {
		return refuse(VerdictGatewaySupervisorMissing, "the managed gateway runs as a transient systemd user unit (so a daemon restart never stops it), and `systemd-run --user` cannot reach a user manager here; log in through a systemd session or run `loginctl enable-linger`")
	}},
	{"G9 the user manager cannot reach Docker", func(c gatewayCheck) bool { return c.f.DockerAccess == TriNo }, func(c gatewayCheck) GatewayDecision {
		return refuse(VerdictGatewayNoDockerAccess, "the private gateway runs under your systemd user manager, which cannot reach the Docker engine"+detailSuffix(c.f.DockerAccessDetail)+"; a user manager started before you joined the docker group keeps its old groups: log out of every session (or reboot) so it starts again")
	}},
	{"G10 idle gateway on a binary no longer usable: stop it", func(c gatewayCheck) bool {
		return c.f.Unit.running() && c.idle() && (!c.f.BinaryFound || c.f.BinaryUntrusted != "" || !c.pairUsable())
	}, func(gatewayCheck) GatewayDecision {
		return GatewayDecision{Action: GatewayStop}
	}},
	{"G11 gateway binary missing", func(c gatewayCheck) bool { return !c.f.BinaryFound }, func(gatewayCheck) GatewayDecision {
		return refuse(VerdictGatewayBinaryMissing, "openshell-gateway is not installed or not on PATH (install the OpenShell package; Observer never installs it)")
	}},
	{"G11t gateway binary untrusted", func(c gatewayCheck) bool { return c.f.BinaryUntrusted != "" }, func(c gatewayCheck) GatewayDecision {
		return refuse(VerdictBinaryUntrusted, c.f.BinaryUntrusted)
	}},
	{"G12 gateway and CLI versions differ", func(c gatewayCheck) bool {
		return !c.binOK || !c.cliOK || c.bin != c.cli
	}, func(c gatewayCheck) GatewayDecision {
		if !c.binOK || !c.cliOK {
			return refuse(VerdictGatewayBinaryMismatch, "could not read the version of openshell-gateway and the openshell CLI")
		}
		return refuse(VerdictGatewayBinaryMismatch, "openshell-gateway is "+c.bin.String()+" but the openshell CLI is "+c.cli.String()+"; upgrade both to the same version (the gateway, its supervisor and its sandbox image move together)")
	}},
	{"G13 gateway version untested", func(c gatewayCheck) bool { _, ok := testedRow(c.bin); return !ok }, func(c gatewayCheck) GatewayDecision {
		return refuse(VerdictGatewayBinaryUntested, "openshell-gateway "+c.bin.String()+" is not a tested version (tested: "+testedList()+")")
	}},
	{"G14 unit state not read", func(c gatewayCheck) bool { return c.f.Unit == UnitUnknown }, func(gatewayCheck) GatewayDecision {
		return refuse(VerdictGatewayUnitUnknown, "could not read the managed gateway unit's state from the systemd user manager")
	}},
	// G14r (audit finding O2-W2): a failed unit is started again on its
	// own a bounded number of times, each after a doubling wait (a user
	// manager that came up at boot before the system Docker engine is the
	// usual transient case); the start resets the failed state first.
	{"G14r the unit failed, an automatic retry is due: start it again", func(c gatewayCheck) bool {
		return c.f.Unit == UnitFailed && c.retryDue()
	}, func(c gatewayCheck) GatewayDecision {
		return GatewayDecision{Action: GatewayStart, FailedRetry: true, Reason: "Observer's private gateway unit failed; automatic retry " + strconv.Itoa(c.f.FailedRetries+1) + " of " + strconv.Itoa(GatewayFailedRetries)}
	}},
	// G14a (audit findings O2-V6, O2-W2): a unit that failed (a crash loop
	// that hit its start limit, which keeps it loaded as failed) is not
	// started again on every pass: it waits for its next automatic retry,
	// and once those are spent the user reads why and clears it.
	{"G14a the unit failed", func(c gatewayCheck) bool { return c.f.Unit == UnitFailed }, func(c gatewayCheck) GatewayDecision {
		unit := "the private gateway's unit"
		if c.f.Record != nil && c.f.Record.Unit != "" {
			unit = c.f.Record.Unit
		}
		if c.f.FailedRetries < GatewayFailedRetries {
			wait := GatewayFailedRetryWait(c.f.FailedRetries)
			if c.f.FailedSince > 0 {
				wait -= c.f.Now - c.f.FailedSince
			}
			return refuse(VerdictGatewayStartFailed, "Observer's private gateway unit failed; Observer starts it again on its own in about "+strconv.FormatInt(max(wait, 1), 10)+" s (automatic retry "+strconv.Itoa(c.f.FailedRetries+1)+" of "+strconv.Itoa(GatewayFailedRetries)+"); see `journalctl --user -u "+unit+"` for why, and `systemctl --user reset-failed "+unit+"` starts it on the next pass")
		}
		return refuse(VerdictGatewayStartFailed, "Observer's private gateway unit failed again after "+strconv.Itoa(GatewayFailedRetries)+" automatic retries (each start stops after the unit's start limit of five starts in two minutes); see `journalctl --user -u "+unit+"`, fix the cause, then run `systemctl --user reset-failed "+unit+"` (a reboot clears it too) and Observer starts it again")
	}},
	// G14b and G14c (audit finding O2-V1): a launched gateway that has not
	// answered yet is still starting (a first start pulls its images, which
	// a slow link stretches) until its start budget runs out; only then is
	// the start a failure, stopped and cleaned up.
	{"G14b launched, not answering yet, within its start budget: finish it", func(c gatewayCheck) bool {
		return c.f.Unit.running() && c.starting() && !c.overBudget()
	}, func(c gatewayCheck) GatewayDecision {
		return GatewayDecision{Action: GatewayFinish, Verdict: VerdictGatewayStarting, Reason: "Observer's private gateway is still starting (a first start pulls its supervisor and sandbox images, which a slow link stretches): launched " + strconv.FormatInt(c.f.Now-c.f.Record.StartedAt, 10) + " s ago, given up after " + strconv.FormatInt(c.budget()/60, 10) + " min"}
	}},
	{"G14c launched, still not answering after its start budget: stop it", func(c gatewayCheck) bool {
		return c.f.Unit.running() && c.starting()
	}, func(c gatewayCheck) GatewayDecision {
		return GatewayDecision{Action: GatewayStop, Verdict: VerdictGatewayStartFailed, Reason: "Observer's private gateway did not answer connected and authenticated within " + strconv.FormatInt(c.budget()/60, 10) + " min of its launch, so it was stopped and cleaned up; see `journalctl --user -u " + c.f.Record.Unit + "` (a Docker engine the user manager cannot reach, or images that cannot be pulled, are the usual causes); the next pass starts it again"}
	}},
	{"G15 not running: start it", func(c gatewayCheck) bool { return !c.f.Unit.running() }, func(gatewayCheck) GatewayDecision {
		return GatewayDecision{Action: GatewayStart}
	}},
	{"G16 running but started by no record: restart it", func(c gatewayCheck) bool {
		return c.f.Record == nil && c.f.LiveRuns == 0
	}, func(gatewayCheck) GatewayDecision {
		return GatewayDecision{Action: GatewayRestart}
	}},
	{"G17 new version, a run holds the old gateway: wait", func(c gatewayCheck) bool {
		return c.versionMoved && c.f.LiveRuns > 0
	}, func(c gatewayCheck) GatewayDecision {
		return GatewayDecision{Action: GatewayWait, Verdict: VerdictGatewayUpgradePending, Reason: "OpenShell was upgraded to " + c.bin.String() + " while the private gateway still runs " + recordVersion(c.f.Record) + "; it restarts on the new version (with its matching supervisor and sandbox images) once the " + strconv.Itoa(c.f.LiveRuns) + " live run(s) on it end, and new launches wait until then"}
	}},
	{"G18 new version or config, idle: restart it", func(c gatewayCheck) bool {
		return (c.versionMoved || c.configMoved) && c.f.LiveRuns == 0
	}, func(gatewayCheck) GatewayDecision {
		return GatewayDecision{Action: GatewayRestart}
	}},
	{"G19 starting", func(c gatewayCheck) bool { return c.f.Unit == UnitActivating }, func(gatewayCheck) GatewayDecision {
		return GatewayDecision{Action: GatewayWait, Verdict: VerdictGatewayStarting, Reason: "the private gateway is still starting (a unit that keeps failing stays failed after its start limit, five starts in two minutes, and row G14a then refuses)"}
	}},
	{"G20 unhealthy, idle: restart it", func(c gatewayCheck) bool {
		return c.f.Healthy == TriNo && c.f.LiveRuns == 0
	}, func(gatewayCheck) GatewayDecision {
		return GatewayDecision{Action: GatewayRestart}
	}},
	{"G21 unhealthy, a run holds it: leave it", func(c gatewayCheck) bool { return c.f.Healthy == TriNo }, func(c gatewayCheck) GatewayDecision {
		return GatewayDecision{Action: GatewayWait, Verdict: VerdictGatewayUnhealthy, Reason: "the private gateway does not answer connected and authenticated from its recorded server; it is not restarted while " + strconv.Itoa(c.f.LiveRuns) + " live run(s) hold it"}
	}},
	{"G22 health not read yet", func(c gatewayCheck) bool { return c.f.Healthy != TriYes }, func(gatewayCheck) GatewayDecision {
		return GatewayDecision{Action: GatewayWait, Verdict: VerdictGatewayNotReady, Reason: "the private gateway's health was not read yet"}
	}},
	{"G23 ready", func(gatewayCheck) bool { return true }, func(c gatewayCheck) GatewayDecision {
		if c.configMoved {
			// A changed config with a live run: keep the running gateway
			// (it still serves the run) and restart once the runs end.
			return GatewayDecision{Action: GatewayNone, Reason: "the private gateway's config changed; it restarts with it once no run holds it"}
		}
		return GatewayDecision{Action: GatewayNone}
	}},
}

// retryDue reports whether an automatic retry of a failed unit is left and
// its wait has passed (an unknown failure time is never due).
func (c gatewayCheck) retryDue() bool {
	return c.f.FailedRetries < GatewayFailedRetries && c.f.FailedSince > 0 && c.f.Now-c.f.FailedSince >= GatewayFailedRetryWait(c.f.FailedRetries)
}

// starting reports whether the recorded start has not finished yet.
func (c gatewayCheck) starting() bool { return c.f.Record != nil && c.f.Record.Starting }

// budget is the start budget in seconds.
func (c gatewayCheck) budget() int64 {
	if c.f.FirstStartBudget > 0 {
		return c.f.FirstStartBudget
	}
	return DefaultFirstStartBudget
}

// overBudget reports whether the recorded start has run past its budget
// (a start with no launch time is over it).
func (c gatewayCheck) overBudget() bool {
	return c.f.Record == nil || c.f.Record.StartedAt <= 0 || c.f.Now-c.f.Record.StartedAt > c.budget()
}

// idle reports whether no run uses the gateway, live or abandoned: the
// only state in which it may be stopped.
func (c gatewayCheck) idle() bool { return c.f.LiveRuns == 0 && c.f.RecordedRuns == 0 }

// pairUsable reports whether the installed gateway and CLI are a usable
// pair (readable, equal and tested).
func (c gatewayCheck) pairUsable() bool {
	if !c.binOK || !c.cliOK || c.bin != c.cli {
		return false
	}
	_, ok := testedRow(c.bin)
	return ok
}

// GatewayKeystoreService is the keystore service the managed gateway's
// custody uses (named in refusals).
const GatewayKeystoreService = "sbo-openshell-gateway-v1"

// refuse builds a refusal.
func refuse(verdict, reason string) GatewayDecision {
	return GatewayDecision{Action: GatewayRefuse, Verdict: verdict, Reason: reason}
}

// recordVersion renders a record's version for a reason.
func recordVersion(r *GatewayRecord) string {
	if r == nil || r.Version == "" {
		return "an unknown version"
	}
	return r.Version
}

// DecideGateway walks the lifecycle table.
func DecideGateway(f GatewayFacts) GatewayDecision {
	c := gatewayCheck{f: f}
	var err error
	c.bin, err = ParseVersion(f.BinaryVersion)
	c.binOK = err == nil
	c.cli, err = ParseVersion(f.CLIVersion)
	c.cliOK = err == nil
	if f.Record != nil {
		rv, err := ParseVersion(f.Record.Version)
		c.versionMoved = err != nil || rv != c.bin
		c.configMoved = f.Record.ConfigDigest != f.WantConfigDigest
	}
	for _, r := range gatewayRules {
		if r.match(c) {
			d := r.decide(c)
			d.Rule = r.id[:indexSpace(r.id)]
			return d
		}
	}
	return refuse(VerdictGatewayNotReady, "no lifecycle row matched")
}

// indexSpace is the length of a rule id's leading token.
func indexSpace(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' {
			return i
		}
	}
	return len(s)
}

// installIDRE is the shape of an install id this file names things after
// (hex, from the driver's openShellInstallID).
var installIDRE = regexp.MustCompile(`^[0-9a-f]{12,64}$`)

// GatewayIdentity is the private gateway's fixed names for one install.
type GatewayIdentity struct {
	// Name is its name in the private CLI registry.
	Name string
	// Unit is its transient user unit.
	Unit string
	// PreferredPort is the first loopback port tried.
	PreferredPort int
}

// The managed gateway's port range: a block above the package gateway's
// default (17670) and lane O0's private gateway (17690), so neither is
// ever taken by Observer's own.
const (
	GatewayPortBase  = 17700
	GatewayPortRange = 256
	// GatewayPortTries is how many ports from the preferred one a start
	// tries before it refuses.
	GatewayPortTries = 16
)

// IdentityFor returns the private gateway's names for an install id: a
// gateway name and a unit name that carry the id's first 12 hex digits
// (so two installs on one host never share one), and a preferred port in
// the managed block derived from the whole id.
func IdentityFor(installID string) (GatewayIdentity, error) {
	if !installIDRE.MatchString(installID) {
		return GatewayIdentity{}, fmt.Errorf("sandboxopenshell.IdentityFor: %q is not an install id", installID)
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(installID))
	short := installID[:12]
	return GatewayIdentity{
		Name:          "observer-" + short,
		Unit:          "observer-openshell-gateway-" + short + ".service",
		PreferredPort: GatewayPortBase + int(h.Sum32()%GatewayPortRange),
	}, nil
}

// PortCandidates returns the ports a start tries, in order: the recorded
// port alone when a run is recorded on it (the pin is name plus server, so
// the port never moves under a recorded run), else the recorded port (if
// any) then the preferred one and the next GatewayPortTries-1, wrapping
// inside the managed block.
func PortCandidates(id GatewayIdentity, recorded int, runRecorded bool) []int {
	if recorded > 0 && runRecorded {
		return []int{recorded}
	}
	var out []int
	seen := map[int]bool{}
	add := func(p int) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	if recorded > 0 {
		add(recorded)
	}
	start := id.PreferredPort - GatewayPortBase
	for i := 0; i < GatewayPortTries; i++ {
		add(GatewayPortBase + (start+i)%GatewayPortRange)
	}
	return out
}

// ServerFor is the server the private gateway's status answer names: its
// https loopback endpoint (it listens on 127.0.0.1 only).
func ServerFor(port int) string { return "https://127.0.0.1:" + strconv.Itoa(port) }
