package sandboxopenshell

import (
	"encoding/json"
	"regexp"
	"strings"
)

// engine.go is the container engine's identity check (ledger row OSH-48,
// adversarial row A9: "a socket whose daemon identity changed since first
// use"). The engine's own ID (`docker info --format '{{json .ID}}'`) is
// recorded the first time the row uses an engine; a later probe that finds
// another ID behind the engine the launch drives is refused with a closed
// reason that names how to accept the new engine. The ID belongs to the
// engine, not to the socket path, so a symlink or a second spelling of the
// same socket (lane OC, OC-A6) answers the same ID and stays accepted.
// The ID is what the engine reports about itself: a substitute engine set
// up to repeat the recorded ID is not caught (the docker group is
// root-equivalent; the row guards against an engine replaced or swapped
// without the user noticing, not one built to impersonate).

// EngineRecordFile is the record's name under the row's state dir.
const EngineRecordFile = "engine-id.json"

// EngineInfoArgv is the docker argv (without the program) that reads the
// engine's ID.
func EngineInfoArgv() []string { return []string{"info", "--format", "{{json .ID}}"} }

// engineIDRE is the shape of an engine ID: Docker 28's twelve groups of
// four base32 characters joined by colons, Docker 29's UUID, or another
// short token of letters, digits, colons and hyphens.
var engineIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:-]{7,127}$`)

// ParseEngineID reads the engine ID from the docker info answer (a JSON
// string); ok is false when the answer is not one, or not an ID's shape.
func ParseEngineID(out string) (string, bool) {
	var id string
	if json.Unmarshal([]byte(strings.TrimSpace(out)), &id) != nil || !engineIDRE.MatchString(id) {
		return "", false
	}
	return id, true
}

// EngineRecord is the row's record of the engine it first used.
type EngineRecord struct {
	// EngineID is the engine's ID.
	EngineID string `json:"engine_id"`
	// FirstSeen is when it was recorded (Unix seconds).
	FirstSeen int64 `json:"first_seen"`
}

// ParseEngineRecord reads a record file; ok is false for anything that is
// not a record with a well-formed ID.
func ParseEngineRecord(b []byte) (EngineRecord, bool) {
	var r EngineRecord
	if json.Unmarshal(b, &r) != nil || !engineIDRE.MatchString(r.EngineID) {
		return EngineRecord{}, false
	}
	return r, true
}

// EngineFacts are what probe row P8e reads.
type EngineFacts struct {
	// ID is the engine ID the launch's engine answered ("" when not read).
	ID string
	// Detail is the first line of docker's error output when not read.
	Detail string
	// Record is the row's state: EngineRecordAbsent, EngineRecordRead or
	// EngineRecordUnreadable.
	Record string
	// Recorded is the recorded ID (Record EngineRecordRead).
	Recorded string
	// RecordPath is the record file (named in a reason).
	RecordPath string
}

// The closed EngineFacts.Record vocabulary.
const (
	// EngineRecordAbsent: no record yet (the first use; the driver
	// records the ID it read).
	EngineRecordAbsent = "absent"
	// EngineRecordRead: a record with a well-formed ID.
	EngineRecordRead = "read"
	// EngineRecordUnreadable: a record file that cannot be read or does
	// not parse (never overwritten: the user removes it to accept).
	EngineRecordUnreadable = "unreadable"
)

// The engine verdicts (probe row P8e).
const (
	// VerdictEngineUnread: the engine's ID could not be read.
	VerdictEngineUnread = "docker_engine_id_unread"
	// VerdictEngineRecordUnreadable: the row's engine record cannot be
	// read, so the engine cannot be compared with the one first used.
	VerdictEngineRecordUnreadable = "docker_engine_record_unreadable"
	// VerdictEngineChanged: the engine behind the launch's socket is not
	// the one the row first used.
	VerdictEngineChanged = "docker_engine_changed"
)

// engineRule is one row of the engine table, walked top-down.
type engineRule struct {
	id      string
	verdict string
	fails   func(f EngineFacts) bool
	reason  func(f EngineFacts) string
}

// acceptRemedy names how to accept a new engine.
func acceptRemedy(f EngineFacts) string {
	return "if the change is intended (Docker reinstalled, or the engine moved), remove " + quoteOr(f.RecordPath, "the row's "+EngineRecordFile) + " and the next probe records the new engine; otherwise point DOCKER_HOST (or the default socket) back at the engine the row first used"
}

// engineRules is probe row P8e's table; an engine with no record yet (the
// first use) and one that matches the record pass.
var engineRules = []engineRule{
	{"E1 id not read", VerdictEngineUnread, func(f EngineFacts) bool { return f.ID == "" }, func(f EngineFacts) string {
		return "could not read the Docker engine's ID (`docker info`), so the engine cannot be compared with the one this row first used" + detailSuffix(f.Detail)
	}},
	{"E2 record unreadable", VerdictEngineRecordUnreadable, func(f EngineFacts) bool { return f.Record == EngineRecordUnreadable }, func(f EngineFacts) string {
		return "the record of the Docker engine this row first used (" + quoteOr(f.RecordPath, EngineRecordFile) + ") cannot be read; remove it and the next probe records the engine it finds"
	}},
	{"E4 changed", VerdictEngineChanged, func(f EngineFacts) bool { return f.Record == EngineRecordRead && f.Recorded != f.ID }, func(f EngineFacts) string {
		return "the Docker engine this launch drives reports ID " + f.ID + ", not " + f.Recorded + ", the engine this row first used: another engine now answers at its socket; " + acceptRemedy(f)
	}},
}

// EngineVerdict is probe row P8e: "" when the engine is the one recorded,
// or no engine is recorded yet (the caller records it; EngineShouldRecord).
func EngineVerdict(f EngineFacts) (verdict, reason string) {
	for _, r := range engineRules {
		if r.fails(f) {
			return r.verdict, r.reason(f)
		}
	}
	return ok, ""
}

// EngineShouldRecord reports whether the driver records f.ID as the row's
// engine: the first use only (an ID was read and no record exists).
func EngineShouldRecord(f EngineFacts) bool {
	return f.ID != "" && f.Record == EngineRecordAbsent
}
