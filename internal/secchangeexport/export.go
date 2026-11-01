package secchangeexport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/loc"
	"github.com/marmutapp/superbased-observer/internal/secchange"
)

// Spec is one pinned external format.
type Spec struct {
	Format  string
	Version string
	URL     string
	// Read is the date this build's mapping was checked against the spec.
	Read   string
	Status string
	// Draft is true while the spec is not explicitly final or stable; the
	// output then carries the experimental label.
	Draft bool
}

// The formats.
const (
	FormatAgentTrace = "agent-trace"
	FormatGitAI      = "git-ai"
)

// GitAINotesRef is the only ref the git-ai standard lets an authorship log
// live under (section 1.1).
const GitAINotesRef = "refs/notes/ai"

// Specs are the pins, one per format.
var Specs = map[string]Spec{
	FormatAgentTrace: {
		Format: FormatAgentTrace, Version: "0.1.0", URL: "https://agent-trace.dev/",
		Read: "2026-10-24",
		// Lane LEFT2-SEC item R-020 (2026-10-25): agent-trace.dev, its
		// schema and the cursor/agent-trace repository were again not
		// reachable from the build sandbox; the shape was re-checked against
		// a secondary summary of the schema (TestAgentTraceShapeAgainstTheSchemaSummary)
		// and stays experimental until the spec text is read.
		Status: "0.1.0-draft (status Proposal, January 2026); the spec text and its schema were not reachable from the build sandbox (2026-10-24 and 2026-10-25), so the shape follows public summaries of it (required version, a UUID id, an RFC 3339 timestamp, files; contributor type human, ai, mixed or unknown; optional vcs, tool, metadata)",
		Draft:  true,
	},
	FormatGitAI: {
		Format: FormatGitAI, Version: "authorship/3.0.0",
		URL:    "https://github.com/git-ai-project/git-ai/blob/main/specs/git_ai_standard_v3.0.0.md",
		Read:   "2026-10-24",
		Status: "Git AI Standard v3.0.0, versioned; section 3.2 calls only the key prefixes and the note structure stable and the ID lengths may change, with no explicit final status, so it is treated as a draft",
		Draft:  true,
	},
}

// Label is the experimental marker text.
const Label = "experimental"

// ToolName names the exporter in the outputs.
const ToolName = "superbased-observer"

// The refusals.
var (
	// ErrUnverified refuses a record whose envelope, key or binding does not
	// check out.
	ErrUnverified = errors.New("secchangeexport: the change record does not verify, so it is not exported")
	// ErrNotExportable refuses a verified record the format cannot carry
	// without inventing a field.
	ErrNotExportable = errors.New("secchangeexport: the record cannot be expressed in this format without inventing a field")
	// ErrFormat is an unknown format.
	ErrFormat = errors.New("secchangeexport: unknown format (agent-trace or git-ai)")
)

// Input is one record to export.
type Input struct {
	Envelope []byte
	Trust    secchange.TrustSet
	// Commit is what git says of the commit the record is bound to.
	Commit secchange.CommitFacts
	// Paths maps a changed file's path hash (internal/loc.PathHash: the
	// SHA-256 of its repository-relative path) to that path, from the
	// commit's own changed files. A file whose hash is not here stays out.
	Paths map[string]string
	// ToolVersion is this observer's version ("" for a development build).
	ToolVersion string
}

// verify checks the envelope and the binding.
func verify(in Input) (secchange.Verified, error) {
	env, err := secchange.ParseEnvelope(in.Envelope)
	if err != nil {
		return secchange.Verified{}, fmt.Errorf("%w: %s", ErrUnverified, secchange.RefusalCode(err))
	}
	v, err := secchange.Verify(env, in.Trust)
	if err != nil {
		return secchange.Verified{}, fmt.Errorf("%w: %s", ErrUnverified, secchange.RefusalCode(err))
	}
	if c := secchange.BindingRefusal(v.Record.Binding, in.Commit); c != "" {
		return secchange.Verified{}, fmt.Errorf("%w: %s", ErrUnverified, c)
	}
	return v, nil
}

// Export renders one verified record in format.
func Export(format string, in Input) ([]byte, error) {
	if _, ok := Specs[format]; !ok {
		return nil, ErrFormat
	}
	v, err := verify(in)
	if err != nil {
		return nil, err
	}
	switch format {
	case FormatAgentTrace:
		return agentTrace(v, in)
	default:
		return gitAI(v, in)
	}
}

// only returns the single value of a list, "" when it has none or several
// (a value the record does not tie to one file or session stays absent).
func only(xs []string) string {
	if len(xs) == 1 {
		return xs[0]
	}
	return ""
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// marshal is the outputs' one encoding: indented JSON, no HTML escaping,
// a trailing newline.
func marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func joinIDs(ids []string) string { return strings.Join(ids, ",") }

// PathHash is the record's path hash of a repository-relative path with
// forward slashes: internal/loc.PathHash, the one owner of that hash (audit
// finding F8). The export matches a commit's changed paths to the record's
// files with it.
func PathHash(rel string) string { return loc.PathHash("", rel) }
