package dashapi

import "context"

// Provenance is the AI change records card's seam (component
// security.provenance, security plan 7.10; lane sec-f2a), bound by the cmd
// layer to the same functions `observer security provenance` runs, so the
// dashboard and the CLI share one consent seam. nil when the security
// module is compiled out. Each func returns a JSON-ready value.
type Provenance struct {
	// Status is the key, the record counts and the consented repositories.
	Status func(ctx context.Context) (any, error)
	// Records lists a repository's records ("" root: every repository).
	Records func(ctx context.Context, root string, limit int) (any, error)
	// Consent gives or withdraws a person's consent for one repository's
	// writers (git notes, the commit trailer).
	Consent func(ctx context.Context, root string, notes, trailer bool) (any, error)
	// ConsentFor reads one repository's consent.
	ConsentFor func(ctx context.Context, root string) (notes, trailer bool, err error)
	// RotateKey retires the signing key and makes the next one.
	RotateKey func(ctx context.Context) (any, error)
	// TrailerPreview is the exact prepare-commit-msg block a trailer consent
	// writes into one repository, shown before the write (PR11).
	TrailerPreview func(ctx context.Context, root string) (ProvenanceHookPreview, error)
}

// ProvenanceHookPreview is the trailer hook block and where it goes.
type ProvenanceHookPreview struct {
	Root     string `json:"root"`
	HookPath string `json:"hook_path"`
	Block    string `json:"block"`
	// Digest is the hex SHA-256 of Block; a dashboard consent that turns
	// the trailer on names it, so the block was shown.
	Digest    string `json:"digest"`
	Installed bool   `json:"installed"`
	Refusal   string `json:"refusal,omitempty"`
}
