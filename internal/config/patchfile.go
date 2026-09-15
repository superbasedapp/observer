package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/config/migrate"
)

// PatchMode says which write strategy PatchFile used.
type PatchMode string

// Patch modes.
const (
	// PatchSurgical — scalar line edits; every untouched line and every
	// comment survived byte-for-byte (plan §2.3 Tier A).
	PatchSurgical PatchMode = "surgical"
	// PatchReserialize — the whole struct was marshalled; comments are lost
	// and the prior file is in .bak (plan §2.3 Tier B).
	PatchReserialize PatchMode = "reserialize"
)

// Patch is one leaf edit for PatchFile. Dotted is the TOML path; RHS is the
// rendered single-line TOML scalar for it (internal/configschema.TOMLScalar)
// and Scalar reports whether such a rendering exists — a list or map patch
// carries Scalar=false and forces the re-serialize path for the batch.
type Patch struct {
	Dotted string
	RHS    string
	Scalar bool
}

// PatchResult reports what PatchFile did.
type PatchResult struct {
	Mode         PatchMode
	CommentsKept bool
	// Reason explains a fallback to PatchReserialize ("" when surgical).
	Reason     string
	BackupPath string
	// Wrote is false when the file already held the target bytes (a
	// surgical no-op), in which case nothing was written and no .bak was
	// refreshed.
	Wrote bool
}

// PatchFile applies leaf-key patches to the config file at path, preserving
// comments and untouched lines byte-for-byte where the pure editor
// (migrate.PatchScalars) can do so safely, and falling back to a full
// re-serialize of cfg — the ALREADY-patched, ALREADY-validated struct the
// caller holds — where it cannot. It is a front door onto writeBytesAtomic,
// never a second write mechanism: whichever strategy runs, the write is
// atomic and the prior file lands in path+".bak".
//
// The surgical result is parsed back into a Config before it is written; a
// text the decoder rejects (a structural TOML conflict the line editor could
// not foresee) falls back to re-serialize with the decoder's reason rather
// than ever landing on disk. That is the "validate before write" half; the
// caller's read-back verification after the write is the other half.
//
// STANCE (docs/configuration.md): config.toml stays operator-owned and
// hand-editable. The daemon never rewrites it unprompted; every dashboard
// write is operator-initiated, atomic and backed up. Scalar edits preserve
// comments; list and table edits currently re-serialize the file. The file
// is the source of truth for VALUES, not a canonical rendering of the
// operator's FORMATTING.
func PatchFile(path string, cfg Config, patches []Patch) (PatchResult, error) {
	if path == "" {
		return PatchResult{}, errors.New("config.PatchFile: empty path")
	}
	res := PatchResult{BackupPath: path + ".bak"}
	current, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return res, fmt.Errorf("config.PatchFile: read %s: %w", path, err)
	}

	text, reason, ok := surgicalText(string(current), patches)
	if ok {
		res.Mode, res.CommentsKept = PatchSurgical, true
		if text == string(current) && err == nil {
			// Nothing to write: the file already says this. Do not churn
			// .bak for a no-op.
			return res, nil
		}
		if werr := writeBytesAtomic(path, []byte(text)); werr != nil {
			return res, fmt.Errorf("config.PatchFile: write %s: %w", path, werr)
		}
		res.Wrote = true
		return res, nil
	}
	res.Reason = reason

	res.Mode, res.CommentsKept = PatchReserialize, false
	if werr := writeTOMLAtomic(path, cfg); werr != nil {
		return res, fmt.Errorf("config.PatchFile: write %s: %w", path, werr)
	}
	res.Wrote = true
	return res, nil
}

// surgicalText attempts the Tier-A edit and proves the result decodes.
// reason names why it could not be used.
func surgicalText(current string, patches []Patch) (text, reason string, ok bool) {
	sps := make([]migrate.ScalarPatch, 0, len(patches))
	for _, p := range patches {
		if !p.Scalar {
			return "", p.Dotted + " is a list or table value — the file is re-serialized", false
		}
		sps = append(sps, migrate.ScalarPatch{Path: strings.Split(p.Dotted, "."), RHS: p.RHS})
	}
	pr := migrate.PatchScalars(current, sps)
	if len(pr.Unsafe) > 0 {
		return "", pr.Reason, false
	}
	var probe Config
	if _, err := toml.Decode(pr.Text, &probe); err != nil {
		return "", "surgical edit produced text the TOML decoder rejects (" + err.Error() + ") — the file is re-serialized", false
	}
	return pr.Text, "", true
}

// RestoreBackup copies path+".bak" back over path (atomically), leaving the
// backup itself in place. It is the recovery step for a write whose
// read-back verification failed: the file returns to its pre-write bytes
// and the .bak still holds them, so a second restore is a no-op rather than
// a swap. Returns os.ErrNotExist when there is no backup.
func RestoreBackup(path string) error {
	bak, err := os.ReadFile(path + ".bak")
	if err != nil {
		return fmt.Errorf("config.RestoreBackup: %w", err)
	}
	// writeBytesAtomic would overwrite .bak with the BROKEN file first; the
	// backup must survive, so write the temp + rename directly.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-restore-*.toml")
	if err != nil {
		return fmt.Errorf("config.RestoreBackup: create temp: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(bak); err != nil {
		tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("config.RestoreBackup: write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("config.RestoreBackup: close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("config.RestoreBackup: rename: %w", err)
	}
	return nil
}
