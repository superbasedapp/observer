package intervention

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

const installManifestFingerprintVersion = "v1"

// InstallManifestFingerprint returns a path-free witness for the registry
// declaration and current installed targets in a manifest. Targets retained
// only for one already-running process lifetime are excluded: they may remain
// controllable, but they cannot authorize a new launch after an install moved.
func InstallManifestFingerprint(manifest InstallManifest) string {
	type installedTarget struct {
		Kind       TargetKind
		Executable ExecutableIdentity
		Entrypoint *ExecutableIdentity
	}
	type surface struct {
		ID          string
		Tool        string
		Class       integration.InterventionSurfaceClass
		NativeUsage integration.NativeUsageKind
		Binding     integration.ProcessBindingSpec
		Binary      *integration.BinaryResolveSpec
		State       BindingState
		Reasons     []BindingReason
		Targets     []installedTarget
	}

	canonical := make([]surface, 0, len(manifest.Surfaces))
	for _, row := range manifest.Surfaces {
		item := surface{
			ID: row.Spec.ID, Tool: row.Spec.Tool, Class: row.Spec.Class,
			NativeUsage: row.Spec.NativeUsage, Binding: row.Spec.Binding,
			Binary: row.Spec.Binary, State: row.State,
			Reasons: append([]BindingReason(nil), row.Reasons...),
		}
		for _, target := range row.Targets {
			if target.BoundProcess != nil {
				continue
			}
			current := installedTarget{Kind: target.Kind, Executable: target.Executable.Identity}
			if target.Entrypoint != nil {
				entrypoint := target.Entrypoint.Identity
				current.Entrypoint = &entrypoint
			}
			item.Targets = append(item.Targets, current)
		}
		sort.Slice(item.Targets, func(i, j int) bool {
			left, right := item.Targets[i], item.Targets[j]
			if left.Kind != right.Kind {
				return left.Kind < right.Kind
			}
			if left.Executable.Device != right.Executable.Device {
				return left.Executable.Device < right.Executable.Device
			}
			if left.Executable.Inode != right.Executable.Inode {
				return left.Executable.Inode < right.Executable.Inode
			}
			if left.Entrypoint == nil || right.Entrypoint == nil {
				return left.Entrypoint == nil && right.Entrypoint != nil
			}
			if left.Entrypoint.Device != right.Entrypoint.Device {
				return left.Entrypoint.Device < right.Entrypoint.Device
			}
			return left.Entrypoint.Inode < right.Entrypoint.Inode
		})
		sort.Slice(item.Reasons, func(i, j int) bool { return item.Reasons[i] < item.Reasons[j] })
		canonical = append(canonical, item)
	}
	sort.Slice(canonical, func(i, j int) bool { return canonical[i].ID < canonical[j].ID })
	raw, err := json.Marshal(canonical)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return installManifestFingerprintVersion + " " + hex.EncodeToString(sum[:])
}
