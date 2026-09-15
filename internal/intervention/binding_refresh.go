package intervention

import "context"

// RefreshInstallManifest rebuilds installed identities while retaining live
// native processes from the previous inventory. Vendor updates commonly unlink
// an executable while an existing session keeps running its old inode. Retained
// targets bind the complete process lifetime, not the removed pathname or an
// inode that might later be reused. Interpreted entrypoints need fresh script
// evidence and cannot inherit this native-executable guarantee.
func RefreshInstallManifest(ctx context.Context, previous InstallManifest, candidates []InstalledCandidate, opts ScanOptions) (InstallManifest, error) {
	current, err := BuildInstallManifest(ctx, candidates)
	if err != nil || len(previous.Surfaces) == 0 {
		return current, err
	}
	running, err := ScanInstalledProcesses(ctx, previous, opts)
	if err != nil {
		return current, err
	}
	for _, match := range running.Matches {
		if match.Target.Kind != TargetNativeExecutable {
			continue
		}
		for i := range current.Surfaces {
			row := &current.Surfaces[i]
			if row.Spec.ID != match.SurfaceID || row.Spec.Tool != match.Tool {
				continue
			}
			alreadyBound := false
			for _, target := range row.Targets {
				alreadyBound = alreadyBound || targetMatches(row.Spec.ID, target, ProcessEvidence{
					Identity:    match.Identity,
					Invocations: []InvocationEvidence{{SurfaceID: row.Spec.ID, Target: TargetNativeExecutable, Class: InvocationCLI}},
				})
			}
			if !alreadyBound {
				target := match.Target
				id := match.Identity
				target.BoundProcess = &id
				row.Targets = append(row.Targets, target)
				if row.State != BindingReady {
					row.State = BindingPartial
				}
			}
		}
	}
	return current, nil
}
