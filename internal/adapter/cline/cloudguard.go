package cline

import "strings"

// cloudTaskIDPrefixes are the id prefixes of a Cline Cloud session as the
// VS Code extension names it (apps/vscode/src/shared/cloud/cloud-sessions.ts
// at cline/cline a6507a62: isCloudSessionId = a persisted "ses-..." id, or
// the "cloud-provisioning-..." placeholder while a sandbox starts). The
// extension's own task history splits cloud from local tasks on exactly this
// predicate, so no local task id carries these prefixes.
var cloudTaskIDPrefixes = []string{"ses-", "cloud-provisioning-"}

// projectedCloudTask reports whether a task id names a Cline Cloud session
// projected into the extension's task history (the "Cloud Only" filter;
// statuses in globalState cloudSessionStatuses). Such a session ran in the
// vendor's sandbox: the cline-cloud pull connector owns it
// (internal/cloudagents, execution_location vendor_cloud), so a task folder
// carrying its id must never land as a local session (lane CA-V6). The
// extension writes no local task folder for one today ("Cloud records are
// owned by the control plane; nothing to persist locally"); this guard keeps
// that true if a build ever mirrors one.
func projectedCloudTask(taskID string) bool {
	id := strings.TrimSpace(taskID)
	for _, p := range cloudTaskIDPrefixes {
		if strings.HasPrefix(id, p) {
			return true
		}
	}
	return false
}
