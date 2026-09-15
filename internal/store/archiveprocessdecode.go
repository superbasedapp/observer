package store

import (
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/archive"
)

// DecodeArchivedProcessRuns turns generic archived row batches back into the
// SAME [ProcessRunRow] values the hot read path produces.
//
// This is the last mile of P3.5's direct-read (design §4.3): a session whose
// process capture has moved to cold storage is answered from the archive file
// for that one request, with NO WRITE-BACK. Re-growing the hot database on a
// read is precisely what this arc exists to stop, and it would additionally
// hand the live correlation sweep historical rows to reconsider, which it has
// no business doing.
//
// Decoding BY COLUMN NAME rather than by position is deliberate and is the
// same discipline the copy uses: the archive is a byte-for-byte mirror whose
// column set is whatever the hot table had when the window was archived, so a
// row archived before a later ALTER TABLE simply lacks that column and decodes
// to its zero value. Positional decoding would instead shift every field after
// it and render a confidently wrong process trail.
//
// Columns this decoder does not know are IGNORED rather than rejected — a
// future migration must not make old archived windows unreadable. Columns it
// knows but the batch omits stay zero.
func DecodeArchivedProcessRuns(batches ...archive.RowBatch) ([]ProcessRunRow, error) {
	var out []ProcessRunRow
	for _, b := range batches {
		if b.Table != "process_runs" {
			return nil, fmt.Errorf("store.DecodeArchivedProcessRuns: batch is for %q, not process_runs", b.Table)
		}
		for _, vals := range b.Vals {
			var r ProcessRunRow
			for i, col := range b.Cols {
				if i >= len(vals) {
					break
				}
				if assign, ok := processRunColumns[col]; ok {
					assign(&r, vals[i])
				}
			}
			r.Exited = !r.ExitedAt.IsZero()
			out = append(out, r)
		}
	}
	return out, nil
}

// processRunColumns is the one-setter-per-column assignment table. A literal
// map rather than a switch (CLAUDE.md §5), and deliberately exhaustive over
// ProcessRunRow so an archived trail renders identically to a hot one.
// Unknown columns are simply absent from the map — see the decoder's
// forward-compatibility contract above.
var processRunColumns = map[string]func(r *ProcessRunRow, v any){
	"id":                 func(r *ProcessRunRow, v any) { r.ID = archiveInt(v) },
	"process_key":        func(r *ProcessRunRow, v any) { r.ProcessKey = archiveText(v) },
	"boot_id":            func(r *ProcessRunRow, v any) { r.BootID = archiveText(v) },
	"pid":                func(r *ProcessRunRow, v any) { r.PID = int(archiveInt(v)) },
	"ppid":               func(r *ProcessRunRow, v any) { r.PPID = int(archiveInt(v)) },
	"start_time_ticks":   func(r *ProcessRunRow, v any) { r.StartTimeTicks = archiveInt(v) },
	"parent_process_key": func(r *ProcessRunRow, v any) { r.ParentProcessKey = archiveText(v) },
	"session_id":         func(r *ProcessRunRow, v any) { r.SessionID = archiveText(v) },
	"project_id":         func(r *ProcessRunRow, v any) { r.ProjectID = archiveInt(v) },
	"tool":               func(r *ProcessRunRow, v any) { r.Tool = archiveText(v) },
	"action_id": func(r *ProcessRunRow, v any) {
		if v != nil {
			id := archiveInt(v)
			r.ActionID = &id
		}
	},
	"turn_index": func(r *ProcessRunRow, v any) {
		if v != nil {
			ti := int(archiveInt(v))
			r.TurnIndex = &ti
		}
	},
	"attribution_source":     func(r *ProcessRunRow, v any) { r.AttributionSource = archiveText(v) },
	"attribution_confidence": func(r *ProcessRunRow, v any) { r.AttributionConfidence = archiveText(v) },
	"exe_path":               func(r *ProcessRunRow, v any) { r.ExePath = archiveText(v) },
	"exe_basename":           func(r *ProcessRunRow, v any) { r.ExeBasename = archiveText(v) },
	"cwd":                    func(r *ProcessRunRow, v any) { r.CWD = archiveText(v) },
	"argv_preview":           func(r *ProcessRunRow, v any) { r.ArgvPreview = archiveText(v) },
	"argv_hash":              func(r *ProcessRunRow, v any) { r.ArgvHash = archiveText(v) },
	"argv_argc":              func(r *ProcessRunRow, v any) { r.ArgvArgc = int(archiveInt(v)) },
	"uid":                    func(r *ProcessRunRow, v any) { r.UID = int(archiveInt(v)) },
	"gid":                    func(r *ProcessRunRow, v any) { r.GID = int(archiveInt(v)) },
	"username":               func(r *ProcessRunRow, v any) { r.Username = archiveText(v) },
	"env_posture_json":       func(r *ProcessRunRow, v any) { r.EnvPostureJSON = archiveText(v) },
	"started_at":             func(r *ProcessRunRow, v any) { r.StartedAt = archiveTime(v) },
	"last_seen_at":           func(r *ProcessRunRow, v any) { r.LastSeenAt = archiveTime(v) },
	"exited_at":              func(r *ProcessRunRow, v any) { r.ExitedAt = archiveTime(v) },
	"exit_code":              func(r *ProcessRunRow, v any) { r.ExitCode = int(archiveInt(v)) },
	"exit_signal":            func(r *ProcessRunRow, v any) { r.ExitSignal = int(archiveInt(v)) },
	"duration_ms":            func(r *ProcessRunRow, v any) { r.DurationMs = archiveInt(v) },
	"seccomp_mode":           func(r *ProcessRunRow, v any) { r.SeccompMode = archiveText(v) },
	"capabilities_eff":       func(r *ProcessRunRow, v any) { r.CapabilitiesEff = archiveText(v) },
	"apparmor_label":         func(r *ProcessRunRow, v any) { r.AppArmorLabel = archiveText(v) },
	"selinux_label":          func(r *ProcessRunRow, v any) { r.SELinuxLabel = archiveText(v) },
	"cgroup_hash":            func(r *ProcessRunRow, v any) { r.CgroupHash = archiveText(v) },
	"container_id":           func(r *ProcessRunRow, v any) { r.ContainerID = archiveText(v) },
	"pid_namespace":          func(r *ProcessRunRow, v any) { r.PIDNamespace = archiveText(v) },
	"mount_namespace":        func(r *ProcessRunRow, v any) { r.MountNamespace = archiveText(v) },
	"net_namespace":          func(r *ProcessRunRow, v any) { r.NetNamespace = archiveText(v) },
	"cpu_user_ms":            func(r *ProcessRunRow, v any) { r.CPUUserMs = archiveInt(v) },
	"cpu_system_ms":          func(r *ProcessRunRow, v any) { r.CPUSystemMs = archiveInt(v) },
	"max_rss_bytes":          func(r *ProcessRunRow, v any) { r.MaxRSSBytes = archiveInt(v) },
	"working_set_bytes":      func(r *ProcessRunRow, v any) { r.WorkingSetBytes = archiveInt(v) },
	"read_bytes":             func(r *ProcessRunRow, v any) { r.ReadBytes = archiveInt(v) },
	"write_bytes":            func(r *ProcessRunRow, v any) { r.WriteBytes = archiveInt(v) },
	"read_ops":               func(r *ProcessRunRow, v any) { r.ReadOps = archiveInt(v) },
	"write_ops":              func(r *ProcessRunRow, v any) { r.WriteOps = archiveInt(v) },
	"thread_count":           func(r *ProcessRunRow, v any) { r.ThreadCount = int32(archiveInt(v)) },
	"handle_count":           func(r *ProcessRunRow, v any) { r.HandleCount = int32(archiveInt(v)) },
	"metric_samples_json":    func(r *ProcessRunRow, v any) { r.MetricSamples = parseMetricSamples(archiveText(v)) },
}

func archiveText(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []byte:
		return string(t)
	case nil:
		return ""
	default:
		return fmt.Sprint(t)
	}
}

func archiveInt(v any) int64 {
	switch t := v.(type) {
	case int64:
		return t
	case float64:
		return int64(t)
	case bool:
		if t {
			return 1
		}
		return 0
	default:
		return 0
	}
}

// archiveTime parses a stored RFC3339Nano timestamp. A malformed or absent
// value yields the zero time, which the callers already treat as "unknown"
// (ProcessRunRow.Exited is derived from ExitedAt being non-zero).
func archiveTime(v any) time.Time {
	s := archiveText(v)
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC()
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC()
	}
	return time.Time{}
}
