package proccapture

import (
	"math"
	"sync"
)

// Per-row byte costs for Estimate. Measured on the live WSL node 2026-11-04
// (plan §1): process_runs held 428,075 rows in 669 MB of pages (table plus
// indexes), about 1,563 bytes per row. The measured session's variable text
// columns (metric ring 15.2 MB, argv 9.4 MB, exe paths 4.3 MB, cwd 2.4 MB over
// 92,428 rows) were about 340 bytes per row, which leaves about 1,220 bytes of
// fixed per-row cost: the ~60 fixed-width columns, the row header and the five
// indexes' entries. A rollup row is narrower (18 columns, one unique index and
// two lookup indexes); its fixed cost is set by the same arithmetic over its
// column list.
const (
	// RowOverheadBytes is the fixed stored cost of one process_runs row,
	// excluding its variable columns.
	RowOverheadBytes = 1220
	// RollupRowOverheadBytes is the fixed stored cost of one process_rollups
	// row, excluding its example argv and key strings.
	RollupRowOverheadBytes = 420
)

// VolumeEstimate is the data-volume projection the Settings page shows for a draft
// [observer.process.capture] (plan §9.3). JSON tags are the wire shape of
// GET /api/process/capture/estimate.
type VolumeEstimate struct {
	Basis     EstimateBasis     `json:"basis"`
	Current   EstimateVolume    `json:"current"`
	Projected EstimateProjected `json:"projected"`
	BySetting []SettingEstimate `json:"by_setting"`
}

// EstimateBasis is what the replay was computed over.
type EstimateBasis struct {
	Days         int `json:"days"`
	Sessions     int `json:"sessions"`
	ObservedRows int `json:"observed_rows"`
}

// EstimateVolume is the stored volume under the current config.
type EstimateVolume struct {
	RowsPerDay  int64 `json:"rows_per_day"`
	BytesPerDay int64 `json:"bytes_per_day"`
}

// EstimateProjected is the stored volume under the proposed config.
type EstimateProjected struct {
	RowsPerDay       int64 `json:"rows_per_day"`
	BytesPerDay      int64 `json:"bytes_per_day"`
	RollupRowsPerDay int64 `json:"rollup_rows_per_day"`
	// OrgRowsPerDay is what the org push would carry for an enrolled node:
	// the session-attributed exemplar rows plus the session rollup rows (the
	// O1 wire; the machine rollup never ships).
	OrgRowsPerDay int64 `json:"org_rows_per_day"`
}

// SettingEstimate is the projected rows per day with only Key changed from
// the current config to the proposed one.
type SettingEstimate struct {
	Key        string `json:"key"`
	RowsPerDay int64  `json:"rows_per_day"`
}

// volume is one replay's totals.
type volume struct {
	rows, bytes, rollupRows, orgRows int64
}

// Estimate replays history through the decision table under current and under
// proposed and returns rows and bytes per day, rollup rows per day, org rows
// per day, and the per-setting breakdown (one row per ConfigKeys key that
// differs between the two configs). Pure; history is not modified.
//
// Unattributed rows held for correlation are counted as rows only when the
// budget is disabled; with it enabled they are transient (the retention pass
// rolls them into the machine rollup, or drops them, after pending_hours), so
// they count as machine rollup rows (mode rollup) or nothing (mode drop).
func Estimate(history []RunFacts, current, proposed Config) VolumeEstimate {
	days := countDays(history)
	perDay := func(n int64) int64 { return int64(math.Round(float64(n) / float64(days))) }

	sessions := map[string]bool{}
	for _, f := range history {
		if f.SessionID != "" {
			sessions[f.SessionID] = true
		}
	}
	// Every replay is independent (Replay copies its input), so they run in
	// parallel; a proposed config equal to the current one is replayed once.
	changed := current.changedKeys(proposed)
	configs := []Config{current}
	if len(changed) > 0 {
		configs = append(configs, proposed)
		if len(changed) > 1 {
			for _, k := range changed {
				configs = append(configs, current.with(k, proposed))
			}
		}
	}
	vols := make([]volume, len(configs))
	var wg sync.WaitGroup
	for i, c := range configs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			vols[i] = measure(history, c)
		}()
	}
	wg.Wait()
	cur, prop := vols[0], vols[len(vols)-1]
	if len(changed) > 0 {
		prop = vols[1]
	}
	est := VolumeEstimate{
		Basis:   EstimateBasis{Days: days, Sessions: len(sessions), ObservedRows: len(history)},
		Current: EstimateVolume{RowsPerDay: perDay(cur.rows), BytesPerDay: perDay(cur.bytes)},
		Projected: EstimateProjected{
			RowsPerDay:       perDay(prop.rows),
			BytesPerDay:      perDay(prop.bytes),
			RollupRowsPerDay: perDay(prop.rollupRows),
			OrgRowsPerDay:    perDay(prop.orgRows),
		},
		BySetting: []SettingEstimate{},
	}
	for i, k := range changed {
		v := prop
		if len(changed) > 1 {
			v = vols[2+i]
		}
		est.BySetting = append(est.BySetting, SettingEstimate{Key: k, RowsPerDay: perDay(v.rows)})
	}
	return est
}

// measure replays history under cfg and totals the stored volume.
func measure(history []RunFacts, cfg Config) volume {
	res := Replay(history, cfg)
	var v volume
	unattributed := map[GroupKey]bool{}
	for _, o := range res.Outcomes {
		if !o.Decision.Action.Persists() {
			continue
		}
		f := o.Facts
		if !f.Attributed() && cfg.Enabled {
			if cfg.UnattributedMode != UnattributedDrop {
				unattributed[UnattributedGroup(f, cfg)] = true
			}
			continue
		}
		v.rows++
		v.bytes += int64(RowBytes(f, cfg))
		if f.Attributed() {
			v.orgRows++
		}
	}
	for _, r := range res.Rollups {
		v.rollupRows++
		v.bytes += int64(rollupBytes(r))
		if r.Key.SessionID != "" {
			v.orgRows++
		}
	}
	v.rollupRows += int64(len(unattributed))
	v.bytes += int64(len(unattributed)) * RollupRowOverheadBytes
	return v
}

// RowBytes is the estimated stored size of one process_runs row: the measured
// variable bytes when known (StoredBytes), else the sum of the facts' string
// lengths plus the metric ring; the ring is not stored for a run younger than
// the ring threshold when the budget is enabled. Plus RowOverheadBytes.
func RowBytes(f RunFacts, cfg Config) int {
	variable := f.StoredBytes
	if variable <= 0 {
		variable = len(f.Argv) + len(f.CWD) + 2*len(f.ExeBasename) +
			len(f.ProcessKey) + len(f.ParentKey) + len(f.SessionID) + f.MetricBytes
	}
	if cfg.Enabled && f.MetricBytes > 0 && f.AliveFor < cfg.RingMinLifetime {
		variable -= f.MetricBytes
	}
	return RowOverheadBytes + max(variable, 0)
}

func rollupBytes(r Rollup) int {
	k := r.Key
	return RollupRowOverheadBytes + len(r.ExampleArgvPreview) + len(r.ExampleProcessKey) +
		len(k.SessionID) + len(k.ParentProcessKey) + len(k.ServiceRootKey) + len(k.ExeBasename) + len(k.ArgvTemplateHash)
}

// countDays is the number of distinct UTC days the history spans (at least 1).
func countDays(history []RunFacts) int {
	seen := map[string]bool{}
	for _, f := range history {
		if !f.Time.IsZero() {
			seen[f.Time.UTC().Format("2006-01-02")] = true
		}
	}
	return max(len(seen), 1)
}
