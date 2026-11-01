package store

// secRootKeyedColumns are the security pillar's tables that name a project
// by the hash of its root (migrations 177 to 194). The project-root repair
// and the Windows case fold only count them (countRootKeyed); this file
// names the tables for that count and never writes them, so the security
// store keeps its one writer (TestSecTablesHaveOneWriter).
var secRootKeyedColumns = []struct {
	table, column string
	hashed        bool
}{
	{"sec_findings", "project_root_hash", true},
	{"sec_finding_events", "project_root_hash", true},
	{"sec_scan_runs", "project_root_hash", true},
	{"sec_baselines", "project_root_hash", true},
	{"sec_config_baseline", "project_root_hash", true},
	{"sec_config_files", "project_root_hash", true},
	{"sec_finding_exceptions", "project_root_hash", true},
	{"sec_change_records", "project_root_hash", true},
	{"sec_change_consent", "project_root_hash", true},
}
