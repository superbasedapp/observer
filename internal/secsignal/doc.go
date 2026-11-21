// Package secsignal is the ONE seam that computes the per-finding ranking
// signals of dependency findings (OS and CI vulnerability scanning plan
// sections 14.5, 14.7 and 14.8, M3L-1): the import-level reachability tier
// (internal/secreachsvc over internal/secreach) and the CISA KEV and FIRST
// EPSS exploit answer (internal/secexploit). Compute is the single entry
// function the surfaces call (the Code security page's findings list and
// finding drawer, the MCP tool get_security_findings); the surfaces then
// order through internal/secrank.
//
// Every read is injected: the local OSV record read (osvdb.DetailLookup),
// the installed exploit data (osvdb.ExploitLookup), and the reach options
// (a shared secreachsvc.Cache, the codeintel index). Each finding's OSV
// records are read once and serve both signals: their affected import
// paths feed the tier and their aliases (the CVE ids) feed the exploit
// lookup. Only ids and import paths are read, never advisory prose.
//
// Nothing here makes a request, starts a process or writes; a cold import
// parse is bounded by secreachsvc's limits. Per ruling Q14-4 (a) the
// signals rank and label only: nothing here closes, hides or re-grades a
// finding, and missing exploit data is "unavailable", never "not exploited".
package secsignal
