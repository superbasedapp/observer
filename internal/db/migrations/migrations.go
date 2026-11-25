package migrations

import "embed"

// Files is the embedded filesystem of .sql migrations, sorted lexicographically
// by filename. The db.Open routine reads every *.sql entry and applies the
// ones its per-step ledger (internal/migplan, internal/migplan/sqliteledger)
// has not recorded, in version order inside one transaction. schema_meta keeps
// a record per applied step plus the highest applied version.
//
//go:embed *.sql
var Files embed.FS
