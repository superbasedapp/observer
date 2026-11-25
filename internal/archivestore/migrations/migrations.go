package migrations

import "embed"

// Files is the embedded filesystem of .sql migrations, applied in version
// order by internal/archivestore.Open and recorded in schema_meta. Filenames
// are NNN_name.sql; the leading integer is the version.
//
//go:embed *.sql
var Files embed.FS
