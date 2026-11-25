package migrations

import "embed"

// Files holds every .sql migration, applied in ascending numeric order by the
// runner in the parent package.
//
//go:embed *.sql
var Files embed.FS
