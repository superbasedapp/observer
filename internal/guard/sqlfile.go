package guard

import (
	"io"
)

// maxSQLFileBytes bounds the SQL script R-126 reads: a script larger than
// this is not read at all (ok=false), never judged on a prefix, so a
// destructive statement past the cut cannot hide behind a harmless head.
// ok=false is "not judged", NOT "clean": the rule asks about a SQL client
// whose file it could not read (internal/policy rules_database.go,
// scanSQLFiles) and stays silent only for a file that was read and is clean.
const maxSQLFileBytes = 256 << 10

// readSQLFileBounded is policy.Config.ReadSQLFile: it reads the SQL script a
// database command runs from a file (`psql -f x.sql`, `mysql < x.sql`) for
// R-126. Only a regular file of at most maxSQLFileBytes is read; anything
// else (absent, a directory, a device or FIFO that could block the hook, a
// larger file) reports ok=false, which the rule treats as not judged.
//
// The file is opened first and checked on the opened handle (openSQLFile
// never blocks on a FIFO), so a path swapped for a FIFO or a larger file
// between a check and the open cannot be read or block the hook.
func readSQLFileBounded(path string) ([]byte, bool) {
	if path == "" {
		return nil, false
	}
	f, err := openSQLFile(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxSQLFileBytes {
		return nil, false
	}
	b, err := io.ReadAll(io.LimitReader(f, maxSQLFileBytes+1))
	if err != nil || len(b) > maxSQLFileBytes {
		return nil, false
	}
	return b, true
}
