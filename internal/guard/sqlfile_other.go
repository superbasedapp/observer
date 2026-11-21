//go:build !unix

package guard

import "os"

// openSQLFile opens a SQL script read-only. Windows has no FIFO to swap in
// (a named pipe lives under \.\pipe\, which the guard's resolved paths do
// not reach), so a plain open is enough; the caller still rejects anything
// that is not a regular file.
func openSQLFile(path string) (*os.File, error) {
	return os.Open(path) //nolint:gosec // the path is the SQL script the guarded command names
}
