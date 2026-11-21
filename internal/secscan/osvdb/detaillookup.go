package osvdb

import (
	"errors"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/secdepdetail"
)

// detaillookup.go is the ONE local OSV record read that dependency detail
// (internal/secdepdetail) is given: the dashboard's finding drawer, the MCP
// tool get_security_findings and `observer security explain --fix` all call
// DetailLookup. It reads the store directory only; there is no network path.

// detailReaders holds one RecordReader per store directory (the directory
// follows the config path, which a test points elsewhere).
var detailReaders sync.Map // dir -> *RecordReader

// DetailLookup returns the record lookup for the OSV store at dir, its
// errors mapped onto secdepdetail's (ErrDatabaseNotInstalled,
// ErrRecordNotFound). An empty dir reads "database not installed".
func DetailLookup(dir string) func(eco, id string) ([]byte, error) {
	if dir == "" {
		return func(string, string) ([]byte, error) { return nil, secdepdetail.ErrDatabaseNotInstalled }
	}
	v, _ := detailReaders.LoadOrStore(dir, NewRecordReader(Open(dir)))
	rr := v.(*RecordReader)
	return func(eco, id string) ([]byte, error) {
		b, err := rr.Record(eco, id)
		switch {
		case errors.Is(err, ErrEcosystemNotInstalled):
			return nil, secdepdetail.ErrDatabaseNotInstalled
		case errors.Is(err, ErrRecordNotFound):
			return nil, secdepdetail.ErrRecordNotFound
		}
		return b, err
	}
}
