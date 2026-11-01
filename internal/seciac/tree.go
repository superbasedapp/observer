package seciac

import (
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secengine"
)

// MaxQueriesFiles caps a recorded KICS queries tree (v2.2.0's
// assets/queries holds 14,420 files, about 72 MB; its libraries a few more).
const MaxQueriesFiles = 32000

// NewQueriesRecord builds the queries tree record after the first verified
// run (X9): every file's digest bound to the binary that read it. ok is
// false when the tree is empty, too large or holds a bad path (nothing is
// recorded, and the next verified run records again). The record is the
// secengine TreeRecord, so secengine.CheckTree compares a later listing.
func NewQueriesRecord(binaryDigest, version string, digests map[string]string, now time.Time) (secengine.TreeRecord, bool) {
	if len(digests) == 0 || len(digests) > MaxQueriesFiles {
		return secengine.TreeRecord{}, false
	}
	files := make(map[string]string, len(digests))
	for p, d := range digests {
		if !secengine.ValidTreePath(p) || len(d) != 64 {
			return secengine.TreeRecord{}, false
		}
		files[p] = strings.ToLower(d)
	}
	return secengine.TreeRecord{BinaryDigest: lower(binaryDigest), Version: version, Files: files, RecordedAt: now.UTC()}, true
}
