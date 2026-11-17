package hostclient_test

import (
	"io/fs"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/db/migrations"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/hostapi"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// TestVocabulariesAgree pins the pure core's closed vocabularies to the store
// and the SQL: the outbox verbs equal store.KnownOrgOutboxVerbs (and so the
// 0049 CHECK, pinned by the store's own test), and the finding kinds equal the
// CHECK in the embedded migration 0060_org_reconcile_findings.sql.
func TestVocabulariesAgree(t *testing.T) {
	t.Parallel()
	var verbs []string
	for _, v := range hostapi.KnownVerbs() {
		verbs = append(verbs, string(v))
	}
	var storeVerbs []string
	for _, v := range store.KnownOrgOutboxVerbs() {
		storeVerbs = append(storeVerbs, string(v))
	}
	if !slices.Equal(verbs, storeVerbs) {
		t.Errorf("hostapi verbs %v != store verbs %v", verbs, storeVerbs)
	}

	b, err := fs.ReadFile(migrations.Files, "0060_org_reconcile_findings.sql")
	if err != nil {
		t.Fatalf("read 0060: %v", err)
	}
	sql := string(b)
	const marker = "CHECK (kind IN ("
	i := strings.Index(sql, marker)
	if i < 0 {
		t.Fatalf("0060 has no %q", marker)
	}
	rest := sql[i+len(marker):]
	j := strings.Index(rest, ")")
	var inSQL []string
	for _, v := range strings.Split(rest[:j], ",") {
		inSQL = append(inSQL, strings.Trim(strings.TrimSpace(v), "'"))
	}
	var kinds []string
	for _, k := range hostapi.KnownFindingKinds() {
		kinds = append(kinds, string(k))
	}
	if !slices.Equal(kinds, inSQL) {
		t.Errorf("finding kinds %v != 0060 CHECK %v", kinds, inSQL)
	}
}
