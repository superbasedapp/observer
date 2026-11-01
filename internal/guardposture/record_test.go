package guardposture

import "testing"

// TestRecordMAC: a record verifies under its own key and domain only; a
// changed body, another domain, another key, an empty key or a missing or
// malformed sum never verifies.
func TestRecordMAC(t *testing.T) {
	t.Parallel()
	key := make([]byte, keyBytes)
	other := make([]byte, keyBytes)
	other[0] = 1
	body := []byte("1\n2026-10-21T09:00:00Z\n\"cli\"")
	sum := RecordMAC("sbo-test-record-v1", body, key)
	if !VerifyRecordMAC("sbo-test-record-v1", body, key, sum) {
		t.Fatal("a signed record does not verify")
	}
	for name, ok := range map[string]bool{
		"changed body": VerifyRecordMAC("sbo-test-record-v1", []byte("1\n2026-10-21T09:00:00Z\n\"dashboard\""), key, sum),
		"other domain": VerifyRecordMAC("sbo-test-record-v2", body, key, sum),
		"other key":    VerifyRecordMAC("sbo-test-record-v1", body, other, sum),
		"no key":       VerifyRecordMAC("sbo-test-record-v1", body, nil, sum),
		"no sum":       VerifyRecordMAC("sbo-test-record-v1", body, key, ""),
		"bad sum":      VerifyRecordMAC("sbo-test-record-v1", body, key, "zz"),
		"no domain":    VerifyRecordMAC("", body, key, RecordMAC("", body, key)),
	} {
		if ok {
			t.Errorf("%s verifies", name)
		}
	}
}
