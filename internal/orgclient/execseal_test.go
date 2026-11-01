package orgclient

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

// TestExecSealStatusErr (ledger SHR-6, lane LEFT2-SEC item R-017): a 409
// carrying seal_key_revoked reads as the org's revocation, any other 409 as
// no machine on record yet; the other statuses keep their meaning.
func TestExecSealStatusErr(t *testing.T) {
	for _, c := range []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"registered", http.StatusOK, `{}`, nil},
		{"no route", http.StatusNotFound, ``, ErrExecSealNotSupported},
		{"revoked", http.StatusConflict, `{"error":"seal_key_revoked","message":"x"}`, ErrExecSealKeyRevoked},
		{"no machine yet", http.StatusConflict, `{"error":"machine_not_on_record"}`, ErrExecSealMachineNotOnRecord},
		{"409 without a body", http.StatusConflict, ``, ErrExecSealMachineNotOnRecord},
		{"auth", http.StatusForbidden, ``, ErrAuthFailed},
	} {
		err := execSealStatusErr(c.status, strings.NewReader(c.body))
		if (c.want == nil) != (err == nil) || (c.want != nil && !errors.Is(err, c.want)) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
}
