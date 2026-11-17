package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/api"
)

// TestPersonalPlaneFromEnv pins the serve wiring of SBCI_PERSONAL_PLANE
// (D-IND-7): empty serves, the two words parse, anything else refuses.
func TestPersonalPlaneFromEnv(t *testing.T) {
	cases := []struct {
		value   string
		want    string
		wantErr bool
	}{
		{value: "", want: api.PersonalPlaneServing},
		{value: "serving", want: api.PersonalPlaneServing},
		{value: " retired ", want: api.PersonalPlaneRetired},
		{value: "retire", wantErr: true},
		{value: "SERVING", wantErr: true},
	}
	for _, tc := range cases {
		t.Setenv(envPersonalPlane, tc.value)
		got, err := personalPlaneFromEnv()
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("SBCI_PERSONAL_PLANE=%q: got %q, %v; want %q, err=%v", tc.value, got, err, tc.want, tc.wantErr)
		}
	}
}
