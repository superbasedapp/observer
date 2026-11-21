package sandboxvocab

import "testing"

func TestGatewayModeVocabulary(t *testing.T) {
	for _, tc := range []struct {
		in   GatewayMode
		want bool
	}{
		{GatewayManagedLocal, true},
		{GatewayExternal, true},
		{"", false},
		{"managed", false},
		{"remote", false},
	} {
		if got := tc.in.Valid(); got != tc.want {
			t.Errorf("GatewayMode(%q).Valid() = %v, want %v", tc.in, got, tc.want)
		}
	}
	for _, m := range GatewayModes() {
		if !m.Valid() {
			t.Errorf("GatewayModes lists %q, which is not valid", m)
		}
	}
}
