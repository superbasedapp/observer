package keystore

import (
	"errors"
	"testing"

	keyring "github.com/zalando/go-keyring"
)

func TestServicesTableIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range Services() {
		if s.Service == "" || s.Purpose == "" || s.Owner == "" {
			t.Errorf("incomplete row: %+v", s)
		}
		if seen[s.Service] {
			t.Errorf("duplicate service %s", s.Service)
		}
		seen[s.Service] = true
		for _, r := range s.Records {
			if !ValidName(r) {
				t.Errorf("%s: invalid record name %q", s.Service, r)
			}
		}
	}
	if got := len(ServiceNames()); got != len(seen) {
		t.Errorf("ServiceNames = %d, want %d", got, len(seen))
	}
}

func TestCheckPresence(t *testing.T) {
	cases := []struct {
		name  string
		info  ServiceInfo
		store map[string]string
		want  Presence
	}{
		{"no fixed records", ServiceInfo{Service: "sbo-presence-t1"}, nil, PresenceUnknown},
		{"absent", ServiceInfo{Service: "sbo-presence-t2", Records: []string{"a", "b"}}, nil, PresenceAbsent},
		{"present on second record", ServiceInfo{Service: "sbo-presence-t3", Records: []string{"a", "b"}}, map[string]string{"b": "secret"}, PresencePresent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for rec, v := range tc.store {
				if err := KeyringSet(tc.info.Service, rec, v); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = KeyringDelete(tc.info.Service, rec) })
			}
			if got := CheckPresence(tc.info); got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

// TestCheckPresenceAllUnavailableKeychain: when the keychain itself cannot be
// read, every service reads unavailable, including the ones without fixed
// record names, never absent.
func TestCheckPresenceAllUnavailableKeychain(t *testing.T) {
	keyring.MockInitWithError(errors.New("no keychain service"))
	t.Cleanup(keyring.MockInit)
	infos := []ServiceInfo{
		{Service: "sbo-presence-u1", Records: []string{"a"}},
		{Service: "sbo-presence-u2"},
	}
	got := CheckPresenceAll(infos)
	for i, p := range got {
		if p != PresenceUnavailable {
			t.Errorf("service %d = %s, want %s", i, p, PresenceUnavailable)
		}
	}
}

// TestCheckPresenceAllKeepsUnknown: with a readable keychain, a service
// without fixed record names stays unknown.
func TestCheckPresenceAllKeepsUnknown(t *testing.T) {
	got := CheckPresenceAll([]ServiceInfo{
		{Service: "sbo-presence-k1", Records: []string{"a"}},
		{Service: "sbo-presence-k2"},
	})
	if got[0] != PresenceAbsent || got[1] != PresenceUnknown {
		t.Errorf("got %v, want [absent unknown]", got)
	}
}
