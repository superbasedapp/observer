package staffauth

import (
	"errors"
	"testing"
)

func TestValidateAllowlistEntry(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, kind, value string
		want              AllowlistEntry
		ok                bool
	}{
		{"account id", "account", "0F8FAD5B-D9CB-469F-A165-70867728950E", AllowlistEntry{AllowlistAccount, "0f8fad5b-d9cb-469f-a165-70867728950e"}, true},
		{"account not a uuid", "account", "bob", AllowlistEntry{}, false},
		{"account in braces", "account", "{0f8fad5b-d9cb-469f-a165-70867728950e}", AllowlistEntry{}, false},
		{"domain", "email_domain", "Example.COM", AllowlistEntry{AllowlistEmailDomain, "example.com"}, true},
		{"domain with at and dot", "email_domain", " @marmut.app. ", AllowlistEntry{AllowlistEmailDomain, "marmut.app"}, true},
		{"subdomain", "email_domain", "eng.example.co.uk", AllowlistEntry{AllowlistEmailDomain, "eng.example.co.uk"}, true},
		{"an address is refused", "email_domain", "alice@example.com", AllowlistEntry{}, false},
		{"single label", "email_domain", "localhost", AllowlistEntry{}, false},
		{"wildcard", "email_domain", "*.example.com", AllowlistEntry{}, false},
		{"leading hyphen", "email_domain", "-x.example.com", AllowlistEntry{}, false},
		{"empty", "email_domain", "", AllowlistEntry{}, false},
		{"unknown kind", "email", "example.com", AllowlistEntry{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got, err := ValidateAllowlistEntry(c.kind, c.value)
			if (err == nil) != c.ok {
				t.Fatalf("err = %v, want ok=%v", err, c.ok)
			}
			if err != nil && !errors.Is(err, ErrAllowlistEntry) {
				t.Fatalf("err %v does not wrap ErrAllowlistEntry", err)
			}
			if got != c.want {
				t.Fatalf("got %+v, want %+v", got, c.want)
			}
		})
	}
}
