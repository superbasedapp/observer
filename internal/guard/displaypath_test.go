package guard

import "testing"

// TestHomeTilde pins the D-704 gap 5 display rewrite, one case per row.
func TestHomeTilde(t *testing.T) {
	t.Parallel()
	const home = "/home/dev"
	cases := []struct {
		name, text, home, want string
	}{
		{
			"bundle read error names the path twice",
			"org bundle /home/dev/.observer/org-policy-bundle.json: read /home/dev/.observer/org-policy-bundle.json: is a directory", home,
			"org bundle ~/.observer/org-policy-bundle.json: read ~/.observer/org-policy-bundle.json: is a directory",
		},
		{"path in parentheses", "restored (/home/dev/.observer/governance-effective.json)", home, "restored (~/.observer/governance-effective.json)"},
		{"home itself at the end", "HOME is /home/dev", home, "HOME is ~"},
		{"trailing separator on home", "in /home/dev/.claude/settings.json", "/home/dev/", "in ~/.claude/settings.json"},
		{"a sibling account is left alone", "in /home/dev2/.claude/settings.json", home, "in /home/dev2/.claude/settings.json"},
		{"a longer path ending in the same run is left alone", "in /mnt/home/dev/x", home, "in /mnt/home/dev/x"},
		{"non-ascii continuation is left alone", "in /home/devé/x", home, "in /home/devé/x"},
		{"outside home is unchanged", "in /etc/observer/config.toml", home, "in /etc/observer/config.toml"},
		{
			"windows home, both spellings",
			`read C:\Users\dev\.observer\org-policy-bundle.json and C:/Users/dev/.observer/x`, `C:\Users\dev`,
			`read ~\.observer\org-policy-bundle.json and ~/.observer/x`,
		},
		{"empty home is a no-op", "in /home/dev/x", "", "in /home/dev/x"},
		{"root home is a no-op", "in /home/dev/x", "/", "in /home/dev/x"},
		{"empty text", "", home, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := HomeTilde(tc.text, tc.home); got != tc.want {
				t.Fatalf("HomeTilde(%q, %q) = %q, want %q", tc.text, tc.home, got, tc.want)
			}
		})
	}
}
