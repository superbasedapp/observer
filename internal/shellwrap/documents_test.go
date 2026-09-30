package shellwrap

import (
	"errors"
	"testing"
)

func TestResolveDocumentsDirLadder(t *testing.T) {
	ok := func(v string) func() (string, error) { return func() (string, error) { return v, nil } }
	fail := func() (string, error) { return "", errors.New("lookup failed") }
	env := map[string]string{"USERPROFILE": `C:\Users\x`, "OneDrive": `C:\Users\x\OneDrive`}
	getenv := func(k string) string { return env[k] }
	const home = `C:\Users\x`

	cases := []struct {
		name       string
		l          DocumentsLookup
		want       string
		wantSource DocumentsSource
		wantOK     bool
	}{
		{
			"known folder wins (OneDrive redirect)",
			DocumentsLookup{KnownFolder: ok(`C:\Users\x\OneDrive\Documents`), ShellFolder: ok(`%USERPROFILE%\Documents`), Getenv: getenv, Home: home},
			`C:\Users\x\OneDrive\Documents`, DocumentsKnownFolder, true,
		},
		{
			"known folder with an org OneDrive name",
			DocumentsLookup{KnownFolder: ok(`C:\Users\x\OneDrive - Contoso\Documents`), Home: home},
			`C:\Users\x\OneDrive - Contoso\Documents`, DocumentsKnownFolder, true,
		},
		{
			"known folder trailing separator trimmed",
			DocumentsLookup{KnownFolder: ok(`D:\Docs\`), Home: home},
			`D:\Docs`, DocumentsKnownFolder, true,
		},
		{
			"known folder fails -> registry, %USERPROFILE% expanded",
			DocumentsLookup{KnownFolder: fail, ShellFolder: ok(`%USERPROFILE%\OneDrive\Documents`), Getenv: getenv, Home: home},
			`C:\Users\x\OneDrive\Documents`, DocumentsShellFolders, true,
		},
		{
			"known folder empty -> registry with two references",
			DocumentsLookup{KnownFolder: ok(""), ShellFolder: ok(`%OneDrive%\Documents`), Getenv: getenv, Home: home},
			`C:\Users\x\OneDrive\Documents`, DocumentsShellFolders, true,
		},
		{
			"registry already absolute (folder redirection to a share)",
			DocumentsLookup{ShellFolder: ok(`\\fs01\home$\x\Documents`), Getenv: getenv, Home: home},
			`\\fs01\home$\x\Documents`, DocumentsShellFolders, true,
		},
		{
			"registry names an unset variable -> home default",
			DocumentsLookup{KnownFolder: fail, ShellFolder: ok(`%NOPE%\Documents`), Getenv: getenv, Home: home},
			`C:\Users\x\Documents`, DocumentsHomeDefault, true,
		},
		{
			"registry unterminated reference -> home default",
			DocumentsLookup{ShellFolder: ok(`%USERPROFILE\Documents`), Getenv: getenv, Home: home},
			`C:\Users\x\Documents`, DocumentsHomeDefault, true,
		},
		{
			"registry relative after expansion -> home default",
			DocumentsLookup{ShellFolder: ok(`Documents`), Getenv: getenv, Home: home},
			`C:\Users\x\Documents`, DocumentsHomeDefault, true,
		},
		{
			"known folder not absolute is refused",
			DocumentsLookup{KnownFolder: ok(`C:Documents`), ShellFolder: fail, Home: home},
			`C:\Users\x\Documents`, DocumentsHomeDefault, true,
		},
		{
			"known folder with a quote is refused",
			DocumentsLookup{KnownFolder: ok(`C:\a"b`), Home: home},
			`C:\Users\x\Documents`, DocumentsHomeDefault, true,
		},
		{
			"nil lookups -> home default",
			DocumentsLookup{Home: home + `\`},
			`C:\Users\x\Documents`, DocumentsHomeDefault, true,
		},
		{
			"nil getenv cannot expand -> home default",
			DocumentsLookup{ShellFolder: ok(`%USERPROFILE%\Documents`), Home: home},
			`C:\Users\x\Documents`, DocumentsHomeDefault, true,
		},
		{
			"everything failed, no home",
			DocumentsLookup{KnownFolder: fail, ShellFolder: fail},
			"", "", false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, src, gotOK := ResolveDocumentsDir(tc.l)
			if got != tc.want || src != tc.wantSource || gotOK != tc.wantOK {
				t.Fatalf("got %q %q %v, want %q %q %v", got, src, gotOK, tc.want, tc.wantSource, tc.wantOK)
			}
		})
	}
}

// TestPowerShellTargetsFollowTheResolvedDocuments pins that the resolved
// folder is what the PowerShell rows of the start-up-file table use.
func TestPowerShellTargetsFollowTheResolvedDocuments(t *testing.T) {
	docs, _, _ := ResolveDocumentsDir(DocumentsLookup{
		KnownFolder: func() (string, error) { return `C:\Users\x\OneDrive\Documents`, nil },
		Home:        `C:\Users\x`,
	})
	h := hostWith("windows")
	h.DocumentsDir = docs
	got := RCTargets(ShellPowerShell, h)
	want := `C:\Users\x\OneDrive\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1`
	if len(got) != 1 || got[0] != want {
		t.Fatalf("targets %v, want [%s]", got, want)
	}
}
