package orgcontract

import (
	"reflect"
	"testing"
)

// TestProjectRemoteForms is the forms table, one row per hard case: the exact
// form always comes first (it is the hash nodes already ship); a
// case-insensitive host adds the lowercased path; every Azure DevOps shape
// adds the one canonical form; a self-hosted host adds nothing.
func TestProjectRemoteForms(t *testing.T) {
	const ado = "dev.azure.com/acme/proj/_git/billing"
	rows := []struct {
		name, in string
		want     []string
	}{
		{"lowercase github path", "github.com/acme/widget", []string{"github.com/acme/widget"}},
		{"mixed-case github path", "github.com/Acme/Widget", []string{"github.com/Acme/Widget", "github.com/acme/widget"}},
		{"gitlab.com", "gitlab.com/Group/Repo", []string{"gitlab.com/Group/Repo", "gitlab.com/group/repo"}},
		{"bitbucket.org", "bitbucket.org/Team/Repo", []string{"bitbucket.org/Team/Repo", "bitbucket.org/team/repo"}},
		{"self-hosted host keeps its case", "gitlab.example.com/Group/Repo", []string{"gitlab.example.com/Group/Repo"}},
		{"azure devops https", "dev.azure.com/Acme/Proj/_git/Billing", []string{"dev.azure.com/Acme/Proj/_git/Billing", ado}},
		{"azure devops https, already canonical", ado, []string{ado}},
		{"azure devops ssh", "ssh.dev.azure.com/v3/acme/proj/billing", []string{"ssh.dev.azure.com/v3/acme/proj/billing", ado}},
		{"visualstudio.com https", "acme.visualstudio.com/proj/_git/billing", []string{"acme.visualstudio.com/proj/_git/billing", ado}},
		{
			"visualstudio.com DefaultCollection", "acme.visualstudio.com/DefaultCollection/proj/_git/billing",
			[]string{"acme.visualstudio.com/DefaultCollection/proj/_git/billing", "acme.visualstudio.com/defaultcollection/proj/_git/billing", ado},
		},
		{"visualstudio.com ssh", "vs-ssh.visualstudio.com/v3/acme/proj/billing", []string{"vs-ssh.visualstudio.com/v3/acme/proj/billing", ado}},
		{"empty", "", nil},
	}
	for _, row := range rows {
		if got := ProjectRemoteForms(row.in); !reflect.DeepEqual(got, row.want) {
			t.Errorf("%s: ProjectRemoteForms(%q) = %q, want %q", row.name, row.in, got, row.want)
		}
	}
}
