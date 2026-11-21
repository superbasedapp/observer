package secreach

// matchNPMRecord decides an npm finding at import level: the package name
// the finding names against the npm packages project files import (the
// key ImportKey derives from each specifier). npm records list no
// functions, so there is no call level.
func matchNPMRecord(adv Advisory, _ Record, set ImportSet, _ []string) Tier {
	u, found := set.Uses[adv.Package]
	match := ""
	if found {
		match = adv.Package
	}
	return decide(set, found, u.NonTest, match)
}
