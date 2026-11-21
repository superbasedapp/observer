package seclicense

import "testing"

func TestNormalize(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"  ", ""},
		{"MIT", "MIT"},
		{"mit", "MIT"},
		{"MIT License", "MIT"},
		{"The MIT License", "MIT"},
		{"Expat", "MIT"},
		{"Apache 2.0", "Apache-2.0"},
		{"Apache-2", "Apache-2.0"},
		{"apache-2.0", "Apache-2.0"},
		{"Apache License 2.0", "Apache-2.0"},
		{"Apache License, Version 2.0", "Apache-2.0"},
		{"BSD", "BSD"},
		{"New BSD License", "BSD-3-Clause"},
		{"Simplified BSD", "BSD-2-Clause"},
		{"GPLv3", "GPL-3.0-only"},
		{"GPL-3", "GPL-3.0-only"},
		{"GNU GPL v3", "GPL-3.0-only"},
		{"GPLv3+", "GPL-3.0-or-later"},
		{"GPLv2", "GPL-2.0-only"},
		{"ISC License", "ISC"},
		{"Unlicense", "Unlicense"},
		{"The Unlicense", "Unlicense"},
		{"UNLICENSED", ProprietaryID},
		{"proprietary", ProprietaryID},
		{"SEE LICENSE IN LICENSE.md", SeeFileID},
		{"SEE LICENSE IN ./docs/LICENSE.txt", SeeFileID},
		{"GPL-2.0", "GPL-2.0-only"},
		{"GPL-2.0+", "GPL-2.0-or-later"},
		{"GPL-3.0", "GPL-3.0-only"},
		{"LGPL-2.1", "LGPL-2.1-only"},
		{"AGPL-3.0", "AGPL-3.0-only"},
		{"MPL 2.0", "MPL-2.0"},
		{"Some Custom Licence", "Some Custom Licence"},
		{"MIT OR Apache-2.0", "MIT OR Apache-2.0"},
		{"mit or apache 2.0", "MIT OR Apache-2.0"},
		{"(MIT OR Apache-2.0) AND BSD-3-Clause", "(MIT OR Apache-2.0) AND BSD-3-Clause"},
		{"MIT/Apache-2.0", "MIT OR Apache-2.0"},
		{"GPL-2.0 WITH Classpath-exception-2.0", "GPL-2.0-only WITH Classpath-exception-2.0"},
		{"Apache License 2.0 OR GPLv3", "Apache-2.0 OR GPL-3.0-only"},
	}
	for _, c := range cases {
		if got := Normalize(c.in); got != c.want {
			t.Errorf("Normalize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestClassTableRows checks every class table row classifies as its row
// says, through Classify, ClassOf and a lower-cased spelling.
func TestClassTableRows(t *testing.T) {
	for _, r := range classTable {
		if got := Classify(r.ID); got != r.Class {
			t.Errorf("Classify(%q) = %q, want %q", r.ID, got, r.Class)
		}
		if got := ClassOf(r.ID); got != r.Class {
			t.Errorf("ClassOf(%q) = %q, want %q", r.ID, got, r.Class)
		}
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		in   string
		want Class
	}{
		{"MIT", ClassPermissive},
		{"MIT License", ClassPermissive},
		{"MPL-2.0", ClassWeakCopyleft},
		{"GPL-3.0", ClassStrongCopyleft},
		{"AGPL-3.0-or-later", ClassNetworkCopyleft},
		{"BUSL-1.1", ClassSourceAvailable},
		{"PolyForm-Noncommercial-1.0.0", ClassSourceAvailable},
		{"PolyForm-Shield-1.0.0", ClassSourceAvailable},
		{"UNLICENSED", ClassProprietary},
		{"BSD", ClassUnknown},
		{"", ClassUnknown},
		{SeeFileID, ClassUnknown},
		{"Some Custom Licence", ClassUnknown},
		// OR takes the most permissive alternative.
		{"MIT OR GPL-3.0-only", ClassPermissive},
		{"GPL-3.0-only OR Custom", ClassStrongCopyleft},
		// AND takes the least permissive part.
		{"MIT AND GPL-3.0-only", ClassStrongCopyleft},
		{"MIT AND Custom", ClassUnknown},
		{"(MIT OR GPL-3.0-only) AND MPL-2.0", ClassWeakCopyleft},
		{"MIT OR (GPL-3.0-only AND AGPL-3.0-only)", ClassPermissive},
		// WITH keeps the base id's class.
		{"GPL-2.0-only WITH Classpath-exception-2.0", ClassStrongCopyleft},
		{"Apache-2.0 WITH LLVM-exception", ClassPermissive},
		// ... except an exception the exception table lists.
		{"Apache-2.0 WITH Commons-Clause", ClassSourceAvailable},
		// Malformed expressions are unknown.
		{"MIT OR", ClassUnknown},
		{"(MIT", ClassUnknown},
		{"MIT WITH", ClassUnknown},
		{"AND MIT", ClassUnknown},
	}
	for _, c := range cases {
		if got := Classify(c.in); got != c.want {
			t.Errorf("Classify(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDeprecatedTableTargetsClassified(t *testing.T) {
	for _, r := range deprecatedTable {
		if Normalize(r.From) != r.To {
			t.Errorf("Normalize(%q) = %q, want %q", r.From, Normalize(r.From), r.To)
		}
	}
}

func TestAliasTableRows(t *testing.T) {
	for _, r := range aliasTable {
		if got := Normalize(r.Alias); got != r.ID {
			t.Errorf("Normalize(%q) = %q, want %q", r.Alias, got, r.ID)
		}
		if r.Alias != collapse(r.Alias) {
			t.Errorf("alias %q is not in collapsed form", r.Alias)
		}
	}
}

// TestDeprecatedTargetsHaveAClass pins every deprecated id's current form
// to a class table row, so a deprecated spelling never falls to unknown.
func TestDeprecatedTargetsHaveAClass(t *testing.T) {
	for _, r := range deprecatedTable {
		if ClassOf(r.To) == ClassUnknown {
			t.Errorf("%q (from %q) has no class table row", r.To, r.From)
		}
	}
}
