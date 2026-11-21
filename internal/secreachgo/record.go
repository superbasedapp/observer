package secreachgo

import (
	"encoding/json"
	"fmt"
	"sort"
)

// RecordImports is one OSV record's Go affected entries, per module.
type RecordImports struct {
	ID      string
	Aliases []string
	// Modules maps an affected Go module path ("stdlib" for the standard
	// library) to what its entries list; a module whose entries list no
	// imports maps to an empty ModuleImports.
	Modules map[string]ModuleImports
}

// ModuleImports is what a record lists for one module: the packages, each
// with its symbols (empty: the whole package).
type ModuleImports struct {
	Packages []PackageSymbols
}

// PackageSymbols is one listed package.
type PackageSymbols struct {
	Path    string
	Symbols []string
}

// osvRecord is the part of an OSV record ParseRecord reads: ids and the Go
// affected entries' imports (never the summary or details).
type osvRecord struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		EcosystemSpecific struct {
			Imports []struct {
				Path    string   `json:"path"`
				Symbols []string `json:"symbols"`
			} `json:"imports"`
		} `json:"ecosystem_specific"`
	} `json:"affected"`
}

// ParseRecord reads one OSV record's Go entries. Entries of the same
// module merge; a package listed twice keeps the union of its symbols (an
// entry with none makes it the whole package).
func ParseRecord(raw []byte) (RecordImports, error) {
	var r osvRecord
	if err := json.Unmarshal(raw, &r); err != nil {
		return RecordImports{}, fmt.Errorf("secreachgo.ParseRecord: %w", err)
	}
	out := RecordImports{ID: r.ID, Aliases: append([]string(nil), r.Aliases...), Modules: map[string]ModuleImports{}}
	type pkgAcc struct {
		whole bool
		syms  map[string]bool
	}
	acc := map[string]map[string]*pkgAcc{}
	for _, a := range r.Affected {
		if a.Package.Ecosystem != "Go" || a.Package.Name == "" {
			continue
		}
		mod := a.Package.Name
		if acc[mod] == nil {
			acc[mod] = map[string]*pkgAcc{}
		}
		for _, imp := range a.EcosystemSpecific.Imports {
			if imp.Path == "" {
				continue
			}
			p := acc[mod][imp.Path]
			if p == nil {
				p = &pkgAcc{syms: map[string]bool{}}
				acc[mod][imp.Path] = p
			}
			if len(imp.Symbols) == 0 {
				p.whole = true
			}
			for _, s := range imp.Symbols {
				if s != "" {
					p.syms[s] = true
				}
			}
		}
	}
	for mod, pkgs := range acc {
		mi := ModuleImports{}
		paths := make([]string, 0, len(pkgs))
		for p := range pkgs {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		for _, p := range paths {
			ps := PackageSymbols{Path: p}
			if !pkgs[p].whole {
				for s := range pkgs[p].syms {
					ps.Symbols = append(ps.Symbols, s)
				}
				sort.Strings(ps.Symbols)
			}
			mi.Packages = append(mi.Packages, ps)
		}
		out.Modules[mod] = mi
	}
	return out, nil
}
