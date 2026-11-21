package osvshard

import "strings"

// Spellings returns every name the node hashes for one package of an OSV
// ecosystem (plan section 13.11 item 1): the raw extractor name, and its
// reproduction of SCALIBR's osvutil.ParsePackage where that differs. The
// one ecosystem where it does today is Go: SCALIBR v0.5.3 lower-cases a Go
// PURL's namespace (ledger SECP-43), so the module path it compares is the
// raw one with every element but the last lower-cased. Fetching the union
// means a later SCALIBR fix needs no node change; spellings that
// canonicalise alike cost one prefix (osvshardkey.Prefixes).
func Spellings(ecosystem, name string) []string {
	if name == "" {
		return nil
	}
	out := []string{name}
	if ecosystem == "Go" {
		if i := strings.LastIndexByte(name, '/'); i > 0 {
			if r := strings.ToLower(name[:i]) + name[i:]; r != name {
				out = append(out, r)
			}
		}
	}
	return out
}
