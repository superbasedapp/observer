//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"sync"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/secscan/scalibrfacade"
)

// security_scan_now_extractors.go hands the Code security page's Coverage
// tab the linked dependency extractors (the SCALIBR facade's closed table),
// through the scan-now seam: the dashboard may not import the facade itself
// (tests/invariant/security_scan_egress_test.go). The list is built once:
// each call to scalibrfacade.Extractors constructs every extractor. A build
// without SCALIBR (sbo_omit_security_scan_scalibr) answers ErrNotCompiled,
// and the tab's file lists then come from depscan's own tables only.

func init() {
	scanNowExtractors = sync.OnceValue(func() []dashapi.SecurityExtractor {
		infos, err := scalibrfacade.Extractors()
		if err != nil {
			return nil
		}
		out := make([]dashapi.SecurityExtractor, 0, len(infos))
		for _, in := range infos {
			out = append(out, dashapi.SecurityExtractor{Kind: in.Kind, Ecosystem: in.Ecosystem, Files: in.Files})
		}
		return out
	})
}
