package main

import (
	"strings"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// registryMaintenanceVocabulary splits one tool's registry-declared
// non-billable leading arguments into the subcommand and flag halves an
// Observer launch gate walks separately.
//
// The integration registry row is the ONE owner of "which invocations are
// billable" (see integration.NonBillableLeadingArguments): a launch gate that
// kept its own table would classify a raw vendor launch differently from the
// process controller that reads the same row, which is exactly the two-owner
// divergence the invocation-classification inversion removed. A launcher may
// still own its flag GRAMMAR — which flags consume a following value — because
// that is argv parsing, not a billability judgement.
func registryMaintenanceVocabulary(tool string) (subcommands, flags map[string]bool) {
	subcommands, flags = map[string]bool{}, map[string]bool{}
	for _, argument := range integration.NonBillableLeadingArguments(tool) {
		if strings.HasPrefix(argument, "-") {
			flags[argument] = true
			continue
		}
		subcommands[argument] = true
	}
	return subcommands, flags
}
