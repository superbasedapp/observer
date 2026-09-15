package integration

import (
	"slices"
	"testing"
)

func TestInterventionSurfacesCoverRegistry(t *testing.T) {
	t.Parallel()

	tools := Tools()
	if len(tools) != 45 {
		t.Fatalf("Tools() = %d, want 45; update the intervention declarations for every new registry row", len(tools))
	}
	seen := make(map[string]bool)
	for _, surface := range AllInterventionSurfaces() {
		if seen[surface.ID] {
			t.Errorf("duplicate surface ID %q", surface.ID)
		}
		seen[surface.ID] = true
		if surface.Class == SurfaceUnclassified {
			t.Errorf("registry tool %q has no intervention declaration", surface.Tool)
		}
	}
	for _, tool := range tools {
		surfaces, ok := InterventionFor(tool)
		if !ok || len(surfaces) == 0 {
			t.Errorf("InterventionFor(%q) = %d rows, ok=%v", tool, len(surfaces), ok)
		}
	}
}

func TestInterventionDedicatedSurfacesAreCapabilityShaped(t *testing.T) {
	t.Parallel()

	for _, surface := range AllInterventionSurfaces() {
		switch surface.Class {
		case SurfaceDedicatedProcess:
			switch surface.NativeUsage {
			case NativeUsageUnavailable, NativeUsageApproximate, NativeUsagePresent:
			default:
				t.Errorf("dedicated surface %q has invalid native usage kind %q", surface.ID, surface.NativeUsage)
			}
			if surface.Binary == nil && surface.Binding.UnsupportedReason == "" {
				t.Errorf("dedicated surface %q has no registry Binary capability", surface.ID)
			}
			binding := surface.Binding
			if !binding.AllowNative && len(binding.Interpreters) == 0 && len(binding.Workers) == 0 && binding.UnsupportedReason == "" {
				t.Errorf("dedicated surface %q declares neither a binding nor an unsupported reason", surface.ID)
			}
			if (binding.AllowNative || len(binding.Interpreters) > 0 || len(binding.Workers) > 0) && !binding.Invocation.AllowsCLI() {
				t.Errorf("dedicated process surface %q has no explicit CLI invocation classifier", surface.ID)
			}
			seen := make(map[string]string)
			for class, values := range map[string][]string{
				"cli":     binding.Invocation.CLILeadingArguments,
				"non_cli": binding.Invocation.NonCLILeadingArguments,
			} {
				for _, value := range values {
					if value == "" {
						t.Errorf("dedicated surface %q has an empty %s leading argument", surface.ID, class)
					}
					if prior := seen[value]; prior != "" {
						t.Errorf("dedicated surface %q classifies leading argument %q as both %s and %s", surface.ID, value, prior, class)
					}
					seen[value] = class
				}
			}
		case SurfaceSharedHost, SurfaceRemoteExecution:
			if surface.NativeUsage != NativeUsageUnavailable {
				t.Errorf("unsupported surface %q carries native usage kind %q", surface.ID, surface.NativeUsage)
			}
			if surface.Binary != nil || surface.Binding.AllowNative || len(surface.Binding.Interpreters) != 0 || len(surface.Binding.Workers) != 0 {
				t.Errorf("unsupported surface %q carries a process binding", surface.ID)
			}
		default:
			t.Errorf("surface %q has unexpected class %q", surface.ID, surface.Class)
		}
	}
}

func TestInterventionNativeUsageIsSurfaceSpecific(t *testing.T) {
	t.Parallel()

	for _, id := range []string{"freebuff/cli", "qoder/cli"} {
		surface := interventionSurfaceByID(t, id)
		if surface.NativeUsage != NativeUsageUnavailable || surface.NativeUsage.Available() {
			t.Errorf("surface %q native usage = %q, available=%v; want unavailable", id, surface.NativeUsage, surface.NativeUsage.Available())
		}
	}

	for _, surface := range AllInterventionSurfaces() {
		if surface.Class != SurfaceSharedHost && surface.Class != SurfaceRemoteExecution {
			continue
		}
		if surface.NativeUsage != NativeUsageUnavailable || surface.NativeUsage.Available() {
			t.Errorf("unsupported surface %q native usage = %q, available=%v; want unavailable", surface.ID, surface.NativeUsage, surface.NativeUsage.Available())
		}
	}

	if !NativeUsageApproximate.Available() || !NativeUsagePresent.Available() {
		t.Error("approximate and present native usage must both be available")
	}
}

func interventionSurfaceByID(t *testing.T, id string) InterventionSurfaceSpec {
	t.Helper()
	for _, surface := range AllInterventionSurfaces() {
		if surface.ID == id {
			return surface
		}
	}
	t.Fatalf("intervention surface %q not found", id)
	return InterventionSurfaceSpec{}
}

func TestInterventionGroundedIndirectWorkers(t *testing.T) {
	t.Parallel()

	codex, ok := InterventionFor("codex")
	if !ok || len(codex) < 1 {
		t.Fatal("codex intervention surface missing")
	}
	if got := codex[0].Binding.Workers; len(got) != 6 {
		t.Fatalf("codex worker layouts = %d, want six exact Linux package paths", len(got))
	} else {
		for _, worker := range got {
			if worker.Kind != WorkerExactRelative || worker.Relative == "" || worker.Prefix != "" {
				t.Errorf("codex worker declaration = %+v, want exact relative path", worker)
			}
		}
	}
	invocation := codex[0].Binding.Invocation
	if !invocation.AllowNoArguments || invocation.RequireDeclaredCLI ||
		!slices.Equal(invocation.CLILeadingArguments, []string{"exec", "fork", "resume", "review"}) ||
		!slices.Contains(invocation.NonCLILeadingArguments, "app-server") ||
		!slices.Contains(invocation.NonCLILeadingArguments, "mcp-server") {
		t.Fatalf("codex native invocation declaration = %+v", invocation)
	}

	muse, ok := InterventionFor("muse")
	if !ok || len(muse) != 1 {
		t.Fatalf("muse intervention surfaces = %d, ok=%v", len(muse), ok)
	}
	workers := muse[0].Binding.Workers
	if len(workers) != 1 || workers[0].Kind != WorkerVersionedSibling || workers[0].Prefix != "muse-bin-" {
		t.Fatalf("muse worker declaration = %+v", workers)
	}
	if invocation := muse[0].Binding.Invocation; !invocation.AllowNoArguments || invocation.RequireDeclaredCLI ||
		!slices.Equal(invocation.CLILeadingArguments, []string{"exec"}) ||
		!slices.Contains(invocation.NonCLILeadingArguments, "export") ||
		!slices.Contains(invocation.NonCLILeadingArguments, "-V") ||
		slices.Contains(invocation.NonCLILeadingArguments, "resume") {
		t.Fatalf("muse invocation declaration = %+v", muse[0].Binding.Invocation)
	}
}

// TestInterventionInvocationIsGovernedByDefault pins the inverted contract on
// the registry side: every dedicated-process surface inherits the universal
// non-billable set, keeps its declared CLI arguments out of that set, and only
// fails closed when it explicitly declares itself ambiguous.
func TestInterventionInvocationIsGovernedByDefault(t *testing.T) {
	t.Parallel()

	universal := universalNonBillableLeadingArguments()
	if len(universal) == 0 {
		t.Fatal("universal non-billable set is empty")
	}
	for _, surface := range AllInterventionSurfaces() {
		if surface.Class != SurfaceDedicatedProcess {
			continue
		}
		invocation := surface.Binding.Invocation
		declaredCLI := make(map[string]bool, len(invocation.CLILeadingArguments))
		for _, argument := range invocation.CLILeadingArguments {
			declaredCLI[argument] = true
		}
		for _, argument := range universal {
			if declaredCLI[argument] {
				// A row may reclaim a universal spelling as billable; it must
				// then stay out of the non-billable set.
				if slices.Contains(invocation.NonCLILeadingArguments, argument) {
					t.Errorf("surface %q declares %q as both CLI and non-billable", surface.ID, argument)
				}
				continue
			}
			if !slices.Contains(invocation.NonCLILeadingArguments, argument) {
				t.Errorf("surface %q is missing universal non-billable argument %q", surface.ID, argument)
			}
		}
		seen := make(map[string]bool, len(invocation.NonCLILeadingArguments))
		for _, argument := range invocation.NonCLILeadingArguments {
			if seen[argument] {
				t.Errorf("surface %q repeats non-billable argument %q", surface.ID, argument)
			}
			seen[argument] = true
		}
		// A fail-closed row must name at least one CLI form, otherwise it
		// declares a surface that can never be governed at all.
		if invocation.RequireDeclaredCLI && !invocation.AllowsCLI() {
			t.Errorf("surface %q requires a declared CLI form but declares none", surface.ID)
		}
		if !invocation.RequireDeclaredCLI && !invocation.AllowsCLI() {
			t.Errorf("surface %q is in inverted mode but reports no CLI form", surface.ID)
		}
	}
}

// TestNonBillableLeadingArgumentsIsTheSingleOwner pins the seam an Observer
// launch gate derives its maintenance vocabulary from, so the launch gate and
// the process controller cannot drift apart.
func TestNonBillableLeadingArgumentsIsTheSingleOwner(t *testing.T) {
	t.Parallel()

	if got := NonBillableLeadingArguments("not-a-tool"); got != nil {
		t.Fatalf("NonBillableLeadingArguments(unknown) = %v", got)
	}
	if got := NonBillableLeadingArguments("cline"); len(got) != 0 {
		t.Fatalf("shared-host-only tool exposed non-billable arguments: %v", got)
	}
	for _, tool := range []string{"muse", "cursor", "codex", "zcode", "claude-code"} {
		got := NonBillableLeadingArguments(tool)
		if !slices.IsSorted(got) {
			t.Errorf("NonBillableLeadingArguments(%q) = %v, want sorted", tool, got)
		}
		surfaces, _ := InterventionFor(tool)
		for _, argument := range universalNonBillableLeadingArguments() {
			if toolDeclaresCLIArgument(surfaces, argument) {
				// A row may reclaim a universal spelling as billable.
				if slices.Contains(got, argument) {
					t.Errorf("NonBillableLeadingArguments(%q) contains reclaimed CLI argument %q", tool, argument)
				}
				continue
			}
			if !slices.Contains(got, argument) {
				t.Errorf("NonBillableLeadingArguments(%q) is missing %q", tool, argument)
			}
		}
	}
	for _, argument := range cursorBillableArguments() {
		if slices.Contains(NonBillableLeadingArguments("cursor"), argument) {
			t.Errorf("cursor non-billable arguments wrongly include reclaimed %q", argument)
		}
	}
	muse := NonBillableLeadingArguments("muse")
	for _, argument := range museNonBillableArguments() {
		if !slices.Contains(muse, argument) {
			t.Errorf("muse non-billable arguments missing grounded %q", argument)
		}
	}
	for _, billable := range []string{"exec", "resume", "session-message", "sandbox"} {
		if slices.Contains(muse, billable) {
			t.Errorf("muse non-billable arguments wrongly include %q", billable)
		}
	}
	cursor := NonBillableLeadingArguments("cursor")
	for _, argument := range cursorNonBillableArguments() {
		if !slices.Contains(cursor, argument) {
			t.Errorf("cursor non-billable arguments missing grounded %q", argument)
		}
	}
	for _, billable := range []string{"agent", "resume", "create-chat", "worker"} {
		if slices.Contains(cursor, billable) {
			t.Errorf("cursor non-billable arguments wrongly include %q", billable)
		}
	}
}

func toolDeclaresCLIArgument(surfaces []InterventionSurfaceSpec, argument string) bool {
	for _, surface := range surfaces {
		if surface.Class != SurfaceDedicatedProcess {
			continue
		}
		if slices.Contains(surface.Binding.Invocation.CLILeadingArguments, argument) {
			return true
		}
	}
	return false
}

func TestComposeInvocationMergesWithoutContradiction(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		in         InvocationSpec
		wantHas    []string
		wantMisses []string
	}{
		{
			name:       "empty row inherits the universal set",
			in:         InvocationSpec{AllowNoArguments: true},
			wantHas:    []string{"serve", "mcp", "login", "--version"},
			wantMisses: []string{"run"},
		},
		{
			name:       "declared CLI argument wins over the universal set",
			in:         InvocationSpec{AllowNoArguments: true, CLILeadingArguments: []string{"config", "serve"}},
			wantHas:    []string{"mcp", "login"},
			wantMisses: []string{"config", "serve"},
		},
		{
			name:    "row extras survive and are not duplicated",
			in:      InvocationSpec{AllowNoArguments: true, NonCLILeadingArguments: []string{"trace", "login", "", "trace"}},
			wantHas: []string{"trace", "login", "serve"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := composeInvocation(tc.in)
			for _, argument := range tc.wantHas {
				if !slices.Contains(got.NonCLILeadingArguments, argument) {
					t.Errorf("composed non-billable set missing %q: %v", argument, got.NonCLILeadingArguments)
				}
			}
			for _, argument := range tc.wantMisses {
				if slices.Contains(got.NonCLILeadingArguments, argument) {
					t.Errorf("composed non-billable set wrongly contains %q: %v", argument, got.NonCLILeadingArguments)
				}
			}
			seen := make(map[string]bool, len(got.NonCLILeadingArguments))
			for _, argument := range got.NonCLILeadingArguments {
				if argument == "" {
					t.Error("composed non-billable set contains an empty argument")
				}
				if seen[argument] {
					t.Errorf("composed non-billable set repeats %q", argument)
				}
				seen[argument] = true
			}
		})
	}
}

func TestInterventionForUnknownTool(t *testing.T) {
	t.Parallel()

	if surfaces, ok := InterventionFor("not-a-tool"); ok || surfaces != nil {
		t.Fatalf("InterventionFor(unknown) = %+v, %v", surfaces, ok)
	}
}
