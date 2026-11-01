package managedsettings

import (
	"fmt"
	"sort"
	"strings"
)

// StrengthLabel is the plain-language name of a Strength.
func StrengthLabel(s Strength) string {
	switch s {
	case StrengthTamperProof:
		return "Tamper-proof: the tool enforces it and only an administrator can change it"
	case StrengthLaunchReset:
		return "Re-applied at every launch: a developer can change it for one session only"
	case StrengthRestrictOnly:
		return "Restrict only: the layer can deny or ask, never set a value"
	case StrengthDefaultOnly:
		return "Default only: an administrator default the developer's own files override"
	case StrengthTamperEvident:
		return "Tamper-evident only: Observer writes it and reports a hand edit, but cannot prevent one"
	}
	return string(s)
}

// ReasonLabel explains a skip reason.
func ReasonLabel(r string) string {
	switch r {
	case ReasonProjectScope:
		return "a per-project value: a device-wide managed layer cannot hold it (Observer still applies it on managed machines)"
	case ReasonNoManagedLayer:
		return "the tool has no administrator-managed settings layer (Observer still applies it on managed machines, tamper-evident)"
	case ReasonNotInLayer:
		return "the tool's managed layer does not carry this setting"
	case ReasonNoDefaultLayer:
		return "the tool has no administrator default layer for a default value (Observer still applies it on managed machines)"
	case ReasonUnknownSetting:
		return "not in the settings catalogue"
	case ReasonUndecodable:
		return "the value is not valid JSON"
	case ReasonValueNotWritten:
		return "the value does not fit the managed file's format"
	}
	return r
}

var osLabel = map[string]string{"linux": "Linux", "darwin": "macOS", "windows": "Windows"}

func toolReadme(t ToolBundle) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s: administrator-managed settings\n\n", t.Tool)
	if len(t.Placed) == 0 {
		b.WriteString("The policy sets nothing this tool's managed layer can carry.\n")
	} else {
		fmt.Fprintf(&b, "Firmest hold: %s.\n\n", StrengthLabel(t.Strength))
		b.WriteString("## Values\n\n")
		for _, p := range t.Placed {
			line := fmt.Sprintf("- `%s` (%s) -> `%s` in %s: %s", p.Setting, p.Mode, p.Key, p.FileID, StrengthLabel(p.Strength))
			if p.Derived != "" {
				line += " (derived: " + p.Derived + ")"
			}
			b.WriteString(line + "\n")
		}
		b.WriteString("\n")
	}
	if len(t.Skipped) > 0 {
		b.WriteString("## Not carried by the managed layer\n\n")
		for _, s := range t.Skipped {
			fmt.Fprintf(&b, "- `%s` (%s): %s\n", s.Setting, s.Mode, ReasonLabel(s.Reason))
		}
		b.WriteString("\n")
	}
	for _, a := range t.Artifacts {
		fmt.Fprintf(&b, "## %s\n\n", a.Name)
		if a.Note != "" {
			b.WriteString(a.Note + "\n\n")
		}
		if w := ObserverWiring(a.FileID); w != "" {
			b.WriteString("Observer's own route and hooks: " + w + "\n\n")
		}
		oses := make([]string, 0, len(a.Strength))
		for o := range a.Strength {
			oses = append(oses, o)
		}
		sort.Strings(oses)
		for _, o := range oses {
			fmt.Fprintf(&b, "- %s: %s\n", osLabel[o], StrengthLabel(a.Strength[o]))
		}
		b.WriteString("\n")
		for _, st := range a.Install {
			if st.Path != "" {
				fmt.Fprintf(&b, "%s, to `%s`:\n\n", osLabel[st.OS], st.Path)
			} else {
				fmt.Fprintf(&b, "%s:\n\n", osLabel[st.OS])
			}
			for _, s := range st.Steps {
				fmt.Fprintf(&b, "    %s\n", s)
			}
			b.WriteString("\n")
		}
	}
	if len(t.Sources) > 0 {
		b.WriteString("## Vendor documentation\n\n")
		for _, s := range t.Sources {
			b.WriteString("- " + s + "\n")
		}
		if t.Verified != "doc" {
			b.WriteString("\nAt least one layer here is not confirmed by the vendor's documentation: test on one machine before a fleet rollout.\n")
		}
	}
	return b.String()
}

func bundleReadme(bd Bundle) string {
	var b strings.Builder
	b.WriteString("# Observer AI tool policy: device management artifacts\n\n")
	fmt.Fprintf(&b, "Generated from the org AI tool policy for %s, version %d", bd.Audience, bd.PolicyVersion)
	if len(bd.Policies) > 0 {
		fmt.Fprintf(&b, " (documents: %s)", strings.Join(bd.Policies, ", "))
	}
	b.WriteString(".\n\n")
	b.WriteString("Observer applies the same policy on managed machines by writing each tool's own user files and\n")
	b.WriteString("reporting any hand edit (tamper-evident). The files here put the ENFORCED values into each tool's\n")
	b.WriteString("administrator-managed settings layer instead, which the tool itself enforces and a developer\n")
	b.WriteString("cannot change: deploy them with your device management to make the lock tamper-proof where the\n")
	b.WriteString("vendor offers one. Policy DEFAULTS go only to a vendor's lowest administrator layer, never to an\n")
	b.WriteString("override layer. Per-project values stay with Observer (a managed layer is device-wide).\n\n")
	b.WriteString("Regenerate and redeploy after every policy change: these files do not update themselves.\n\n")
	if len(bd.Tools) > 0 {
		b.WriteString("## Tools in this bundle\n\n")
		for _, t := range bd.Tools {
			fmt.Fprintf(&b, "- %s: %d value(s), %s. See %s/README.md.\n", t.Tool, len(t.Placed), StrengthLabel(t.Strength), t.Tool)
		}
		b.WriteString("\n")
	}
	if len(bd.Unplaced) > 0 {
		b.WriteString("## Values no managed layer carries\n\n")
		for _, s := range bd.Unplaced {
			fmt.Fprintf(&b, "- `%s` (%s): %s\n", s.Setting, s.Mode, ReasonLabel(s.Reason))
		}
		b.WriteString("\n")
	}
	b.WriteString("## What each tool can lock\n\n")
	b.WriteString("| Tool | Linux | macOS | Windows | Note |\n|---|---|---|---|---|\n")
	for _, l := range bd.Locks {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", l.Tool, short(l.PerOS["linux"]), short(l.PerOS["darwin"]), short(l.PerOS["windows"]),
			strings.ReplaceAll(l.Note, "|", "/"))
	}
	return b.String()
}

func short(s Strength) string {
	switch s {
	case StrengthTamperProof:
		return "tamper-proof"
	case StrengthLaunchReset:
		return "re-applied each launch"
	case StrengthRestrictOnly:
		return "restrict only"
	case StrengthDefaultOnly:
		return "default only"
	}
	return "tamper-evident"
}
