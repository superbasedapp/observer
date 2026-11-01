package agentconfig

// Shared grounding for the catalogues of the 2026-10-21 capture-only wave
// (autohand, ibm-bob, cortex-code, codebuddy, deepagents-code, dimcode,
// dirac, kimchi, stakpak, vtcode; surface-gap lane w4-catalog). Their file
// rows come from the per-OS settings-location matrix (Part 7, "Matrix E"),
// which cites the vendor docs and vendor source per row, and from each
// tool's docs/<pkg>-adapter.md. A fact the matrix marks UNV stays marked
// unverified here; nothing in these catalogues was read from a real home.

const (
	wave1021Date   = "2026-10-25"
	wave1021Matrix = "docs/audits/surface-settings-location-matrix-2026-10-25.md Part 7"
	wave1021Review = "docs/audits/surface-settings-precedence-gap-review-2026-10-25.md"
)

// matrixE grounds a row in the location matrix's Part 7 section for a tool,
// which itself cites the vendor URL.
func matrixE(section string) Grounding {
	return Grounding{Kind: GroundSource, Source: wave1021Matrix + " " + section, Date: wave1021Date}
}

// waveDoc grounds a row in a vendor doc URL fetched for the matrix.
func waveDoc(url string) Grounding {
	return Grounding{Kind: GroundDoc, Source: url, Date: wave1021Date}
}

// waveSource grounds a row in vendor source (or a vendor bundle) fetched
// for the matrix.
func waveSource(url string) Grounding {
	return Grounding{Kind: GroundSource, Source: url, Date: wave1021Date}
}

// waveAdapterDoc grounds a row in the repo's own adapter doc.
func waveAdapterDoc(path string) Grounding {
	return Grounding{Kind: GroundAdapterDoc, Source: path, Date: wave1021Date}
}

// waveRows fills the tool, id, owner, verification and source of one
// tool's rows; fileID is the default shape.
func waveRows(tool, fileID, src string, rows []SettingRow) []SettingRow {
	for i := range rows {
		r := &rows[i]
		r.Tool = tool
		r.ID = r.Tool + "/" + r.Path.String()
		if r.FileID == "" {
			r.FileID = fileID
		}
		if r.Owner == "" {
			r.Owner = OwnerUser
		}
		if r.Verified == "" {
			r.Verified = VerifiedDoc
		}
		if r.Source == "" {
			r.Source = src
		}
	}
	return rows
}
