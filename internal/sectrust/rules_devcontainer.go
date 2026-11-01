package sectrust

// DevcontainerParser is the container sandbox driver's own devcontainer.json
// parser, injected by the caller (N2, lane SBX-P3B): it returns the fields
// the driver ignores, each one's value as compact JSON, or an error when the
// file does not parse. Injected rather than imported so this package never
// links the driver's planner into a build that omits the driver.
type DevcontainerParser func(data []byte) (ignored []string, values map[string]string, err error)

// devcontainer judges a .devcontainer/devcontainer.json, a conditional row:
// every ignored field where the container sandbox is active (agentconfig
// TrustCondOCISandbox), and initializeCommand alone wherever the trust
// check runs (TrustCondDevcontainerHost, the proposed N2 ruling of lane
// SBX-P3D). Which fields the injected parser returns is the caller's
// filter over agentconfig's devcontainerFields table. It goes through the driver's parser, so the trust
// check and the driver can never disagree about which fields are ignored:
// each one is a devcontainer_ignored_field reason whose digest covers the
// field's value, and a file that does not parse is one reason for the whole
// file (the driver will not adopt it either). Without a parser (a caller
// that passed the conditional table but no parser) the whole file is one
// reason too, never a silent skip.
func (c *checker) devcontainer(file string, data []byte) {
	if c.devcontainerParse == nil {
		c.add(Reason{Code: "devcontainer_ignored_field", File: file, Key: "(file)", Excerpt: "not judged: no devcontainer parser in this build", value: string(data)})
		return
	}
	ignored, values, err := c.devcontainerParse(data)
	if err != nil {
		c.add(Reason{Code: "devcontainer_ignored_field", File: file, Key: "(file)", Excerpt: "does not parse; the container sandbox will not adopt it", value: string(data)})
		return
	}
	for _, f := range ignored {
		v := values[f]
		c.add(Reason{Code: "devcontainer_ignored_field", File: file, Key: f, Excerpt: excerpt(v), value: v})
	}
}
