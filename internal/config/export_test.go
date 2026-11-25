package config

// Test-only helpers: production callers plan and apply a project overlay
// edit through PlanProjectOverlayEdit and ApplyProjectOverlayEdit directly.

// UpdateProjectOverlay sets a dotted key in <root>/.observer/
// config.toml, creating the file when absent. Only allow-listed keys
// are writable: the profiles table and compression parameters. The
// edit is key-preserving and goes through the shared .bak +
// atomic-rename path (PlanProjectOverlayEdit / ApplyProjectOverlayEdit,
// the one owner the dashboard's per-project profile card also uses).
// The home directory is always refused; a caller that knows a custom
// master config path plans with ProjectOverlayEditRequest.ExcludeFile.
func UpdateProjectOverlay(root, dotted, value string) error {
	e, err := PlanProjectOverlayEdit(ProjectOverlayEditRequest{Root: root, Key: dotted, Value: value})
	if err != nil {
		return err
	}
	return ApplyProjectOverlayEdit(e)
}
