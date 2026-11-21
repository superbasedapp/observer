package store

// ProjectIdentityHash is the project identity hash of a project root: the
// digest projects.root_path_hash holds and orgcontract.SessionRow ships as
// project_root_hash (normalize, then hash, exactly as UpsertProject does).
// Callers outside the store that name a project on an org wire (the gen9
// local rule changes on the guard policy-state row) use it so the org joins
// the same project. "" for an empty root.
func ProjectIdentityHash(root string) string {
	if root == "" {
		return ""
	}
	return projectRootHashForPath(root)
}
