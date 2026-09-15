package policy

// BudgetUnavailableWindows identifies accounting windows whose usage cannot
// be determined. False means no accounting failure was stamped; hook events
// remain unstamped because they cannot perform the daemon's spend lookup.
type BudgetUnavailableWindows struct {
	Session bool
	Daily   bool
	Weekly  bool
	Monthly bool
}
