// Package nodefeas is the node side of the feasibility seam (operator
// ruling D-514, lane UX-INFEASIBLE). It turns what the node knows (the
// component resolver's decisions, host facts such as a sandbox probe) into
// internal/feasibility verdicts, through two tables:
//
//   - componentReasons: one row per resolver Reason, the sentence and the
//     fix step a chooser shows for a component that cannot be chosen here
//     (Settings > Components, observer init's checklist, the doctor row);
//   - SettingRules: one row per node setting that needs a component or a
//     host fact (non-loopback dashboard needs remote, a sandboxed launch
//     needs terminals.sandbox and bubblewrap, admission needs obs, ...), so
//     the daemon starts with an infeasible setting off and one reason
//     instead of refusing to start.
//
// Pure: it imports only internal/feasibility and internal/components (both
// pure). Every caller fills the inputs; nothing here reads config, the
// network or the file system.
package nodefeas
