// Package pspolicy answers one question without doing any I/O of its own:
// will PowerShell run an unsigned, locally written script file under the
// execution policy a host's PowerShell process ends up with?
//
// It exists for hosts whose Windows hook runner executes Observer's hook as
// a .ps1 file (`powershell -File <script>`, Dirac;
// integration.WindowsHookRunner with Kind RunnerPowerShellScript). Such a
// host cannot run the hook when the effective execution policy is Restricted
// or AllSigned, and the gap review (W-8) records that Dirac then runs the
// tool call without the guard.
//
// The input is the `Get-ExecutionPolicy -List` answer of the same PowerShell
// the host runs (Windows PowerShell 5.1 and PowerShell 7 keep separate
// policy stores and separate Group Policy keys), parsed by ParseList; the
// caller reads it. Evaluate walks the documented scope precedence
// (about_Execution_Policies: MachinePolicy, UserPolicy, Process,
// CurrentUser, LocalMachine) as an ordered table. A host that passes
// `-ExecutionPolicy Bypass` sets the Process scope, which only the two Group
// Policy scopes outrank.
//
// The package never changes a policy; it only classifies one. It is pure
// (CLAUDE.md Module Boundaries #1; imports_test.go pins it).
package pspolicy
