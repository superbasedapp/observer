package orgcontract

// secci_binding.go names the change-record key enrolment's machine binding
// refusal (security plan 7.10 "Key enrolment", SECP-31, lane LEFT-SHARED):
// a member's first certified enrolment binds the machine identity it named;
// a later enrolment naming another machine is refused with this code (403)
// until an org admin resets the binding. An older node reads the 403 as an
// auth failure and retries later, which changes nothing.
const ChangeKeyMachineBound = "machine_bound"
