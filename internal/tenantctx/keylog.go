package tenantctx

import "strings"

// Installing a tenant-context key sends the key to the database as a bound
// parameter (the org's sbo_tenant_context_rotate, pgmigrations 0188; the
// cloud's sbci_tenant_context_install, cloud migration 0066), and the
// function stores HMAC pads derived from it that are exactly as sensitive as
// the key. What can leak it is the server's own logging of statement
// parameters. KeyLogExposure lists the settings, as the installing login's
// session sees them, under which the call's parameters (or, with pgaudit,
// the function's inner INSERT of the pads) would be written to the log. Both
// adopters' install paths refuse to send the key while any applies, unless
// the operator overrides (docs/security.md TCK-1, TCK-3, CLOUDKEYLOG-1).
//
// The table is pure: each adopter reads the settings with its own driver
// (KeyLogSettings names them) and asks KeyLogExposure.

// KeyLogSettings are the server settings KeyLogExposure reads.
var KeyLogSettings = []string{
	"log_statement",
	"log_min_duration_statement",
	"log_min_duration_sample",
	"log_statement_sample_rate",
	"log_parameter_max_length",
	"log_parameter_max_length_on_error",
	"log_min_error_statement",
	"pgaudit.log",
	"pgaudit.log_parameter",
}

// keyLogRule is one way a setting combination writes the key to the log.
type keyLogRule struct {
	applies func(s map[string]string) bool
	reason  string
}

// paramsLogged reports whether a statement log line carries its bound
// parameters at all (log_parameter_max_length 0 drops them; unset reads as
// the server default -1, the whole value).
func paramsLogged(s map[string]string) bool { return s["log_parameter_max_length"] != "0" }

// durationOn reports whether a "-1 is off" duration setting is on.
func durationOn(v string) bool { return v != "" && v != "-1" }

// errorStatementLevels are the log_min_error_statement values at or below
// ERROR, under which a refused call's statement is logged.
var errorStatementLevels = map[string]bool{
	"debug5": true, "debug4": true, "debug3": true, "debug2": true, "debug1": true,
	"info": true, "notice": true, "warning": true, "error": true,
}

// keyLogRules is the ordered rule table; every applying row is reported.
var keyLogRules = []keyLogRule{
	{
		applies: func(s map[string]string) bool { return s["log_statement"] == "all" && paramsLogged(s) },
		reason:  "log_statement = all logs every statement with its parameters",
	},
	{
		applies: func(s map[string]string) bool { return durationOn(s["log_min_duration_statement"]) && paramsLogged(s) },
		reason:  "log_min_duration_statement logs a slow statement with its parameters",
	},
	{
		applies: func(s map[string]string) bool {
			return durationOn(s["log_min_duration_sample"]) && s["log_statement_sample_rate"] != "0" && paramsLogged(s)
		},
		reason: "log_min_duration_sample logs sampled slow statements with their parameters",
	},
	{
		applies: func(s map[string]string) bool {
			return s["log_parameter_max_length_on_error"] != "" && s["log_parameter_max_length_on_error"] != "0" &&
				errorStatementLevels[strings.ToLower(s["log_min_error_statement"])]
		},
		reason: "log_parameter_max_length_on_error logs a failed statement with its parameters",
	},
	{
		applies: func(s map[string]string) bool {
			on := strings.ToLower(s["pgaudit.log_parameter"])
			audit := strings.ToLower(strings.TrimSpace(s["pgaudit.log"]))
			return (on == "on" || on == "true") && audit != "" && audit != "none"
		},
		reason: "pgaudit.log_parameter logs audited statements with their parameters, including the install's write of the key pads",
	},
}

// KeyLogExposure returns, for the settings s (name to pg_settings value; a
// missing pgaudit row means pgaudit is not loaded), every reason the key
// would reach the database's log. Empty means none applies.
func KeyLogExposure(s map[string]string) []string {
	var out []string
	for _, r := range keyLogRules {
		if r.applies(s) {
			out = append(out, r.reason)
		}
	}
	return out
}
