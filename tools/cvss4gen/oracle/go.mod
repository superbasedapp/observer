// This is a separate module on purpose: it exists only to produce the oracle
// fixtures of internal/secassess/cvss4 by running the independent
// github.com/pandatix/go-cvss implementation (MIT) once. The main module does
// not depend on go-cvss and must not (see README.md).
module github.com/marmutapp/superbased-observer/tools/cvss4gen/oracle

go 1.25.0

require github.com/pandatix/go-cvss v0.6.4
