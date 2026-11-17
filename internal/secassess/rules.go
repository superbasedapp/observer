package secassess

// valRule is one row of the validator's ordered table. Rows run top to bottom
// and stop at the first that refuses the whole file. Every row has a test case
// per code it can raise (validate_test.go).
type valRule struct {
	ID     string
	Effect Effect
	Name   string
	Run    func(*validator)
}

// valRules is the ordered table. V14 is the request-log evidence and V16 the
// red team exercise and chain; V15 is DeriveSARIF, which is not part of
// validation.
var valRules = []valRule{
	{"V1", EffectRefuseFile, "size and nesting caps", ruleV1},
	{"V2", EffectRefuseFile, "decode, schema and run id", ruleV2},
	{"V3", EffectRefuseItem, "collection caps", ruleV3},
	{"V4", EffectRefuseItem, "item ids", ruleV4},
	{"V5", EffectRefuseItem, "closed enums", ruleV5},
	{"V6", EffectDropField, "text cleaning", ruleV6},
	{"V7", EffectRefuseItem, "references between items", ruleV7},
	{"V8", EffectSet, "source references", ruleV8},
	{"V9", EffectWarn, "scope", ruleV9},
	{"V10", EffectSet, "inherent band", ruleV10},
	{"V11", EffectReport, "threat model coverage", ruleV11},
	{"V12", EffectWarn, "abuse cases and attack trees", ruleV12},
	{"V13", EffectReport, "penetration test coverage", ruleV13},
	{"V14", EffectSet, "evidence from the request helper's log", ruleV14},
	{"V16", EffectRefuseItem, "red team exercise and chain", ruleV16},
}

// RuleInfo describes a validator row for documentation and tests.
type RuleInfo struct {
	ID     string
	Effect Effect
	Name   string
}

// Rules lists the validator rows in order.
func Rules() []RuleInfo {
	out := make([]RuleInfo, len(valRules))
	for i, r := range valRules {
		out[i] = RuleInfo{r.ID, r.Effect, r.Name}
	}
	return out
}
