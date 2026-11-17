package cvss4

// baseMetricDef is one base metric: its key and the values it may take, in
// the order FIRST's configuration lists them.
type baseMetricDef struct {
	Key    string
	Values []string
}

// metricValue is one metric fixed to one value inside a maximal vector.
type metricValue struct {
	Metric string
	Value  string
}

// fragment is the part of a maximal vector that one EQ fixes.
type fragment []metricValue
