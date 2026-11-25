package vendorsurface

// Lookups over dimensionTable that only this package's tests use; nothing
// outside the tests called them, so they are compiled into test builds only.

// DimensionOf returns the orthogonal dimension of a reporting class.
func DimensionOf(c DataClass) (Dimension, bool) {
	for _, r := range dimensionTable {
		if r.Class == c {
			return r.Dim, true
		}
	}
	return Dimension{}, false
}

// ReportingClass returns the reporting class a dimension rolls up to.
func ReportingClass(d Dimension) (DataClass, bool) {
	for _, r := range dimensionTable {
		if r.Dim == d {
			return r.Class, true
		}
	}
	return "", false
}
