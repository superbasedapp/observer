package secrulepack

import "strconv"

func formatFloat(f float64) string { return strconv.FormatFloat(f, 'f', 6, 64) }
