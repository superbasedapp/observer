//go:build !linux

package termsession

func processStartIdentity(int) string { return "" }
