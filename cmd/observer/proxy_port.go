package main

// effectiveProxyPort is the one rule for the proxy port a daemon runs on: the
// `--port` override when set, else [proxy].port. buildProxy binds it, and the
// dashboard reports it (sidebar footer, Setup route writers), so the two never
// disagree (U-05). It lives in an untagged file because start.go calls it in
// every build, including one without capture.proxy.
func effectiveProxyPort(configured, override int) int {
	if override > 0 {
		return override
	}
	return configured
}
