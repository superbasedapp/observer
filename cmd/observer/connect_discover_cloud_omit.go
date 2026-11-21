//go:build sbo_omit_cloud_intelligence

package main

// connect_discover_cloud_omit.go: a build without Cloud Intelligence links no
// cloud network package, so it has no discovery seams; `observer connect`
// with no address asks for the organization's address instead
// (printConnectNeedsAddress).

func defaultConnectDiscovery() connectDiscovery { return connectDiscovery{} }
