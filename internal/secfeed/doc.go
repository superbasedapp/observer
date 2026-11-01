// Package secfeed is the pure core of the security pillar's install gate
// (component `security.deps`; security pillar plan sections 5.4, 8.2, 8.3
// and 8.5, Phase D1): the ecosystem table, the offline install index (the
// authenticated malicious-packages list and the popular-names lists, each a
// content kind of the signed content channel, roadmap F0-6), its builder,
// the near-miss check, the install-command parser over the guard shell
// parser's commands, the manifest-edit reader, the private-name classifier,
// the online-answer cache and the verdict table.
//
// It does no I/O: no database/sql, no net/http, no net, no os/exec, no
// fsnotify (imports_test.go). Files reach it as bytes from the cmd layer,
// the network through internal/secfeed/online (the `security.online` lane,
// the only package that may dial a public source) or the org client's relay
// call, both injected as functions.
package secfeed
