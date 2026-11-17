package cloudclient

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins the dependency boundary (plan 6 CI-P2): stdlib
// plus cloudpop, cloudcred, cloudcontract and cloudevidence only, and
// attachgrant: the pure attach grant contract (Getting started v2, section
// 11), whose SignProof is the one owner of the proof the device key signs.
// It is stdlib plus platformcontract, imports no store, config, network or
// server tree (its own imports_test.go pins that), and this package is the
// only holder of the device private key, so the signing has to happen here.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql",
			"github.com/fsnotify/fsnotify",
			"github.com/marmutapp/superbased-observer/internal/store",
			"github.com/marmutapp/superbased-observer/internal/config",
			"github.com/marmutapp/superbased-observer/internal/db",
		},
		Custom: func(_, p string) string {
			if strings.HasPrefix(p, "github.com/marmutapp/superbased-observer/") && !(p == "github.com/marmutapp/superbased-observer/internal/cloudpop" || p == "github.com/marmutapp/superbased-observer/internal/cloudcred" || p == "github.com/marmutapp/superbased-observer/internal/cloudcontract" || p == "github.com/marmutapp/superbased-observer/internal/cloudevidence" || p == "github.com/marmutapp/superbased-observer/internal/attachgrant") {
				return "cloudclient allows only cloudpop/cloudcred/cloudcontract/cloudevidence/attachgrant"
			}
			return ""
		},
		Reason: "cloudclient dependency boundary",
	})
}
