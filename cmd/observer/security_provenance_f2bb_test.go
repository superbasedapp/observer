//go:build !sbo_omit_security

package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/commitlog"
	"github.com/marmutapp/superbased-observer/internal/commitscan"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/secquickscan"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestPublishProvenanceBeforeEnrol (SEC-F2B merge audit finding 4): the
// provenance service is published to the commit seam before its key
// enrolment (a network call) runs, and withdrawn by the returned func.
func TestPublishProvenanceBeforeEnrol(t *testing.T) {
	prev := provenanceRT.Load()
	t.Cleanup(func() { provenanceRT.Store(prev) })
	provenanceRT.Store(nil)
	svc := &provenanceSvc{now: time.Now}
	svc.enrol = func(context.Context, ed25519.PrivateKey, string, time.Time) (orgclient.ChangeKeyCertificate, error) {
		return orgclient.ChangeKeyCertificate{}, errors.New("not reached")
	}
	published := false
	svc.enrolment = func(context.Context) (*store.Enrolment, error) {
		published = provenanceRT.Load() == svc
		return nil, errors.New("stop the enrolment here")
	}
	withdraw := publishProvenance(context.Background(), svc, nil)
	if !published {
		t.Fatal("the key enrolment ran before the service was published")
	}
	if !provenanceRunning() {
		t.Fatal("provenanceRunning is false while published")
	}
	withdraw()
	if provenanceRT.Load() != nil || provenanceRunning() {
		t.Fatal("the withdraw func left the service published")
	}
}

// TestProvenanceOnBoxCommitOff: with the loop off the box seam decides
// nothing, so the scanner keeps the box ref to offer again.
func TestProvenanceOnBoxCommitOff(t *testing.T) {
	prev := provenanceRT.Load()
	t.Cleanup(func() { provenanceRT.Store(prev) })
	provenanceRT.Store(nil)
	if newProvenanceOnBoxCommit(nil)(context.Background(), commitscan.Root{BoxRef: "refs/observer/sandbox/r"}, commitlog.Commit{SHA: "x"}) {
		t.Fatal("the box seam decided a commit with the provenance loop off")
	}
}

// TestBoxRefPrefixesAgree: the commit scan's box ref walk (internal/
// commitscan, core) and SEC-BOX's (internal/secquickscan, security pillar)
// list the same namespaces; the listing is not shared because the core
// package must not link the security pillar's scan package.
func TestBoxRefPrefixesAgree(t *testing.T) {
	if got, want := commitscan.BoxRefPrefixes(), secquickscan.BoxRefPrefixes; !reflect.DeepEqual(got, want) {
		t.Fatalf("commitscan %v, secquickscan %v", got, want)
	}
}
