package taskflow

import (
	"testing"
	"time"
)

func TestApply_NewItemWithKnownStatus(t *testing.T) {
	ts := time.Date(2026, 9, 7, 10, 0, 0, 0, time.UTC)
	item := TaskItem{Key: "1", Content: "do the thing", Status: StatusPending, StatusKnown: true}
	res := Apply(nil, item, ts)
	if !res.IsNew {
		t.Fatal("want IsNew=true")
	}
	if res.Transition == nil || res.Transition.FromStatus != "" || res.Transition.ToStatus != StatusPending {
		t.Errorf("transition = %+v", res.Transition)
	}
	if res.NewState.Content != "do the thing" || res.NewState.Status != StatusPending {
		t.Errorf("state = %+v", res.NewState)
	}
}

func TestApply_NewItemWithoutStatus(t *testing.T) {
	// TaskCreate-shaped: implicit pending, always StatusKnown=true in
	// practice, but this exercises the defensive branch for any decoder
	// that produces an item with no known status yet.
	item := TaskItem{Key: "1", Content: "x"}
	res := Apply(nil, item, time.Now())
	if res.Transition != nil {
		t.Errorf("want no transition when status is unknown, got %+v", res.Transition)
	}
}

func TestApply_StatusOnlyUpdateNeverBlanksContent(t *testing.T) {
	existing := &ItemState{Content: "original subject", Status: StatusPending}
	item := TaskItem{Key: "1", Status: StatusInProgress, StatusKnown: true} // no Content
	res := Apply(existing, item, time.Now())
	if res.NewState.Content != "original subject" {
		t.Errorf("content = %q, want preserved", res.NewState.Content)
	}
	if res.Transition == nil || res.Transition.FromStatus != StatusPending || res.Transition.ToStatus != StatusInProgress {
		t.Errorf("transition = %+v", res.Transition)
	}
}

func TestApply_ContentOnlyUpdateNeverEmitsTransition(t *testing.T) {
	existing := &ItemState{Content: "old", Status: StatusInProgress}
	item := TaskItem{Key: "1", Content: "new"} // StatusKnown=false
	res := Apply(existing, item, time.Now())
	if res.Transition != nil {
		t.Errorf("want no transition for a content-only edit, got %+v", res.Transition)
	}
	if res.NewState.Content != "new" || res.NewState.Status != StatusInProgress {
		t.Errorf("state = %+v", res.NewState)
	}
}

func TestApply_SameStatusReSentEmitsNoTransition(t *testing.T) {
	existing := &ItemState{Content: "x", Status: StatusCompleted, RawStatus: "completed"}
	item := TaskItem{Key: "1", Content: "x", RawStatus: "completed", Status: StatusCompleted, StatusKnown: true}
	res := Apply(existing, item, time.Now())
	if res.Transition != nil {
		t.Errorf("re-sending the same status in a snapshot rewrite must not fabricate a transition: %+v", res.Transition)
	}
}
