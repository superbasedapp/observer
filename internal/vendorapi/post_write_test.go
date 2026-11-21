package vendorapi

import (
	"errors"
	"testing"
)

// TestUserSpendLimitSetIsClosed (lane ENTAPI-L14, T-617): the one write body
// encodes only a lower-case email and a whole, non-negative, bounded dollar
// amount; it has no null form (removing a limit is a loosening and cannot be
// expressed), and only it is a write kind.
func TestUserSpendLimitSetIsClosed(t *testing.T) {
	b, err := EncodePostBody(UserSpendLimitSet{UserEmail: "dev.one+x@corp.example", LimitDollars: 0})
	if err != nil || string(b) != `{"userEmail":"dev.one+x@corp.example","spendLimitDollars":0}` {
		t.Fatalf("encode %s %v", b, err)
	}
	for _, bad := range []UserSpendLimitSet{
		{UserEmail: "", LimitDollars: 1},
		{UserEmail: "Dev@corp.example", LimitDollars: 1},
		{UserEmail: "dev@corp", LimitDollars: 1},
		{UserEmail: "dev @corp.example", LimitDollars: 1},
		{UserEmail: "dev@corp.example\n", LimitDollars: 1},
		{UserEmail: "dev@corp.example", LimitDollars: -1},
		{UserEmail: "dev@corp.example", LimitDollars: MaxSpendLimitDollars + 1},
	} {
		if _, err := EncodePostBody(bad); !errors.Is(err, ErrBadPostBody) {
			t.Errorf("%+v encoded: %v", bad, err)
		}
	}
	if !WriteKind(PostUserSpendLimitSet) {
		t.Error("the spend-limit body is not a write kind")
	}
	for _, k := range []PostKind{PostEpochRange, PostEpochRangePage, PostPage} {
		if WriteKind(k) {
			t.Errorf("read body %s is a write kind", k)
		}
	}
}

// TestEpochRangePageHostingIsClosed (cloud agents arc, lane CA-C8): the
// hosting filter encodes only a hosting type from the closed table, on top of
// the EpochRangePage rules, and it is a read.
func TestEpochRangePageHostingIsClosed(t *testing.T) {
	b, err := EncodePostBody(EpochRangePageHosting{StartMillis: 1, EndMillis: 2, Page: 1, PageSize: 1000, HostingType: HostingCloud})
	if err != nil || string(b) != `{"startDate":1,"endDate":2,"page":1,"pageSize":1000,"hostingType":"CLOUD"}` {
		t.Fatalf("encode %s %v", b, err)
	}
	for _, bad := range []EpochRangePageHosting{
		{StartMillis: 1, EndMillis: 2, Page: 1, PageSize: 10, HostingType: ""},
		{StartMillis: 1, EndMillis: 2, Page: 1, PageSize: 10, HostingType: "SELF_HOSTED"},
		{StartMillis: 1, EndMillis: 2, Page: 1, PageSize: 10, HostingType: "cloud"},
		{StartMillis: 2, EndMillis: 1, Page: 1, PageSize: 10, HostingType: HostingCloud},
		{StartMillis: 1, EndMillis: 2, Page: 0, PageSize: 10, HostingType: HostingCloud},
		{StartMillis: 1, EndMillis: 2, Page: 1, PageSize: MaxPostPageSize + 1, HostingType: HostingCloud},
	} {
		if _, err := EncodePostBody(bad); !errors.Is(err, ErrBadPostBody) {
			t.Errorf("%+v encoded: %v", bad, err)
		}
	}
	if WriteKind(PostEpochRangePageHosting) {
		t.Error("the hosting-filtered range is a write kind")
	}
}
