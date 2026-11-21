package identity

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestWorkOSUsersDelete pins the request and the answer table against a
// local fake (no live WorkOS call).
func TestWorkOSUsersDelete(t *testing.T) {
	t.Parallel()
	var gotPath, gotAuth, gotMethod string
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth, gotMethod = r.URL.Path, r.Header.Get("Authorization"), r.Method
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"email":"someone@example.test"}`))
	}))
	defer srv.Close()
	w, err := NewWorkOSUsers(srv.URL, "sk_test_key", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		status  int
		wantErr bool
	}{{200, false}, {202, false}, {204, false}, {404, false}, {401, true}, {429, true}, {500, true}}
	for _, tc := range cases {
		status = tc.status
		err := w.DeleteUser(context.Background(), "user_01ABC")
		if (err != nil) != tc.wantErr {
			t.Errorf("HTTP %d: err = %v", tc.status, err)
		}
		var se *WorkOSStatusError
		if tc.wantErr && (!errors.As(err, &se) || se.Status != tc.status || strings.Contains(err.Error(), "example.test")) {
			t.Errorf("HTTP %d: error %v", tc.status, err)
		}
	}
	if gotMethod != http.MethodDelete || gotPath != "/user_management/users/user_01ABC" || gotAuth != "Bearer sk_test_key" {
		t.Errorf("request = %s %s %q", gotMethod, gotPath, gotAuth)
	}
	for _, bad := range []string{"", "user_", "user_../x", "user_a/b", "dev-subject", "USER_x"} {
		if err := w.DeleteUser(context.Background(), bad); !errors.Is(err, ErrNotWorkOSUser) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if _, err := NewWorkOSUsers("", " ", nil); err == nil {
		t.Error("no key accepted")
	}
	if _, err := NewWorkOSUsers("ftp://x", "k", nil); err == nil {
		t.Error("a bad base accepted")
	}
}
