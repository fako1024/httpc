package httpc

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"gopkg.in/h2non/gock.v1"
)

// Too many retries leads to... success
// https://github.com/fako1024/httpc/issues/43
func TestIssue43FailedRetriesLeadToSuccedd(t *testing.T) {
	uri := joinURI(httpsEndpoint, "issue_43")

	// Set up a mock matcher
	g := gock.New(uri)
	g.Persist().
		Get("/").
		Reply(http.StatusInternalServerError)

	req := New(http.MethodGet, uri).
		RetryBackOffErrFn(func(resp *http.Response, err error) bool {
			if resp == nil || err != nil {
				return true
			}
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return false
			}
			return true
		}).
		RetryBackOff(Intervals{time.Millisecond, time.Millisecond, time.Millisecond})

	gock.InterceptClient(req.client)
	defer gock.RestoreClient(req.client)

	err := req.Run()
	if err == nil {
		t.Fatal("expected error, got none")
	}
	if !errors.Is(err, ErrRetryLimit) {
		t.Fatalf("unexpected error, want %s, have %s", ErrRetryLimit, err)
	}
}
