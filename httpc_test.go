package httpc

import (
	"bytes"
	"fmt"
	"net/http"
	"path"
	"testing"

	"gopkg.in/h2non/gock.v1"
)

type testCase struct {
	expectedStatusCode int
	body               []byte
	responseFn         func(resp *http.Response) error
}

var (
	endpoint = "http://api.example.org"
)

var testRequests = map[*Request]testCase{
	New(http.MethodGet, path.Join(endpoint, "simple_ok")): {
		expectedStatusCode: http.StatusOK,
		responseFn: func(resp *http.Response) error {
			return nil
		},
	},
}

func TestTable(t *testing.T) {
	for k, v := range testRequests {
		t.Run(fmt.Sprintf("%s %s", k.method, k.uri), func(t *testing.T) {

			// Set up a mock matcher for this particular case
			defer gock.Off()

			// Initialize mock server, intercepting all traffic to the mock URI
			// and returning the expected data for this particular test case
			g := gock.New(k.uri)

			// Define the method based on the test case
			switch k.method {
			case http.MethodGet:
				g.Get(path.Base(k.uri))
			case http.MethodPost:
				g.Post(path.Base(k.uri))
			case http.MethodPut:
				g.Put(path.Base(k.uri))
			case http.MethodDelete:
				g.Delete(path.Base(k.uri))
			}

			// Define the return code
			g.Reply(v.expectedStatusCode)

			// Define the return body, if provided
			if v.body != nil {
				g.Body(bytes.NewBuffer(v.body))
			}

			// Execute and parse the result (if parsing function was provided)
			err := k.ParseFn(v.responseFn).Run()
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
