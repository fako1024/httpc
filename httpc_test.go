package httpc

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"testing"
	"time"

	"gopkg.in/h2non/gock.v1"
)

type testCase struct {
	expectedStatusCode int
	body               []byte
	responseFn         func(resp *http.Response) error

	hostName string
}

var (
	endpoint = "http://api.example.org"
)

func TestTimeout(t *testing.T) {

	// Define a URI that safely won't exist on localhost
	uri := "http://127.0.0.1/uiatbucacajdahgsdkjasdgcagagd/timeout"

	// Set up a mock matcher for this particular case
	defer gock.Off()
	defer gock.DisableNetworking()

	// Initialize mock server, intercepting all traffic to the mock URI
	// and returning the expected data for this particular test case
	g := gock.New(uri).EnableNetworking()

	// Prepare the mock response
	g.Get(path.Base(uri)).
		Reply(http.StatusOK)

	// Define request with very low timeout (a mocked delay does not trigger
	// the deadline excess)
	req := New(http.MethodGet, uri).Timeout(1 * time.Nanosecond)

	// Execute the request
	if err := req.Run(); err == nil || err.Error() != fmt.Sprintf("Get \"%s\": context deadline exceeded", uri) {
		t.Fatal(err)
	}

}

func TestTable(t *testing.T) {

	var testRequests = map[*Request]testCase{
		New(http.MethodGet, joinURI(endpoint, "simple_ok")): {
			expectedStatusCode: http.StatusOK,
			responseFn: func(resp *http.Response) error {
				return nil
			},
		},
		New(http.MethodPost, joinURI(endpoint, "simple_ok")): {
			expectedStatusCode: http.StatusOK,
			responseFn: func(resp *http.Response) error {
				return nil
			},
		},
		New(http.MethodPut, joinURI(endpoint, "simple_ok")): {
			expectedStatusCode: http.StatusOK,
			responseFn: func(resp *http.Response) error {
				return nil
			},
		},
		New(http.MethodDelete, joinURI(endpoint, "simple_ok")): {
			expectedStatusCode: http.StatusOK,
			responseFn: func(resp *http.Response) error {
				return nil
			},
		},
		New(http.MethodGet, joinURI(endpoint, "set_hostname")): {
			expectedStatusCode: http.StatusOK,
			responseFn: func(resp *http.Response) error {
				return nil
			},
			hostName: "api2.example.org",
		},
		New(http.MethodGet, joinURI(endpoint, "string_message")): {
			expectedStatusCode: http.StatusOK,
			body:               []byte("Hello, world! 你好世界 😊😎"),
			responseFn: func(resp *http.Response) error {
				bodyBytes, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					return err
				}
				if string(bodyBytes) != "Hello, world! 你好世界 😊😎" {
					return fmt.Errorf("Unexpected response body string, want `Hello, world! 你好世界 😊😎`, have `%s`", string(bodyBytes))
				}
				return nil
			},
		},
	}

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
			default:
				t.Fatalf("Unsupported HTTP method requested: %s", k.method)
			}

			// Handle hostnames
			if v.hostName != "" {
				g.AddMatcher(gock.MatchFunc(func(arg1 *http.Request, arg2 *gock.Request) (bool, error) {
					return arg1.Host == v.hostName, nil
				}))
			}

			// Define the return code (and body, if provided)
			if v.body != nil {
				g.Reply(v.expectedStatusCode).Body(bytes.NewBuffer(v.body))
			} else {
				g.Reply(v.expectedStatusCode)
			}

			// Execute and parse the result (if parsing function was provided)
			req := k.ParseFn(v.responseFn)

			// If a hostname was provided, set it
			if v.hostName != "" {
				req.HostName(v.hostName)
			}

			// Execute the request
			if err := req.Run(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func joinURI(base, suffix string) string {
	u, err := url.Parse(base)
	if err != nil {
		panic(err)
	}
	u.Path = path.Join(u.Path, suffix)
	return u.String()
}
