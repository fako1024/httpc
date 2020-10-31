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
	responseBody       []byte
	responseFn         func(resp *http.Response) error

	queryParams Params
	headers     Params

	hostName string
}

var (
	httpEndpoint  = "http://api.example.org"
	httpsEndpoint = "https://api.example.org"
)

func TestTimeout(t *testing.T) {

	// Define a URI that safely won't exist on localhost
	uri := "http://127.0.0.1/uiatbucacajdahgsdkjasdgcagagd/timeout"

	// Set up a mock matcher
	defer gock.Off()
	defer gock.DisableNetworking()
	g := gock.New(uri).EnableNetworking()
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

func TestSkipCertificateValidation(t *testing.T) {

	uri := joinURI(httpsEndpoint, "secure")

	// Set up a mock matcher
	defer gock.Off()

	gock.InterceptClient(skipTLSVerifyClient)
	defer gock.RestoreClient(skipTLSVerifyClient)

	g := gock.New(uri)
	g.Get(path.Base(uri)).
		Reply(http.StatusOK)

	// Define request disabling certificate validation
	req := New(http.MethodGet, uri).SkipCertificateVerification()

	// Execute the request
	if err := req.Run(); err != nil {
		t.Fatal(err)
	}
}

func TestTable(t *testing.T) {

	var testRequests = map[*Request]testCase{
		New(http.MethodGet, joinURI(httpEndpoint, "simple_ok")): {
			expectedStatusCode: http.StatusOK,
		},
		New(http.MethodPost, joinURI(httpEndpoint, "simple_ok")): {
			expectedStatusCode: http.StatusOK,
		},
		New(http.MethodPut, joinURI(httpEndpoint, "simple_ok")): {
			expectedStatusCode: http.StatusOK,
		},
		New(http.MethodDelete, joinURI(httpEndpoint, "simple_ok")): {
			expectedStatusCode: http.StatusOK,
		},
		New(http.MethodGet, joinURI(httpEndpoint, "set_hostname")): {
			expectedStatusCode: http.StatusOK,
			hostName:           "api2.example.org",
		},
		New(http.MethodGet, joinURI(httpEndpoint, "simple_params")): {
			expectedStatusCode: http.StatusOK,
			queryParams: map[string]string{
				"param1": "DPZU3PILpO2vtoe0oRq6",
				"param2": "NvleFEzAcBzhMhvQSBKB 你好世界 😊😎",
			},
		},
		New(http.MethodGet, joinURI(httpEndpoint, "simple_headers")): {
			expectedStatusCode: http.StatusOK,
			headers: map[string]string{
				"X-TEST-HEADER-1": "sExavefMTeOVFu6LfLLN",
				"X-TEST-HEADER-2": "zHW4aaMhMJzrA5eJtahB 你好世界 😊😎",
			},
		},
		New(http.MethodGet, joinURI(httpEndpoint, "string_message")): {
			expectedStatusCode: http.StatusOK,
			responseBody:       []byte("Hello, world! 你好世界 😊😎"),
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

			// Handle query parameters
			if len(v.queryParams) > 0 {
				g.MatchParams(v.queryParams)
			}

			// Handle headers
			if len(v.headers) > 0 {
				g.MatchHeaders(v.headers)
			}

			// Define the return code (and body, if provided)
			if v.responseBody != nil {
				g.Reply(v.expectedStatusCode).Body(bytes.NewBuffer(v.responseBody))
			} else {
				g.Reply(v.expectedStatusCode)
			}

			// Execute and parse the result (if parsing function was provided)
			req := k.ParseFn(v.responseFn)

			if err := testGetters(req); err != nil {
				t.Fatalf("Getter validation failed: %s", err)
			}

			// If a hostname was provided, set it
			if v.hostName != "" {
				req.HostName(v.hostName)
			}

			// Handle query parameters
			if len(v.queryParams) > 0 {
				req.QueryParams(v.queryParams)
			}

			// Handle headers
			if len(v.headers) > 0 {
				req.Headers(v.headers)
			}

			// Execute the request
			if err := req.Run(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func testGetters(req *Request) error {

	if req.GetURI() != req.uri {
		return fmt.Errorf("Unexpected getter URI received")
	}

	if req.GetMethod() != req.method {
		return fmt.Errorf("Unexpected getter method received")
	}

	if !bytes.Equal(req.GetBody(), req.body) {
		return fmt.Errorf("Unexpected getter body received")
	}

	return nil
}

func joinURI(base, suffix string) string {
	u, err := url.Parse(base)
	if err != nil {
		panic(err)
	}
	u.Path = path.Join(u.Path, suffix)
	return u.String()
}
