package httpc

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path"
	"testing"
	"time"

	"golang.org/x/net/publicsuffix"
	"gopkg.in/h2non/gock.v1"
)

type testCase struct {
	expectedStatusCode int
	requestBody        []byte
	responseBody       []byte
	responseFn         func(resp *http.Response) error

	queryParams Params
	headers     Params

	hostName string
}

const (
	helloWorldString = "Hello, world! 你好世界 😊😎"
)

var (
	httpEndpoint  = "http://api.example.org"
	httpsEndpoint = "https://api.example.org"
)

func TestInvalidRequest(t *testing.T) {
	if err := New("", "").Run(); err == nil || err.Error() != `Get "": unsupported protocol scheme ""` {
		t.Fatalf("Unexpected success creating invalid request: %s", err)
	}
	if err := New("😊", "").Run(); err == nil || err.Error() != `Error creating request: net/http: invalid method "😊"` {
		t.Fatalf("Unexpected success creating invalid request: %s", err)
	}
	if err := New("", "NOTVALID").Run(); err == nil || err.Error() != `Get "NOTVALID": unsupported protocol scheme ""` {
		t.Fatalf("Unexpected success creating invalid request: %s", err)
	}
}

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

func TestReuse(t *testing.T) {

	uri := joinURI(httpsEndpoint, "reuse")

	// Set up a mock matcher
	g := gock.New(uri)
	g.Persist()
	g.Get(path.Base(uri)).
		Reply(http.StatusOK)

	req := New(http.MethodGet, uri)

	for i := 0; i < 100; i++ {

		// Execute the request
		if err := req.Run(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestClientDelay(t *testing.T) {

	uri := joinURI(httpsEndpoint, "delay")

	// Set up a mock matcher
	defer gock.Off()

	g := gock.New(uri)
	g.Get(path.Base(uri)).
		AddMatcher(gock.MatchFunc(func(arg1 *http.Request, arg2 *gock.Request) (bool, error) {
			bodyBytes, err := ioutil.ReadAll(arg1.Body)
			if err != nil {
				return false, err
			}
			return bytes.Equal(bodyBytes, []byte(helloWorldString)), nil
		})).
		Reply(http.StatusOK)

	// Define request disabling certificate validation
	start := time.Now()
	req := New(http.MethodGet, uri).Body([]byte(helloWorldString)).Delay(50 * time.Millisecond)

	// Execute the request
	if err := req.Run(); err != nil {
		t.Fatal(err)
	}

	// Check the latency of the request
	if lat := time.Now().Sub(start); lat < 50*time.Millisecond {
		t.Fatalf("Delayed request unexpectedly too fast, latency %v", lat)
	}
}

func TestModifyClient(t *testing.T) {

	uri := joinURI(httpsEndpoint, "client_modification")

	// Set up a mock matcher
	defer gock.Off()

	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		t.Fatalf("Failed to set cookie jar")
	}
	u, _ := url.Parse(uri)
	jar.SetCookies(u, []*http.Cookie{
		{Name: "test_cookie1", Value: "lW9p2ku5iR2OjDHS69xa"},
		{Name: "test_cookie2", Value: "wBbycTsBM7yGIxURLKSp"},
	})

	g := gock.New(uri)
	g.Get(path.Base(uri)).
		AddMatcher(gock.MatchFunc(func(arg1 *http.Request, arg2 *gock.Request) (bool, error) {
			if len(arg1.Cookies()) != len(jar.Cookies(u)) {
				return false, fmt.Errorf("Unexpected number of cookies")
			}
			for i, cookie := range arg1.Cookies() {
				if jar.Cookies(u)[i].String() != cookie.String() {
					return false, fmt.Errorf("Mismatching cookie, want %s, have %s", jar.Cookies(u)[i].String(), cookie.String())
				}
			}
			return true, nil
		})).
		Reply(http.StatusOK)

	// Define request setting custom HTTP client parameters
	req := New(http.MethodGet, uri).ModifyHTTPClient(func(c *http.Client) {
		c.Jar = jar
	})

	// Execute the request
	if err := req.Run(); err != nil {
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

func TestAcceptedResponseCodes(t *testing.T) {

	if err := testResponseCode([]int{}, http.StatusOK); err == nil || err.Error() != fmt.Sprintf("No accepted HTTP response codes set, considering request to be failed (Got %d)", http.StatusOK) {
		t.Fatalf("Unexpected success for empty accepted response codes")
	}

	codes := []int{
		http.StatusOK,
		http.StatusGone,
		http.StatusLocked,
		http.StatusCreated,
		http.StatusAccepted,
		http.StatusContinue,
		http.StatusNoContent,
	}

	var acceptedCodes []int
	for i, acceptedCode := range codes {
		acceptedCodes = append(acceptedCodes, acceptedCode)

		for _, returnedCode := range codes[:i+1] {
			if err := testResponseCode(acceptedCodes, returnedCode); err != nil {
				t.Fatalf("Unexpected failure for code %d, accepted codes %v: %s", returnedCode, acceptedCodes, err)
			}
		}

		for _, returnedCode := range codes[i+1:] {
			if err := testResponseCode(acceptedCodes, returnedCode); err == nil {
				t.Fatalf("Unexpected success for code %d, accepted codes %v", returnedCode, acceptedCodes)
			}
		}
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
		New(http.MethodGet, joinURI(httpEndpoint, "string_request")): {
			expectedStatusCode: http.StatusOK,
			requestBody:        []byte(helloWorldString),
		},
		New(http.MethodGet, joinURI(httpEndpoint, "string_response")): {
			expectedStatusCode: http.StatusOK,
			responseBody:       []byte(helloWorldString),
			responseFn: func(resp *http.Response) error {
				bodyBytes, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					return err
				}
				if string(bodyBytes) != helloWorldString {
					return fmt.Errorf("Unexpected response body string, want `Hello, world! 你好世界 😊😎`, have `%s`", string(bodyBytes))
				}
				return nil
			},
		},
	}

	for k, v := range testRequests {
		t.Run(fmt.Sprintf("%s %s", k.method, k.uri), func(t *testing.T) {
			if err := runGenericRequest(k, v); err != nil {
				t.Fatalf("Failed running test: %s", err)
			}
		})
	}
}

func runGenericRequest(k *Request, v testCase) error {

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
		return fmt.Errorf("Unsupported HTTP method requested: %s", k.method)
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

	// Handle request body
	if v.requestBody != nil {
		g.AddMatcher(gock.MatchFunc(func(arg1 *http.Request, arg2 *gock.Request) (bool, error) {
			bodyBytes, err := ioutil.ReadAll(arg1.Body)
			if err != nil {
				return false, err
			}
			return bytes.Equal(bodyBytes, v.requestBody), nil
		}))
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
		return fmt.Errorf("Getter validation failed: %s", err)
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

	// Handle request body
	if v.requestBody != nil {
		req.Body(v.requestBody)
	}

	// Execute the request
	return req.Run()
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

func testResponseCode(codes []int, returnCode int) error {

	uri := joinURI(httpEndpoint, "codes")

	// Set up a mock matcher
	defer gock.Off()

	g := gock.New(uri)
	g.Get(path.Base(uri)).
		Reply(returnCode)

	// Define request disabling certificate validation
	req := New(http.MethodGet, uri).AcceptedResponseCodes(codes)

	// Execute the request
	return req.Run()
}

func joinURI(base, suffix string) string {
	u, err := url.Parse(base)
	if err != nil {
		panic(err)
	}
	u.Path = path.Join(u.Path, suffix)
	return u.String()
}
