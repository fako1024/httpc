package httpc

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/gob"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path"
	"testing"
	"time"

	jsoniter "github.com/json-iterator/go"
	"golang.org/x/net/context"
	"golang.org/x/net/publicsuffix"
	"gopkg.in/h2non/gock.v1"
	"gopkg.in/yaml.v2"
)

type testCase struct {
	expectedStatusCode int
	requestBody        []byte
	responseBody       []byte
	responseFn         func(resp *http.Response) error
	errorFn            func(resp *http.Response) error

	queryParams Params
	headers     Params

	expectedError string

	hostName string
}

type testStruct struct {
	Message string
	Status  int
}

const (
	helloWorldString = "Hello, world! 你好世界 😊😎"
	helloWorldJSON   = `{"status": 200, "message": "Hello, world! 你好世界 😊😎"}`
	helloWorldYAML   = `---
status: 200
message: "Hello, world! 你好世界 \U0001F60A\U0001F60E"
`
	helloWorldXML = `<?xml version="1.0" encoding="UTF-8"?>
<testStruct>
  <Message>Hello, world! 你好世界 😊😎</Message>
  <Status>200</Status>
</testStruct>
`
)

var (
	httpEndpoint  = "http://api.example.org"
	httpsEndpoint = "https://api.example.org"
)

func TestInvalidRequest(t *testing.T) {
	if err := New("", "").Run(); err == nil || err.Error() != `Get "": unsupported protocol scheme ""` {
		t.Fatalf("Unexpected success creating invalid request: %s", err)
	}
	if err := New("😊", "").Run(); err == nil || err.Error() != `error creating request: net/http: invalid method "😊"` {
		t.Fatalf("Unexpected success creating invalid request: %s", err)
	}
	if err := New("", "NOTVALID").Run(); err == nil || err.Error() != `Get "NOTVALID": unsupported protocol scheme ""` {
		t.Fatalf("Unexpected success creating invalid request: %s", err)
	}
	if err := New(http.MethodGet, "").EncodeJSON(struct{}{}).Body([]byte{0}).Run(); err == nil || err.Error() != `cannot use both body encoding and raw body content` {
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

	t.Run("with-timeout-method", func(t *testing.T) {
		// Define request with very low timeout (a mocked delay does not trigger
		// the deadline excess)
		req := New(http.MethodGet, uri).Timeout(1 * time.Nanosecond)

		// Execute the request
		if err := req.Run(); err == nil || err.Error() != fmt.Sprintf("Get \"%s\": context deadline exceeded", uri) {
			t.Fatal(err)
		}
	})

	t.Run("with-context", func(t *testing.T) {
		// Only the request, as we are using the context for timeout
		req := New(http.MethodGet, uri)

		// Define very low timeout (a mocked delay does not trigger
		// the deadline excess)
		ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
		defer cancel()

		// Execute the request
		if err := req.RunWithContext(ctx); err == nil || err.Error() != fmt.Sprintf("Get \"%s\": context deadline exceeded", uri) {
			t.Fatal(err)
		}
	})
}

func TestRetries(t *testing.T) {
	uri := joinURI(httpsEndpoint, "retries")
	intervals := Intervals{10 * time.Millisecond, 15 * time.Millisecond, 20 * time.Millisecond}
	var sumIntervals time.Duration
	for i := 0; i < len(intervals); i++ {
		sumIntervals += intervals[i]
	}

	// Set up a mock matcher
	nTries := 0
	g := gock.New(uri)
	g.Persist()
	g.Put(path.Base(uri)).AddMatcher(func(r1 *http.Request, r2 *gock.Request) (bool, error) {

		bodyData, err := ioutil.ReadAll(r1.Body)
		if err != nil {
			return false, err
		}
		if string(bodyData) != helloWorldString {
			return false, fmt.Errorf("invalid body on attempt %d: %s", nTries, string(bodyData))
		}

		nTries++
		if nTries != 4 {
			return false, nil
		}
		return true, nil
	}).
		Reply(http.StatusOK)

	req := New(http.MethodPut, uri).RetryBackOff(intervals).Body([]byte(helloWorldString))
	gock.InterceptClient(req.client)
	defer gock.RestoreClient(req.client)

	start := time.Now()
	if err := req.Run(); err != nil {
		t.Fatal(err)
	}
	if timeTaken := time.Since(start); timeTaken < sumIntervals {
		t.Fatalf("too short duration using Retry(): %v", timeTaken)
	}

	start = time.Now()
	if err := New(http.MethodPut, joinURI(httpsEndpoint, "doesnotexist")).RetryBackOff(intervals).Body([]byte(helloWorldString)).Run(); err == nil {
		t.Fatalf("unexpected success using Retry()")
	}
	if timeTaken := time.Since(start); timeTaken < sumIntervals {
		t.Fatalf("too short duration using Retry(): %v", timeTaken)
	}
}

func TestRetriesErrorFn(t *testing.T) {
	uri := joinURI(httpsEndpoint, "sdfhgajhdsd")
	intervals := Intervals{10 * time.Millisecond, 15 * time.Millisecond, 20 * time.Millisecond}
	var sumIntervals time.Duration
	for i := 0; i < len(intervals); i++ {
		sumIntervals += intervals[i]
	}

	// Set up a mock matcher
	g := gock.New(uri)
	g.Persist()
	g.Put(path.Base(uri)).AddMatcher(func(r1 *http.Request, r2 *gock.Request) (bool, error) {
		bodyData, err := ioutil.ReadAll(r1.Body)
		if err != nil {
			return false, err
		}
		if string(bodyData) != helloWorldString {
			return false, fmt.Errorf("invalid body: %s", string(bodyData))
		}

		return true, nil
	}).
		Reply(http.StatusBadRequest)

	req := New(http.MethodPut, uri).RetryBackOff(intervals).RetryBackOffErrFn(func(r *http.Response, err error) bool {
		return err != nil || r.StatusCode == 500
	}).Body([]byte(helloWorldString))
	gock.InterceptClient(req.client)
	defer gock.RestoreClient(req.client)

	start := time.Now()
	if err := req.Run(); err == nil || err.Error() != "400 Bad Request [body=]" {
		t.Fatalf("unexpected error response: %s", err)
	}
	if timeTaken := time.Since(start); timeTaken >= sumIntervals {
		t.Fatalf("too long duration using Retry(): %v", timeTaken)
	}

	start = time.Now()
	if err := New(http.MethodPut, joinURI(httpsEndpoint, "doesnotexist")).RetryBackOff(intervals).RetryBackOffErrFn(func(r *http.Response, err error) bool {
		return err != nil || r.StatusCode == 400
	}).Body([]byte(helloWorldString)).Run(); err == nil {
		t.Fatalf("unexpected success using Retry()")
	}
	if timeTaken := time.Since(start); timeTaken < sumIntervals {
		t.Fatalf("too short duration using Retry(): %v", timeTaken)
	}
}

type gobEncoder struct {
	v interface{}
}

// Encode fulfills the Encoder interface, performing the actual encoding
func (e gobEncoder) Encode() ([]byte, error) {
	w := new(bytes.Buffer)
	if err := gob.NewEncoder(w).Encode(e.v); err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

// Encode fulfills the Encoder interface, providing the required content-type header
func (e gobEncoder) ContentType() string {
	return "application/custom-type"
}

func TestGenericEncoding(t *testing.T) {
	uri := joinURI(httpsEndpoint, "genericEncoding")

	// Set up a mock matcher
	g := gock.New(uri)
	g.Persist()
	g.Get(path.Base(uri)).AddMatcher(func(r1 *http.Request, r2 *gock.Request) (bool, error) {

		if contentType := r1.Header.Get("Content-Type"); contentType != "application/custom-type" {
			return false, fmt.Errorf("unexpected content-type: %s", contentType)
		}

		var parsedBody testStruct
		if err := gob.NewDecoder(r1.Body).Decode(&parsedBody); err != nil {
			return false, err
		}

		if parsedBody.Status != 42 || parsedBody.Message != "JSON String" {
			return false, fmt.Errorf("unexpected content of parsed content: %v", parsedBody)
		}

		return true, nil
	}).
		Reply(http.StatusOK)

	reqBody := testStruct{
		Status:  42,
		Message: "JSON String",
	}

	req := New(http.MethodGet, uri).Encode(gobEncoder{reqBody})
	gock.InterceptClient(req.client)
	defer gock.RestoreClient(req.client)

	if err := req.Run(); err != nil {
		t.Fatal(err)
	}
}

func TestJSONRequest(t *testing.T) {
	t.Run("no_duplicate_header", func(t *testing.T) {
		testJSONRequest(false, t)
	})
	t.Run("duplicate_header", func(t *testing.T) {
		testJSONRequest(true, t)
	})
}

func testJSONRequest(duplicateHeader bool, t *testing.T) {
	uri := joinURI(httpsEndpoint, "jsonRequest")

	// Set up a mock matcher
	g := gock.New(uri)
	g.Persist()
	g.Get(path.Base(uri)).AddMatcher(func(r1 *http.Request, r2 *gock.Request) (bool, error) {

		if contentType := r1.Header.Get("Content-Type"); contentType != "application/json" {
			return false, fmt.Errorf("unexpected content-type: %s", contentType)
		}
		if contentTypeValues := r1.Header.Values("Content-Type"); len(contentTypeValues) != 1 {
			return false, fmt.Errorf("unexpected content-type values: %s", contentTypeValues)
		}

		bodyBytes, err := ioutil.ReadAll(r1.Body)
		if err != nil {
			return false, err
		}

		var parsedBody testStruct
		if err := jsoniter.Unmarshal(bodyBytes, &parsedBody); err != nil {
			return false, err
		}

		if parsedBody.Status != 42 || parsedBody.Message != "JSON String" {
			return false, fmt.Errorf("unexpected content of parsed content: %v", parsedBody)
		}

		return true, nil
	}).
		Reply(http.StatusOK)

	reqBody := testStruct{
		Status:  42,
		Message: "JSON String",
	}

	req := New(http.MethodGet, uri).EncodeJSON(reqBody)
	if duplicateHeader {
		req.Headers(Params{
			"Content-type": "application/json",
		})
	}
	gock.InterceptClient(req.client)
	defer gock.RestoreClient(req.client)

	if err := req.Run(); err != nil {
		t.Fatal(err)
	}
}

func TestJSONParser(t *testing.T) {
	uri := joinURI(httpsEndpoint, "jsonParsing")

	// Set up a mock matcher
	g := gock.New(uri)
	g.Persist()
	g.Get(path.Base(uri)).Reply(http.StatusOK).Body(bytes.NewBuffer([]byte(helloWorldJSON))).SetHeader("Content-Type", "application/json")

	var parsedResult testStruct
	req := New(http.MethodGet, uri).ParseJSON(&parsedResult)
	gock.InterceptClient(req.client)
	defer gock.RestoreClient(req.client)

	if err := req.Run(); err != nil {
		t.Fatal(err)
	}

	if parsedResult.Status != 200 || parsedResult.Message != "Hello, world! 你好世界 😊😎" {
		t.Fatalf("unexpected content of parsed result: %v", parsedResult)
	}
}

func TestYAMLRequest(t *testing.T) {
	t.Run("no_duplicate_header", func(t *testing.T) {
		testYAMLRequest(false, t)
	})
	t.Run("duplicate_header", func(t *testing.T) {
		testYAMLRequest(true, t)
	})
}

func testYAMLRequest(duplicateHeader bool, t *testing.T) {
	uri := joinURI(httpsEndpoint, "yamlRequest")

	// Set up a mock matcher
	g := gock.New(uri)
	g.Persist()
	g.Get(path.Base(uri)).AddMatcher(func(r1 *http.Request, r2 *gock.Request) (bool, error) {

		if contentType := r1.Header.Get("Content-Type"); contentType != "application/yaml" {
			return false, fmt.Errorf("unexpected content-type: %s", contentType)
		}
		if contentTypeValues := r1.Header.Values("Content-Type"); len(contentTypeValues) != 1 {
			return false, fmt.Errorf("unexpected content-type values: %s", contentTypeValues)
		}

		bodyBytes, err := ioutil.ReadAll(r1.Body)
		if err != nil {
			return false, err
		}

		var parsedBody testStruct
		if err := yaml.Unmarshal(bodyBytes, &parsedBody); err != nil {
			return false, err
		}

		if parsedBody.Status != 42 || parsedBody.Message != "YAML String" {
			return false, fmt.Errorf("unexpected content of parsed content: %v", parsedBody)
		}

		return true, nil
	}).
		Reply(http.StatusOK)

	reqBody := testStruct{
		Status:  42,
		Message: "YAML String",
	}

	req := New(http.MethodGet, uri).EncodeYAML(reqBody)
	if duplicateHeader {
		req.Headers(Params{
			"Content-type": "application/yaml",
		})
	}
	gock.InterceptClient(req.client)
	defer gock.RestoreClient(req.client)

	if err := req.Run(); err != nil {
		t.Fatal(err)
	}
}

func TestYAMLParser(t *testing.T) {
	uri := joinURI(httpsEndpoint, "yamlParsing")

	// Set up a mock matcher
	g := gock.New(uri)
	g.Persist()
	g.Get(path.Base(uri)).Reply(http.StatusOK).Body(bytes.NewBuffer([]byte(helloWorldYAML))).SetHeader("Content-Type", "application/yaml")

	var parsedResult testStruct
	req := New(http.MethodGet, uri).ParseYAML(&parsedResult)
	gock.InterceptClient(req.client)
	defer gock.RestoreClient(req.client)

	if err := req.Run(); err != nil {
		t.Fatal(err)
	}

	if parsedResult.Status != 200 || parsedResult.Message != "Hello, world! 你好世界 😊😎" {
		t.Fatalf("unexpected content of parsed result: %v", parsedResult)
	}
}

func TestXMLRequest(t *testing.T) {
	t.Run("no_duplicate_header", func(t *testing.T) {
		testXMLRequest(false, t)
	})
	t.Run("duplicate_header", func(t *testing.T) {
		testXMLRequest(true, t)
	})
}

func testXMLRequest(duplicateHeader bool, t *testing.T) {
	uri := joinURI(httpsEndpoint, "xmlRequest")

	// Set up a mock matcher
	g := gock.New(uri)
	g.Persist()
	g.Get(path.Base(uri)).AddMatcher(func(r1 *http.Request, r2 *gock.Request) (bool, error) {

		if contentType := r1.Header.Get("Content-Type"); contentType != "application/xml" {
			return false, fmt.Errorf("unexpected content-type: %s", contentType)
		}
		if contentTypeValues := r1.Header.Values("Content-Type"); len(contentTypeValues) != 1 {
			return false, fmt.Errorf("unexpected content-type values: %s", contentTypeValues)
		}

		bodyBytes, err := ioutil.ReadAll(r1.Body)
		if err != nil {
			return false, err
		}

		var parsedBody testStruct
		if err := xml.Unmarshal(bodyBytes, &parsedBody); err != nil {
			return false, err
		}

		if parsedBody.Status != 42 || parsedBody.Message != "XML String" {
			return false, fmt.Errorf("unexpected content of parsed content: %v", parsedBody)
		}

		return true, nil
	}).
		Reply(http.StatusOK)

	reqBody := testStruct{
		Status:  42,
		Message: "XML String",
	}

	req := New(http.MethodGet, uri).EncodeXML(reqBody)
	if duplicateHeader {
		req.Headers(Params{
			"Content-type": "application/xml",
		})
	}
	gock.InterceptClient(req.client)
	defer gock.RestoreClient(req.client)

	if err := req.Run(); err != nil {
		t.Fatal(err)
	}
}

func TestXMLParser(t *testing.T) {
	uri := joinURI(httpsEndpoint, "xmlParsing")

	// Set up a mock matcher
	g := gock.New(uri)
	g.Persist()
	g.Get(path.Base(uri)).Reply(http.StatusOK).Body(bytes.NewBuffer([]byte(helloWorldXML))).SetHeader("Content-Type", "application/xml")

	var parsedResult testStruct
	req := New(http.MethodGet, uri).ParseXML(&parsedResult)
	gock.InterceptClient(req.client)
	defer gock.RestoreClient(req.client)

	if err := req.Run(); err != nil {
		t.Fatal(err)
	}

	if parsedResult.Status != 200 || parsedResult.Message != "Hello, world! 你好世界 😊😎" {
		t.Fatalf("unexpected content of parsed result: %v", parsedResult)
	}
}

func TestModifyRequest(t *testing.T) {
	uri := joinURI(httpsEndpoint, "modifyRequest")

	// Set up a mock matcher
	g := gock.New(uri)
	g.Persist()
	g.Get(path.Base(uri)).
		MatchHeader("X-TEST", "test").
		Reply(http.StatusOK)

	t.Run("add-header", func(t *testing.T) {
		req := New(http.MethodGet, uri).ModifyRequest(func(req *http.Request) error {
			req.Header.Add("X-TEST", "test")
			return nil
		})
		gock.InterceptClient(req.client)
		defer gock.RestoreClient(req.client)

		for i := 0; i < 100; i++ {
			// Execute the request
			if err := req.Run(); err != nil {
				t.Fatal(err)
			}
		}
	})

}

func TestReuse(t *testing.T) {

	uri := joinURI(httpsEndpoint, "reuse")

	// Set up a mock matcher
	g := gock.New(uri)
	g.Persist()
	g.Get(path.Base(uri)).
		Reply(http.StatusOK)

	t.Run("normal", func(t *testing.T) {
		req := New(http.MethodGet, uri)

		gock.InterceptClient(req.client)
		defer gock.RestoreClient(req.client)

		for i := 0; i < 100; i++ {

			// Execute the request
			if err := req.Run(); err != nil {
				t.Fatal(err)
			}
		}
	})

	t.Run("with-context-timeout", func(t *testing.T) {
		req := New(http.MethodGet, uri)

		gock.InterceptClient(req.client)
		defer gock.RestoreClient(req.client)

		for i := 0; i < 100; i++ {
			func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()

				// Execute the request
				if err := req.RunWithContext(ctx); err != nil {
					t.Fatal(err)
				}
			}(t)
		}
	})
}

func TestReuseDefaultTransport(t *testing.T) {

	uri := joinURI(httpsEndpoint, "reuse")

	// Set up a mock matcher
	g := gock.New(uri)
	g.Persist()
	g.Get(path.Base(uri)).
		Reply(http.StatusOK)

	req := New(http.MethodGet, uri).
		Transport(http.DefaultTransport)

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

	gock.InterceptClient(req.client)
	defer gock.RestoreClient(req.client)

	// Execute the request
	if err := req.Run(); err != nil {
		t.Fatal(err)
	}

	// Check the latency of the request
	if lat := time.Since(start); lat < 50*time.Millisecond {
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

	gock.InterceptClient(req.client)
	defer gock.RestoreClient(req.client)

	// Execute the request
	if err := req.Run(); err != nil {
		t.Fatal(err)
	}
}

func TestSkipCertificateValidation(t *testing.T) {

	uri := joinURI(httpsEndpoint, "secure")

	// Define request disabling certificate validation
	req := New(http.MethodGet, uri).SkipCertificateVerification()

	// Set up a mock matcher
	defer gock.Off()

	gock.InterceptClient(req.client)
	defer gock.RestoreClient(req.client)

	g := gock.New(uri)
	g.Get(path.Base(uri)).
		Reply(http.StatusOK)

	// Execute the request
	if err := req.Run(); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidClientCertificates(t *testing.T) {
	if _, err := New(http.MethodGet, "https://127.0.0.1:10001/").ClientCertificates(nil, nil, nil); err == nil {
		t.Fatal("Unexpected non-nil error")
	}
	if _, err := New(http.MethodGet, "https://127.0.0.1:10001/").ClientCertificates([]byte{}, []byte{}, []byte{}); err == nil {
		t.Fatal("Unexpected non-nil error")
	}
	if _, err := New(http.MethodGet, "https://127.0.0.1:10001/").ClientCertificates([]byte{0}, []byte{1, 2}, []byte{3, 4, 5}); err == nil {
		t.Fatal("Unexpected non-nil error")
	}
	if _, err := New(http.MethodGet, "https://127.0.0.1:10001/").ClientCertificatesFromFiles("", "", ""); err == nil {
		t.Fatal("Unexpected non-nil error")
	}

	tmpClientCertFile, err := genTempFile([]byte(testClientCert))
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpClientCertFile)
	tmpClientKeyFile, err := genTempFile([]byte(testClientKey))
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpClientKeyFile)
	tmpCACertFile, err := genTempFile([]byte{})
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpCACertFile)

	if _, err := New(http.MethodGet, "https://127.0.0.1:10001/").ClientCertificatesFromFiles("/tmp/JADGSYDYhsdgayawjdas", "", ""); err == nil {
		t.Fatal("Unexpected non-nil error")
	}
	if _, err := New(http.MethodGet, "https://127.0.0.1:10001/").ClientCertificatesFromFiles("", "/tmp/JADGSYDYhsdgayawjdas", ""); err == nil {
		t.Fatal("Unexpected non-nil error")
	}
	if _, err := New(http.MethodGet, "https://127.0.0.1:10001/").ClientCertificatesFromFiles(tmpClientCertFile, "", ""); err == nil {
		t.Fatal("Unexpected non-nil error")
	}
	if _, err := New(http.MethodGet, "https://127.0.0.1:10001/").ClientCertificatesFromFiles(tmpClientCertFile, tmpClientKeyFile, ""); err == nil {
		t.Fatal("Unexpected non-nil error")
	}
	if _, err := New(http.MethodGet, "https://127.0.0.1:10001/").ClientCertificatesFromFiles(tmpClientCertFile, tmpClientKeyFile, tmpCACertFile); err == nil {
		t.Fatal("Unexpected non-nil error")
	}
}

func TestClientCertificates(t *testing.T) {

	runDummyTLSServer()

	// Define request disabling certificate validation
	req, err := New(http.MethodGet, "https://127.0.0.1:10001/").SkipCertificateVerification().ClientCertificates([]byte(testClientCert), []byte(testClientKey), []byte(testCACert))
	if err != nil {
		t.Fatal(err)
	}

	// Execute the request
	if err := req.Run(); err != nil {
		t.Fatal(err)
	}
}

func TestClientCertificatesFromFiles(t *testing.T) {

	runDummyTLSServer()

	tmpClientCertFile, err := genTempFile([]byte(testClientCert))
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpClientCertFile)
	tmpClientKeyFile, err := genTempFile([]byte(testClientKey))
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpClientKeyFile)
	tmpCACertFile, err := genTempFile([]byte(testCACert))
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpCACertFile)

	// Define request disabling certificate validation
	req, err := New(http.MethodGet, "https://127.0.0.1:10001/").SkipCertificateVerification().ClientCertificatesFromFiles(tmpClientCertFile, tmpClientKeyFile, tmpCACertFile)
	if err != nil {
		t.Fatal(err)
	}

	// Execute the request
	if err := req.Run(); err != nil {
		t.Fatal(err)
	}
}

func TestAcceptedResponseCodes(t *testing.T) {

	if err := testResponseCode([]int{}, http.StatusOK); err == nil || err.Error() != fmt.Sprintf("no accepted HTTP response codes set, considering request to be failed (Got %d)", http.StatusOK) {
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

	var (
		parsedStruct testStruct
	)
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
		New(http.MethodGet, joinURI(httpEndpoint, "json_response")): {
			expectedStatusCode: http.StatusOK,
			responseBody:       []byte(helloWorldJSON),
			responseFn:         ParseJSON(&parsedStruct),
		},
		New(http.MethodGet, joinURI(httpEndpoint, "yaml_response")): {
			expectedStatusCode: http.StatusOK,
			responseBody:       []byte(helloWorldYAML),
			responseFn:         ParseYAML(&parsedStruct),
		},
		New(http.MethodGet, joinURI(httpEndpoint, "xml_response")): {
			expectedStatusCode: http.StatusOK,
			responseBody:       []byte(helloWorldXML),
			responseFn:         ParseXML(&parsedStruct),
		},
		New(http.MethodGet, joinURI(httpEndpoint, "byte_response")): {
			expectedStatusCode: http.StatusOK,
			responseBody:       []byte(helloWorldString),
			responseFn: func(resp *http.Response) error {
				buf := new(bytes.Buffer)
				if err := Copy(buf)(resp); err != nil {
					return err
				}
				if buf.String() != helloWorldString {
					return fmt.Errorf("Unexpected body string: %s", buf.String())
				}
				return nil
			},
		},
		New(http.MethodGet, joinURI(httpEndpoint, "404_response")): {
			expectedStatusCode: http.StatusNotFound,
			expectedError:      "got 404",
			errorFn: func(resp *http.Response) error {
				return fmt.Errorf("got %d", resp.StatusCode)
			},
		},
		New(http.MethodGet, joinURI(httpEndpoint, "404_response_noFn")): {
			expectedStatusCode: http.StatusNotFound,
			expectedError:      "404 Not Found [body=]",
		},
		New(http.MethodGet, joinURI(httpEndpoint, "401_response_withJSON")): {
			expectedStatusCode: http.StatusUnauthorized,
			responseBody:       []byte(`{"code": 401, "message": "no authorization"}`),
			expectedError:      "401 Unauthorized [code=401, message=no authorization]",
		},
		New(http.MethodGet, joinURI(httpEndpoint, "401_response_withBody")).AcceptedResponseCodes([]int{http.StatusNoContent}): {
			expectedStatusCode: http.StatusUnauthorized,
			responseBody:       []byte("no authorization"),
			expectedError:      "401 Unauthorized [body=no authorization]",
		},
	}

	for k, v := range testRequests {
		t.Run(fmt.Sprintf("%s %s", k.method, k.uri), func(t *testing.T) {
			if err := runGenericRequest(k, v); err != nil {
				if v.expectedError != "" {
					if v.expectedError != err.Error() {
						t.Fatalf("error expected %s, got %s", v.expectedError, err.Error())
					}
				} else {
					t.Fatalf("Failed running test: %s", err)
				}
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
	req := k.ParseFn(v.responseFn).ErrorFn(v.errorFn)

	gock.InterceptClient(req.client)
	defer gock.RestoreClient(req.client)

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

	gock.InterceptClient(req.client)
	defer gock.RestoreClient(req.client)

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

func genTempFile(data []byte) (string, error) {

	tmpfile, err := ioutil.TempFile("", "httpc_test")
	if err != nil {
		return "", err
	}
	if _, err := tmpfile.Write(data); err != nil {
		return "", err
	}
	if err := tmpfile.Close(); err != nil {
		return "", err
	}

	return tmpfile.Name(), nil
}

func runDummyTLSServer() {

	cert, err := tls.X509KeyPair([]byte(testServerCert), []byte(testServerKey))
	if err != nil {
		panic(err)
	}

	caCertPool, err := x509.SystemCertPool()
	if err != nil {
		panic(err)
	}
	if !caCertPool.AppendCertsFromPEM([]byte(testCACert)) {
		panic(err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:10001", config)
	if err != nil {
		panic(err)
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			panic(err)
		}

		resp := &http.Response{
			StatusCode: http.StatusOK,
		}
		err = resp.Write(conn)
		if err != nil {
			panic(err)
		}

		ln.Close()
	}()
}
