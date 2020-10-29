package httpc

import (
	"bytes"
	"fmt"
	"io/ioutil"
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

func TestTable(t *testing.T) {

	var testRequests = map[*Request]testCase{
		New(http.MethodGet, path.Join(endpoint, "simple_ok")): {
			expectedStatusCode: http.StatusOK,
			responseFn: func(resp *http.Response) error {
				return nil
			},
		},
		New(http.MethodPost, path.Join(endpoint, "simple_ok")): {
			expectedStatusCode: http.StatusOK,
			responseFn: func(resp *http.Response) error {
				return nil
			},
		},
		New(http.MethodPut, path.Join(endpoint, "simple_ok")): {
			expectedStatusCode: http.StatusOK,
			responseFn: func(resp *http.Response) error {
				return nil
			},
		},
		New(http.MethodDelete, path.Join(endpoint, "simple_ok")): {
			expectedStatusCode: http.StatusOK,
			responseFn: func(resp *http.Response) error {
				return nil
			},
		},
		New(http.MethodGet, path.Join(endpoint, "string_message")): {
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

			// Define the return code (and body, if provided)
			if v.body != nil {
				g.Reply(v.expectedStatusCode).Body(bytes.NewBuffer(v.body))
			} else {
				g.Reply(v.expectedStatusCode)
			}

			// Execute and parse the result (if parsing function was provided)
			err := k.ParseFn(v.responseFn).Run()
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
