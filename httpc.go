package httpc

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers/legacy"
	jsoniter "github.com/json-iterator/go"
)

const (
	contentTypeHeaderKey        = "Content-Type"
	contentTypeHeaderValRFC9457 = "application/problem+json"
)

var (
	// ErrErrRetryLimit
	ErrRetryLimit = errors.New("maximum number of request retries reached")

	defaultacceptedResponseCodes = []int{
		http.StatusOK,
		http.StatusCreated,
		http.StatusAccepted,
	}

	defaultRetryErrFn = func(resp *http.Response, err error) bool {
		return err != nil
	}
)

// Params is an alias for a map of string key / value pairs
type Params = map[string]string

// Intervals is an alias for a list of durations / time intervals
type Intervals = []time.Duration

// Request represents a generic web request for quick execution, providing access
// to method, URL parameters, headers, the body and an optional 1st class function
// used to parse the result
type Request struct {
	method      string
	uri         string
	host        string
	timeout     time.Duration
	queryParams Params
	headers     Params
	parseFn     func(resp *http.Response) error
	errorFn     func(resp *http.Response) error

	bodyEncoder Encoder
	body        []byte

	openAPIValidationFileData []byte
	delay                     time.Duration
	retryIntervals            Intervals
	retryErrFn                func(resp *http.Response, err error) bool
	retryEventFn              func(attempt int, resp *http.Response, err error)

	acceptedResponseCodes []int
	client                *http.Client
	httpClientFunc        func(c *http.Client)
	httpRequestFunc       func(c *http.Request) error
	httpAuthFunc          func(c *http.Request)
}

// New instantiates a new http client
func New(method, uri string) *Request {
	// Instantiate a new NectIdent service using default options
	return NewWithClient(method, uri, nil)
}

// NewWithClient instantiates a new httpc request with custom http client
// This eases testing and client interception
func NewWithClient(method, uri string, hc *http.Client) *Request {
	r := &Request{
		method:                method,
		uri:                   uri,
		acceptedResponseCodes: defaultacceptedResponseCodes,
		client:                hc,
	}

	if r.client == nil {
		r.client = &http.Client{Transport: defaultTransport.Clone()}
	}

	return r
}

// GetMethod returns the method of the request
func (r *Request) GetMethod() string {
	return r.method
}

// GetURI returns the URI of the request
func (r *Request) GetURI() string {
	return r.uri
}

// GetBody returns the body of the request
func (r *Request) GetBody() []byte {
	return r.body
}

// HostName sets an explicit hostname for the client call
func (r *Request) HostName(host string) *Request {
	r.host = host
	return r
}

// Timeout sets timeout for the client call
func (r *Request) Timeout(timeout time.Duration) *Request {
	r.timeout = timeout
	return r
}

// RetryBackOff sets back-off intervals and attempts the call multiple times
func (r *Request) RetryBackOff(intervals Intervals) *Request {
	r.retryIntervals = intervals
	return r
}

// RetryBackOffErrFn sets an assessment function to decide wether an error
// or status code is deemed as a reason to retry the call.
// Note: both the response and the error may be nil (depending on the reason for the retry)
// so proper checks must be ensured
func (r *Request) RetryBackOffErrFn(fn func(*http.Response, error) bool) *Request {
	r.retryErrFn = fn
	return r
}

// RetryEventFn sets an event handler / function that gets triggered upon a retry, providing
// the HTTP response and error that causes the retry.
// Note: both the response and the error may be nil (depending on the reason for the retry)
// so proper checks must be ensured
func (r *Request) RetryEventFn(fn func(int, *http.Response, error)) *Request {
	r.retryEventFn = fn
	return r
}

// SkipCertificateVerification will accept any SSL certificate
func (r *Request) SkipCertificateVerification() *Request {
	r.client.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true

	return r
}

// ClientCertificates sets client certificates from memory
func (r *Request) ClientCertificates(clientCert, clientKey, caCert []byte) (*Request, error) {
	tlsConfig, err := setupClientCertificateFromBytes(clientCert, clientKey, caCert, r.client.Transport.(*http.Transport).TLSClientConfig)
	if err != nil {
		return r, err
	}

	r.client.Transport.(*http.Transport).TLSClientConfig = tlsConfig

	return r, nil
}

// ClientCertificatesFromFiles sets client certificates from files
func (r *Request) ClientCertificatesFromFiles(certFile, keyFile, caFile string) (*Request, error) {
	clientCert, clientKey, caCert, err := readClientCertificateFiles(certFile, keyFile, caFile)
	if err != nil {
		return r, err
	}

	return r.ClientCertificates(clientCert, clientKey, caCert)
}

// ClientCertificatesFromInstance sets the client certificates from a cert instance
func (r *Request) ClientCertificatesFromInstance(clientCertWithKey tls.Certificate, caChain []*x509.Certificate) (*Request, error) {
	tlsConfig, err := setupClientCertificate(clientCertWithKey, caChain, r.client.Transport.(*http.Transport).TLSClientConfig)

	if err != nil {
		return r, err
	}

	r.client.Transport.(*http.Transport).TLSClientConfig = tlsConfig

	return r, nil
}

// QueryParams sets the URL / query parameters for the client call
// Note: Any existing URL / query parameters are overwritten / removed
func (r *Request) QueryParams(queryParams Params) *Request {
	r.queryParams = queryParams
	return r
}

// Headers sets the headers for the client call
// Note: Any existing headers are overwritten / removed
func (r *Request) Headers(headers Params) *Request {
	r.headers = headers
	return r
}

// Body sets the body for the client call
// Note: Any existing body is overwritten
func (r *Request) Body(body []byte) *Request {
	r.body = body
	return r
}

// Encode encodes and sets the body for the client call using an arbitrary encoder
func (r *Request) Encode(encoder Encoder) *Request {
	r.bodyEncoder = encoder
	return r
}

// EncodeJSON encodes and sets the body for the client call using JSON encoding
func (r *Request) EncodeJSON(v any) *Request {
	r.bodyEncoder = JSONEncoder{v}
	return r
}

// EncodeYAML encodes and sets the body for the client call using YAML encoding
func (r *Request) EncodeYAML(v any) *Request {
	r.bodyEncoder = YAMLEncoder{v}
	return r
}

// EncodeXML encodes and sets the body for the client call using XML encoding
func (r *Request) EncodeXML(v any) *Request {
	r.bodyEncoder = XMLEncoder{v}
	return r
}

// ParseFn sets a generic parsing function for the result of the client call
func (r *Request) ParseFn(parseFn func(*http.Response) error) *Request {
	r.parseFn = parseFn
	return r
}

// ParseJSON parses the result of the client call as JSON
func (r *Request) ParseJSON(v any) *Request {
	r.parseFn = ParseJSON(v)
	return r
}

// ParseYAML parses the result of the client call as YAML
func (r *Request) ParseYAML(v any) *Request {
	r.parseFn = ParseYAML(v)
	return r
}

// ParseXML parses the result of the client call as XML
func (r *Request) ParseXML(v any) *Request {
	r.parseFn = ParseXML(v)
	return r
}

// ErrorFn sets a parsing function for results not handled by ParseFn
func (r *Request) ErrorFn(errorFn func(*http.Response) error) *Request {
	r.errorFn = errorFn
	return r
}

// OpenAPIValidationFileData sets an OpenAPI validation file for the client call
// using a byte slice (containing the raw JSON file data)
func (r *Request) OpenAPIValidationFileData(fileData []byte) *Request {
	r.openAPIValidationFileData = fileData
	return r
}

// Delay sets an artificial delay for the client call
func (r *Request) Delay(delay time.Duration) *Request {
	r.delay = delay
	return r
}

// ModifyHTTPClient executes any function / allows setting parameters of the
// underlying HTTP client before the actual request is made
func (r *Request) ModifyHTTPClient(fn func(*http.Client)) *Request {
	r.httpClientFunc = fn
	return r
}

// ModifyRequest allows the caller to call any methods or other functions on the
// http.Request prior to execution of the call
func (r *Request) ModifyRequest(fn func(*http.Request) error) *Request {
	r.httpRequestFunc = fn
	return r
}

// Transport forces a specific transport for the HTTP client (e.g. http.DefaultTransport
// in order to support standard gock flows)
func (r *Request) Transport(transport http.RoundTripper) *Request {
	r.client.Transport = transport
	return r
}

// AcceptedResponseCodes defines a set of accepted HTTP response codes for the
// client call
func (r *Request) AcceptedResponseCodes(acceptedResponseCodes []int) *Request {
	r.acceptedResponseCodes = acceptedResponseCodes
	return r
}

// Run executes a request
func (r *Request) Run() error {
	return r.RunWithContext(context.Background())
}

var (
	errorEncodedRawBodyCollision = errors.New("cannot use both body encoding and raw body content")
)

func (r *Request) setBody(req *http.Request) (err error) {

	// If requested, parse the requst body using the specified encoder
	bodyBytes := r.body
	if r.bodyEncoder != nil {
		if len(r.body) > 0 {
			return errorEncodedRawBodyCollision
		}

		bodyBytes, err = r.bodyEncoder.Encode()
		if err != nil {
			return fmt.Errorf("error encoding body: %w", err)
		}
		req.Header.Set(contentTypeHeaderKey, r.bodyEncoder.ContentType())
	}

	contentLength := len(bodyBytes)

	// From net/http:
	//
	// 	If body is of type *bytes.Buffer, *bytes.Reader, or *strings.Reader, the returned request's ContentLength is set to its exact value
	// 	(instead of -1), GetBody is populated (so 307 and 308 redirects can replay the body), and Body is set to NoBody if the ContentLength
	// 	is 0.
	req.Body = http.NoBody
	if contentLength > 0 {
		req.ContentLength = int64(contentLength)

		// If a delay was requested, assign a delayed reader
		if r.delay > 0 {
			dr := newDelayedReader(bytes.NewBuffer(bodyBytes), r.delay)

			req.GetBody = func() (io.ReadCloser, error) {
				snapshot := newDelayedReader(bytes.NewReader(bodyBytes), r.delay)
				return io.NopCloser(snapshot), nil
			}
			req.Body = io.NopCloser(dr)
			return nil
		}

		buf := bytes.NewReader(bodyBytes)

		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(bodyBytes)), nil
		}
		req.Body = io.NopCloser(buf)
	}

	return nil
}

// RunWithContext executes a request using a specific context
func (r *Request) RunWithContext(ctx context.Context) error {

	// Initialize new http.Request

	req, err := http.NewRequestWithContext(ctx, r.method, r.uri, nil)
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}
	if err = r.setBody(req); err != nil {
		return fmt.Errorf("failed to set request body: %w", err)
	}

	// Notify the server that the connection should be closed after completion of
	// the request
	req.Close = false

	// If requested, set authentication
	if r.httpAuthFunc != nil {
		r.httpAuthFunc(req)
	}

	// If URL parameters were provided, assign them to the request
	if r.queryParams != nil {
		q := req.URL.Query()
		for key, val := range r.queryParams {
			q.Set(key, val)
		}
		req.URL.RawQuery = q.Encode()
	}

	// If headers were provided, assign them to the request
	if r.headers != nil {
		for key, val := range r.headers {
			req.Header.Set(key, val)
		}
	}

	if r.httpClientFunc != nil {
		r.httpClientFunc(r.client)
	}

	// If an explicit host override was provided it, set it
	if r.host != "" {
		req.Host = r.host
	}

	// Perform validation agaions OpenAPI specification, if requested
	var requestValidationInput *openapi3filter.RequestValidationInput
	if r.openAPIValidationFileData != nil {
		swaggerFileData, err := openapi3.NewLoader().LoadFromData(r.openAPIValidationFileData)
		if err != nil {
			return err
		}
		router, err := legacy.NewRouter(swaggerFileData)
		if err != nil {
			return err
		}

		route, pathParams, err := router.FindRoute(req)
		if err != nil {
			return err
		}

		requestValidationInput = &openapi3filter.RequestValidationInput{
			Request:    req,
			PathParams: pathParams,
			Route:      route,
		}
		if err := openapi3filter.ValidateRequest(ctx, requestValidationInput); err != nil {
			return err
		}
	}

	if r.httpRequestFunc != nil {
		err := r.httpRequestFunc(req)

		if err != nil {
			return err
		}
	}

	// Handle retry options / parameter
	retryErrFn, err := r.setRetryHandling()
	if err != nil {
		return err
	}

	// Perform the actual request
	var resp *http.Response
	if r.timeout > 0 {
		timeoutCtx, timeoutCancel := context.WithTimeout(req.Context(), r.timeout)
		defer timeoutCancel()
		req = req.WithContext(timeoutCtx)
	}

	resp, err = r.client.Do(req)
	for i := 0; retryErrFn(resp, err) && i < len(r.retryIntervals); i++ {

		// If a retry event handler exists, trigger it
		if r.retryEventFn != nil {
			r.retryEventFn(i+1, resp, err)
		}

		// Wait until the retry inteval has elapsed or the context was cancelled
		// In both cases simply continue and have the client handle the (potentially
		// cancelled) context (that way the same error is returned no matter _when_
		// the context was cancelled)
		timer := time.NewTimer(r.retryIntervals[i])
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}

		if err = r.setBody(req); err != nil {
			return fmt.Errorf("failed to set request body: %w", err)
		}
		resp, err = r.client.Do(req)
	}

	// If the cause was an actual error, return it - otherwise return sentinal error
	if retryErrFn(resp, err) {
		if err != nil {
			return err
		}
		return ErrRetryLimit
	}

	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	// Perform validation agaions OpenAPI specification, if requested
	if r.openAPIValidationFileData != nil {
		responseValidationInput := &openapi3filter.ResponseValidationInput{
			RequestValidationInput: requestValidationInput,
			Status:                 resp.StatusCode,
			Header:                 resp.Header,
			Body:                   resp.Body,
		}
		if resp.Body != nil {
			data, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			resp.Body = io.NopCloser(bytes.NewBuffer(data))
			responseValidationInput.Body = io.NopCloser(bytes.NewBuffer(data))
		}

		// Validate response
		ctx := context.TODO()
		if err := openapi3filter.ValidateResponse(ctx, responseValidationInput); err != nil {
			return err
		}
	}

	// Check if the query was successful
	if len(r.acceptedResponseCodes) == 0 {
		return fmt.Errorf("no accepted HTTP response codes set, considering request to be failed (Got %d)", resp.StatusCode)
	}
	if !isAnyOf(resp.StatusCode, r.acceptedResponseCodes) {
		if r.errorFn != nil {
			return r.errorFn(resp)
		}

		buf := new(bytes.Buffer)
		if _, err := io.Copy(buf, resp.Body); err != nil {
			return fmt.Errorf("failed to load body into buffer for error handling: %w", err)
		}

		// Handle RFC 9457
		if strings.EqualFold(resp.Header.Get(contentTypeHeaderKey), contentTypeHeaderValRFC9457) {
			return fmt.Errorf("%s [body=%s]", resp.Status, buf.String())
		}

		// Attempt to decode a generic JSON error from the response body
		var extraErr HTTPError
		if err := jsoniter.NewDecoder(bytes.NewReader(buf.Bytes())).Decode(&extraErr); err == nil {
			return fmt.Errorf("%s [%.512s]", resp.Status, fmt.Sprintf("code=%d, message=%v", extraErr.Code, extraErr.Message))
		}

		// Attempt to decode the response body directly
		return fmt.Errorf("%s [body=%.512s]", resp.Status, buf.String())
	}

	// If a parsing function was provided, execute it
	if r.parseFn != nil {
		return r.parseFn(resp)
	}

	return nil
}

////////////////////////////////////////////////////////////////////////////////

func (r *Request) setRetryHandling() (func(resp *http.Response, err error) bool, error) {

	// Check if provided parameters / options are consistent
	if len(r.retryIntervals) == 0 {
		if r.retryErrFn != nil || r.retryEventFn != nil {
			return nil, fmt.Errorf("cannot use RetryBackOffErrFn() [used: %v] / RetryEventFn() [used: %v] without providing intervals via RetryBackOff()",
				r.retryErrFn != nil,
				r.retryEventFn != nil)
		}
	}

	// Set retry / back-off function to use
	retryErrFn := defaultRetryErrFn
	if r.retryErrFn != nil {
		retryErrFn = r.retryErrFn
	}

	return retryErrFn, nil
}

type delayReader struct {
	reader     io.Reader
	wasDelayed bool
	delay      time.Duration
}

func newDelayedReader(reader io.Reader, delay time.Duration) *delayReader {
	return &delayReader{reader: reader, delay: delay}
}

func (a *delayReader) Read(p []byte) (int, error) {
	if !a.wasDelayed {
		time.Sleep(a.delay)
		a.wasDelayed = true
	}

	return a.reader.Read(p)
}

func isAnyOf(val int, ref []int) bool {
	for _, v := range ref {
		if v == val {
			return true
		}
	}

	return false
}
