////////////////////////////////////////////////////////////////////////////////
//
// httpc.go
//
// Web interaction functions for calls to NectIdent API
//
// Written by Fabian Kohn (fk@nect.com), November 2017
// Copyright (c) 2017 Nect GmbH, Germany
// All Rights Reserved.
//
////////////////////////////////////////////////////////////////////////////////

package httpc

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	jsoniter "github.com/json-iterator/go"
	"github.com/labstack/echo"
)

var defaultacceptedResponseCodes = []int{
	http.StatusOK,
	http.StatusCreated,
	http.StatusAccepted,
}

// Params is an alias for a map of string key / value pairs
type Params = map[string]string

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
	body        []byte
	parseFn     func(resp *http.Response) error

	openAPIValidationFileData []byte
	delay                     time.Duration

	acceptedResponseCodes []int
	client                *http.Client
	httpClientFunc        func(c *http.Client)
}

// New instantiates a new http client
func New(method, uri string) *Request {

	// Instantiate a new NectIdent service using default options
	return &Request{
		method:                method,
		uri:                   uri,
		acceptedResponseCodes: defaultacceptedResponseCodes,
		client: &http.Client{
			Transport: defaultTransport.Clone(),
		},
	}
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

// QueryParams sets the query parameters for the client call
func (r *Request) QueryParams(queryParams Params) *Request {
	r.queryParams = queryParams
	return r
}

// Headers sets the headers for the client call
func (r *Request) Headers(headers Params) *Request {
	r.headers = headers
	return r
}

// Body sets the body for the client call
func (r *Request) Body(body []byte) *Request {
	r.body = body
	return r
}

// ParseFn sets a parsing function for the result of the client call
func (r *Request) ParseFn(parseFn func(resp *http.Response) error) *Request {
	r.parseFn = parseFn
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
func (r *Request) ModifyHTTPClient(fn func(c *http.Client)) *Request {
	r.httpClientFunc = fn
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

	// Initialize new http.Request
	req, err := http.NewRequest(r.method, r.uri, nil)
	if err != nil {
		return fmt.Errorf("error creating request: %s", err)
	}

	// Notify the server that the connection should be closed after completion of
	// the request
	req.Close = false

	// If a body was provided, assign it to the request
	if len(r.body) > 0 {

		// If a delay was requested, assign a delayed reader
		if r.delay > 0 {
			req.Body = ioutil.NopCloser(newDelayedReader(bytes.NewBuffer(r.body), r.delay))
		} else {
			req.Body = ioutil.NopCloser(bytes.NewBuffer(r.body))
		}

		// Pass content length to enforce non-chunked http request.
		// Since data is completly in mem it's useless anyways.
		// Also needed to mitigate a bug in PHP...
		req.ContentLength = int64(len(r.body))
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
			req.Header.Add(key, val)
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
		swaggerFileData, err := openapi3.NewSwaggerLoader().LoadSwaggerFromData(r.openAPIValidationFileData)
		if err != nil {
			return err
		}
		router := openapi3filter.NewRouter().WithSwagger(swaggerFileData)
		ctx := context.TODO()
		route, pathParams, err := router.FindRoute(req.Method, req.URL)
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

	// Perform the actual request
	var resp *http.Response
	if r.timeout > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
		defer cancel()
		resp, err = r.client.Do(req.WithContext(ctx))
	} else {
		resp, err = r.client.Do(req)
	}
	if err != nil {
		return err
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
			data, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			resp.Body = ioutil.NopCloser(bytes.NewBuffer(data))
			responseValidationInput.Body = ioutil.NopCloser(bytes.NewBuffer(data))
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

		// Read the binary data from the response body
		var extraErr echo.HTTPError
		if err := jsoniter.NewDecoder(resp.Body).Decode(&extraErr); err != nil {
			return fmt.Errorf("%s [%.256s]", resp.Status, fmt.Sprintf("code=%d, message=%v", extraErr.Code, extraErr.Message))
		}

		return fmt.Errorf("unknown error occurred")
	}

	// If a parsing function was provided, execute it
	if r.parseFn != nil {
		return r.parseFn(resp)
	}

	return nil
}

////////////////////////////////////////////////////////////////////////////////

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
