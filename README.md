# A simple wrapper around the default Go http client optimized for ease-of-use

[![Github Release](https://img.shields.io/github/release/fako1024/httpc.svg)](https://github.com/fako1024/httpc/releases)
[![GoDoc](https://godoc.org/github.com/fako1024/httpc?status.svg)](https://godoc.org/github.com/fako1024/httpc/)
[![Go Report Card](https://goreportcard.com/badge/github.com/fako1024/httpc)](https://goreportcard.com/report/github.com/fako1024/httpc)
[![Build/Test Status](https://github.com/fako1024/httpc/workflows/Go/badge.svg)](https://github.com/fako1024/httpc/actions?query=workflow%3AGo)

This package wraps the Go standard http client, providing a simplified interaction model using method chaining and additional capabilities such as optional in-flow validation against an OpenAPI specification.

## Features
- Simple, method chaining based interface for HTTP client requests
- Simulation of request delays
- Validation of request + response against OpenAPI specification
- Customization of HTTP client via functional parameter
- Back-Off-Retry concept to automatically retry requests if required

## Installation
```bash
go get -u github.com/fako1024/httpc
```

## Examples
#### Perform simple HTTP GET request
```go
err := httpc.New("GET", "http://example.org").Run()
if err != nil {
	log.Fatalf("Error performing GET request: %s", err)
}
```

#### Perform HTTP GET request and parse the result as JSON into a struct
```go
var res = struct {
	Status int
	Message string
}{}
err := httpc.New("GET", "http://example.org").
	ParseJSON(&res).
	Run()
if err != nil {
	log.Fatalf("Error performing GET request: %s", err)
}
```

#### Perform HTTPS POST request with a simple body, disabling certificate validation and copying the response to a bytes.Buffer
```go
buf := new(bytes.Buffer)
err := httpc.New("POST", "https://example.org").
	SkipCertificateVerification().
    Body([]byte{0x1, 0x2}).
    ParseFn(httpc.Copy(buf)).
	Run()

if err != nil {
    log.Fatalf("Error performing POST request: %s", err)
}

fmt.Println(buf.String())
```

#### Perform HTTPS GET request (with query parameters + headers), validating request and response against OpenAPIv3 specification
```go
openAPIFileData, err := ioutil.ReadFile("/tmp/openapi.json")
if err != nil {
	log.Fatalf("Error opening OpenAPI specification file: %s", err)
}

err = httpc.New("GET", "https://example.org").
	SkipCertificateVerification().
	QueryParams(httpc.Params{
		"param": "test",
	}).
	Headers(httpc.Params{
		"X-HEADER-TEST": "test",
	}).
	OpenAPIValidationFileData(openAPIFileData).
	Run()

if err != nil {
	log.Fatalf("Error performing GET request: %s", err)
}
```
