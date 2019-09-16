
# A simple wrapper around the default Go http client optimized for ease-of-use

This package wraps the Go standard http client, providing a simplified interaction model using method chaining and additional capabilities such as optional in-flow validation against an OpenAPI specification.

## Features
- Simple, method chaining based interface for HTTP client requests
- Simulation of request delays (optional)
- Validation of request + response against OpenAPI specification (optional)
- Customization of HTTP client via functional parameter

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

#### Perform HTTPS POST request with a simple body, disabling certificate validation and parsing the response
```go
err := httpc.New("POST", "https://example.org").
	SkipCertificateVerification().
	Body([]byte{0x1, 0x2}).
	ParseFn(func(resp *http.Response) error {

		// Read the binary data from the response body
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("Failed to read response body: %s", err)
		}

		log.Printf("Read body content: %s\n", string(bodyBytes))

		return nil
	}).Run()

	if err != nil {
		log.Fatalf("Error performing POST request: %s", err)
	}
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
	log.Fatalf("Error performing POST request: %s", err)
}
```
