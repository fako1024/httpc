package httpc

import (
	"io"
	"net/http"

	jsoniter "github.com/json-iterator/go"
	"gopkg.in/yaml.v2"
)

// EncoderFn denotes a generic encoder function / method, usually a Marshal() function
type EncoderFn func(v interface{}) ([]byte, error)

var (

	// EncodeJSON provides a default function to encode a body to JSON
	EncodeJSON = jsoniter.Marshal

	// EncodeYAML provides a default function to encode a body to YAML
	EncodeYAML = yaml.Marshal
)

// Copy copies the response body into any io.Writer
func Copy(w io.Writer) func(resp *http.Response) error {
	return func(resp *http.Response) error {
		_, err := io.Copy(w, resp.Body)
		return err
	}
}

// ParseJSON parses the response body as JSON into a struct
func ParseJSON(v interface{}) func(resp *http.Response) error {
	return func(resp *http.Response) error {
		return jsoniter.NewDecoder(resp.Body).Decode(v)
	}
}

// ParseYAML parses the response body as YAML into a struct
func ParseYAML(v interface{}) func(resp *http.Response) error {
	return func(resp *http.Response) error {
		return yaml.NewDecoder(resp.Body).Decode(v)
	}
}
