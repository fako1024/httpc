package httpc

import (
	"encoding/xml"

	jsoniter "github.com/json-iterator/go"
	"gopkg.in/yaml.v3"
)

// Encoder denotes a generic encoder, including an encoding function and content-type getter
type Encoder interface {

	// Encode denotes a generic encoder function / method, usually a Marshal() function
	Encode() ([]byte, error)

	// ContentType provides an automated way to retrieve / set the content-type header
	ContentType() string
}

// JSONEncoder provdes encoding to JSON
type JSONEncoder struct {
	v interface{}
}

// Encode fulfills the Encoder interface, performing the actual encoding
func (e JSONEncoder) Encode() ([]byte, error) {
	return jsoniter.Marshal(e.v)
}

// ContentType fulfills the Encoder interface, providing the required content-type header
func (e JSONEncoder) ContentType() string {
	return "application/json"
}

// YAMLEncoder provdes encoding to YAML
type YAMLEncoder struct {
	v interface{}
}

// Encode fulfills the Encoder interface, performing the actual encoding
func (e YAMLEncoder) Encode() ([]byte, error) {
	return yaml.Marshal(e.v)
}

// ContentType fulfills the Encoder interface, providing the required content-type header
func (e YAMLEncoder) ContentType() string {
	return "application/yaml"
}

// XMLEncoder provdes encoding to XML
type XMLEncoder struct {
	v interface{}
}

// Encode fulfills the Encoder interface, performing the actual encoding
func (e XMLEncoder) Encode() ([]byte, error) {
	return xml.Marshal(e.v)
}

// ContentType fulfills the Encoder interface, providing the required content-type header
func (e XMLEncoder) ContentType() string {
	return "application/xml"
}
