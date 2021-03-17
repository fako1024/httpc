package httpc

import (
	"net/http"

	jsoniter "github.com/json-iterator/go"
	"gopkg.in/yaml.v2"
)

func ParseJSON(v interface{}) func(resp *http.Response) error {
	return func(resp *http.Response) error {
		return jsoniter.NewDecoder(resp.Body).Decode(v)
	}
}

func ParseYAML(v interface{}) func(resp *http.Response) error {
	return func(resp *http.Response) error {
		return yaml.NewDecoder(resp.Body).Decode(v)
	}
}
