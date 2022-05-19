package httpc

import "net/http"

type Option func(*Request)

func WithCustomClient(client *http.Client) Option {
	return func(r *Request) {
		r.client = client
	}
}
