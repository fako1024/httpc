package httpc

import "net/http"

const authHeaderKey = "Authorization"

// AuthBasic sets parameters to perform basic authentication
func (r *Request) AuthBasic(user, password string) *Request {
	r.httpAuthFunc = func(c *http.Request) {
		c.SetBasicAuth(user, password)
	}
	return r
}

// AuthToken sets parameters to perform any token-based authentication, setting
// "Authorization: <prefix> <token>"
func (r *Request) AuthToken(prefix, token string) *Request {
	r.httpAuthFunc = func(c *http.Request) {
		c.Header.Set(authHeaderKey, prefix+" "+token)
	}
	return r
}

// AuthBearer sets parameters to perform bearer token authentication, setting
// "Authorization: Bearer <token>"
func (r *Request) AuthBearer(token string) *Request {
	r.httpAuthFunc = func(c *http.Request) {
		c.Header.Set(authHeaderKey, "Bearer "+token)
	}
	return r
}
