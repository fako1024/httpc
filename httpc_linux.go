//go:build linux
// +build linux

package httpc

import (
	"fmt"
	"net"
	"net/http"
	"syscall"
)

// Bind sets an explicit network interface to bind the client call to
func (r *Request) Bind(iface string) *Request {
	r.bindIface = iface
	return r
}

func (r *Request) bindTo() error {
	transport, ok := r.client.Transport.(*http.Transport)
	if !ok {
		return fmt.Errorf("cannot bind to interface, http client transport is not of type *http.Transport")
	}
	var err error
	transport.DialContext = (&net.Dialer{
		Control: func(_, _ string, c syscall.RawConn) (err error) {
			return c.Control((func(fd uintptr) {
				err = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, r.bindIface)
			}))
		},
	}).DialContext
	if err != nil {
		return fmt.Errorf("failed to bind socket to interface `%s`: %w", r.bindIface, err)
	}
	return nil
}
