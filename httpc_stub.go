//go:build !linux
// +build !linux

package httpc

import "errors"

func (r *Request) bindTo() error {
	return errors.New("unsupported platform")
}
