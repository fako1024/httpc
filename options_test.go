package httpc

import (
	"net/http"
	"testing"
)

func TestWithCustomClient(t *testing.T) {

	cl := &http.Client{}

	r1 := New("Get", "/test")

	if r1.client == cl {
		t.Fatalf("r1 did not create a new client")
	}

	r2 := New("Get", "/test", WithCustomClient(cl))
	if r2.client != cl {
		t.Fatalf("r2 did not use customClient")
	}
}
