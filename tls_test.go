package httpc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"
)

func constructTLSKeys() (tls.Certificate, tls.Certificate, []*x509.Certificate, error) {
	fail := func(err error) (tls.Certificate, tls.Certificate, []*x509.Certificate, error) {
		return tls.Certificate{}, tls.Certificate{}, nil, err
	}

	// generate CA key
	caKey, err := rsa.GenerateKey(rand.Reader, 1024)

	if err != nil {
		return fail(err)
	}

	caSerial, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))

	if err != nil {
		return fail(err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: caSerial,
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,

		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	// generate CA cert
	caCert, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)

	if err != nil {
		return fail(err)
	}

	caCertParsed, err := x509.ParseCertificate(caCert)

	if err != nil {
		return fail(err)
	}

	// generate leaf key
	leafKey, err := rsa.GenerateKey(rand.Reader, 1024)

	if err != nil {
		return fail(err)
	}

	leafSerial, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))

	if err != nil {
		return fail(err)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: leafSerial,
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	// generate leaf cert, signed by CA
	leafCert, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCertParsed, &leafKey.PublicKey, caKey)

	if err != nil {
		return fail(err)
	}

	// generate leaf key
	serverKey, err := rsa.GenerateKey(rand.Reader, 1024)

	if err != nil {
		return fail(err)
	}

	serverSerial, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))

	if err != nil {
		return fail(err)
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: serverSerial,
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),

		KeyUsage: x509.KeyUsageDigitalSignature,

		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	// generate leaf cert, signed by CA
	serverCert, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCertParsed, &serverKey.PublicKey, caKey)

	if err != nil {
		return fail(err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{leafCert},
		PrivateKey:  leafKey,
	}
	serverTlsCert := tls.Certificate{
		Certificate: [][]byte{serverCert},
		PrivateKey:  serverKey,
	}

	return tlsCert, serverTlsCert, []*x509.Certificate{caCertParsed}, nil
}

func configureTLSServer(serverCertWithKey tls.Certificate, caChain []*x509.Certificate) (net.Listener, chan error, error) {
	caCertPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, nil, err
	}

	for _, cert := range caChain {
		caCertPool.AddCert(cert)

	}

	config := &tls.Config{
		Certificates: []tls.Certificate{serverCertWithKey},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:10002", config)
	if err != nil {
		return nil, nil, err
	}

	c := make(chan error, 1)

	go func() {
		for {
			conn, err := ln.Accept()

			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				c <- err
				continue
			}

			resp := &http.Response{
				StatusCode: http.StatusOK,
			}
			err = resp.Write(conn)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				c <- err
				continue
			}
			c <- nil
		}
	}()

	return ln, c, nil
}

func TestCertificateInstance(t *testing.T) {
	r := New(http.MethodGet, "/")

	clientCertKey, serverTlsCert, caChain, err := constructTLSKeys()

	if err != nil {
		t.Fatal(err)
	}

	_, err = r.ClientCertificatesFromInstance(clientCertKey, caChain)

	if err != nil {
		t.Error(err)
	}

	ln, respChan, err := configureTLSServer(serverTlsCert, caChain)

	if err != nil {
		t.Error(err)
	}

	defer ln.Close()

	if err != nil {
		t.Fatal(err)
	}
	// Define request disabling certificate validation
	req, err := New(http.MethodGet, "https://127.0.0.1:10002/").ClientCertificatesFromInstance(clientCertKey, caChain)
	if err != nil {
		t.Fatal(err)
	}

	err = req.Run()
	// Execute the request
	if err != nil {
		t.Error(err)
	}

	err = <-respChan

	if err != nil {
		t.Error(err)
	}
}

func TestCertificateInstanceNoPrivateKey(t *testing.T) {
	r := New(http.MethodGet, "/")

	clientCertKey, _, caBytes, err := constructTLSKeys()

	if err != nil {
		t.Fatal(err)
	}

	clientCertKey.PrivateKey = nil

	_, err = r.ClientCertificatesFromInstance(clientCertKey, caBytes)

	if err == nil {
		t.Error("expected err, got none")
	}
}
