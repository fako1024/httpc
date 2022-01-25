package httpc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"math"
	"math/big"
	"net/http"
	"testing"
)

func constructTLSKeys() (tls.Certificate, []*x509.Certificate, error) {
	fail := func(err error) (tls.Certificate, []*x509.Certificate, error) {
		return tls.Certificate{}, nil, err
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
	}

	// generate leaf cert, signed by CA
	leafCert, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCertParsed, &leafKey.PublicKey, caKey)

	if err != nil {
		return fail(err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{leafCert},
		PrivateKey:  leafKey,
	}

	return tlsCert, []*x509.Certificate{caCertParsed}, nil
}

func TestCertificateInstance(t *testing.T) {
	r := New(http.MethodGet, "/")

	clientCertKey, caBytes, err := constructTLSKeys()

	if err != nil {
		t.Fatal(err)
	}

	_, err = r.ClientCertificatesFromInstance(clientCertKey, caBytes)

	if err != nil {
		t.Error(err)
	}
}

func TestCertificateInstanceNoPrivateKey(t *testing.T) {
	r := New(http.MethodGet, "/")

	clientCertKey, caBytes, err := constructTLSKeys()

	if err != nil {
		t.Fatal(err)
	}

	clientCertKey.PrivateKey = nil

	_, err = r.ClientCertificatesFromInstance(clientCertKey, caBytes)

	if err == nil {
		t.Error("expected err, got none")
	}
}
