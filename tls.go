package httpc

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"path/filepath"
)

var defaultTransport = http.DefaultTransport.(*http.Transport).Clone()

// setupClientCertificateFromBytes reads the provided client certificate / key and CA certificate
// from memory and creates / modifies a tls.Config object
func setupClientCertificateFromBytes(clientCert, clientKey, caCert []byte, tlsConfig *tls.Config) (*tls.Config, error) {

	// Load the key pair
	clientKeyCert, err := tls.X509KeyPair(clientCert, clientKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load client key / certificate: %s", err)
	}

	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}

	// If required, instantiate CA certificate pool
	if tlsConfig.RootCAs == nil {

		caCertPool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("failed to obtain system CA pool: %s", err)
		}

		tlsConfig.RootCAs = caCertPool
	}

	// Append CA to pool
	if !tlsConfig.RootCAs.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to add CA certificate to pool")
	}

	// Append client certificate to config
	tlsConfig.Certificates = append(tlsConfig.Certificates, clientKeyCert)

	return tlsConfig, nil
}

// readClientCertificateFiles reads the provided client certificate / key and CA certificate
// files
func readClientCertificateFiles(certFile, keyFile, caFile string) ([]byte, []byte, []byte, error) {

	// Read the client certificate / key file
	clientCert, clientKey, err := readclientKeyCertificate(certFile, keyFile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read / decode client key / certificate file: %s", err)
	}

	// Read CA certificate from file
	caCert, err := ioutil.ReadFile(filepath.Clean(caFile))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read CA certificate: %s", err)
	}

	return clientCert, clientKey, caCert, nil
}

// readclientKeyCertificate reads both client certificate and key from their
// respective files
func readclientKeyCertificate(certFile, keyFile string) ([]byte, []byte, error) {

	// Read the client certificate file
	clientCert, err := ioutil.ReadFile(filepath.Clean(certFile))
	if err != nil {
		return nil, nil, err
	}

	// Read the client key file
	clientKey, err := ioutil.ReadFile(filepath.Clean(keyFile))
	if err != nil {
		return nil, nil, err
	}

	return clientCert, clientKey, nil
}

// setupClientCertificate uses the provided tls.Certificate and caCert bytes to create/modify tls.Config
func setupClientCertificate(clientCertWithKey tls.Certificate, caChain []*x509.Certificate, tlsConfig *tls.Config) (*tls.Config, error) {
	if clientCertWithKey.PrivateKey == nil {
		return nil, fmt.Errorf("supplied certificate does not have a private key")
	}

	if len(caChain) == 0 {
		return nil, fmt.Errorf("no ca certificate(s) supplied")
	}

	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}

	// If required, instantiate CA certificate pool
	if tlsConfig.RootCAs == nil {

		caCertPool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("failed to obtain system CA pool: %s", err)
		}

		tlsConfig.RootCAs = caCertPool
	}

	for _, cert := range caChain {
		tlsConfig.RootCAs.AddCert(cert)
	}

	// Append client certificate to config
	tlsConfig.Certificates = append(tlsConfig.Certificates, clientCertWithKey)

	return tlsConfig, nil
}

// ParseCAChain takes a file of PEM encoded things and returns the CERTIFICATEs in order
// taken and adapted from crypto/tls
func ParseCAChain(caCert []byte) ([]*x509.Certificate, error) {
	var caChain []*x509.Certificate
	for len(caCert) > 0 {
		var block *pem.Block
		block, caCert = pem.Decode(caCert)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		certBytes := block.Bytes
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, err
		}

		caChain = append(caChain, cert)
	}

	return caChain, nil
}
