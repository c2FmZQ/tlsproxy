// MIT License
//
// Copyright (c) 2023 TTBT Enterprises LLC
// Copyright (c) 2023 Robin Thellend <rthellend@rthellend.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// Package certmanager implements an X509 certificate manager that can replace
// https://pkg.go.dev/golang.org/x/crypto/acme/autocert#Manager for testing
// purposes.
// This certificate manager is a self-signed certificate authority that is not
// and should not be trusted for securing any real life communication.
package certmanager

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// CertManager is an X509 certificate manager that also acts as a certificate
// authority for testing purposes.
type CertManager struct {
	name      string
	key       *rsa.PrivateKey
	caCert    *x509.Certificate
	caCertPEM []byte
	pool      *x509.CertPool
	logger    func(string, ...interface{})

	mu    sync.Mutex
	certs map[string]*tls.Certificate
}

// New returns a new ephemeral certificate manager.
func New(name string, logger func(string, ...interface{})) (*CertManager, error) {
	if logger == nil {
		logger = func(string, ...interface{}) {}
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("rsa.GenerateKey: %w", err)
	}
	sn, _ := rand.Int(rand.Reader, big.NewInt(1<<32))
	now := time.Now()
	templ := &x509.Certificate{
		PublicKeyAlgorithm:    x509.RSA,
		SerialNumber:          sn,
		Issuer:                pkix.Name{CommonName: name},
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now,
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{name},
	}
	b, err := x509.CreateCertificate(rand.Reader, templ, templ, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("x509.CreateCertificate: %w", err)
	}
	caCert, err := x509.ParseCertificate(b)
	if err != nil {
		return nil, fmt.Errorf("x509.ParseCertificate: %w", err)
	}
	caCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: b,
	})
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	return &CertManager{
		name:      name,
		key:       key,
		caCert:    caCert,
		caCertPEM: caCertPEM,
		pool:      pool,
		logger:    logger,
		certs:     make(map[string]*tls.Certificate),
	}, nil
}

// RootCAPEM returns the root certificate in PEM format.
func (cm *CertManager) RootCAPEM() string {
	return string(cm.caCertPEM)
}

// RootCACertPool returns a CertPool that contains the root certificate.
func (cm *CertManager) RootCACertPool() *x509.CertPool {
	return cm.pool
}

// TLSConfig returns a tls.Config that uses this certificate manager.
func (cm *CertManager) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: cm.GetCertificate,
	}
}

// GetCertificate can be used in tls.Config.
func (cm *CertManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return cm.GetCert(hello.ServerName)
}

// GetCert returns a new tls.Certificate with name as the subject's common name.
func (cm *CertManager) GetCert(name string) (*tls.Certificate, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if c := cm.certs[name]; c != nil {
		return c, nil
	}

	cm.logger("[%s] GetCert(%q)", cm.name, name)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("rsa.GenerateKey: %w", err)
	}
	sn, _ := rand.Int(rand.Reader, big.NewInt(1<<32))
	now := time.Now()
	templ := &x509.Certificate{
		PublicKeyAlgorithm:    x509.RSA,
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now,
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDataEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		DNSNames:              []string{name},
	}
	b, err := x509.CreateCertificate(rand.Reader, templ, cm.caCert, key.Public(), cm.key)
	if err != nil {
		return nil, fmt.Errorf("x509.CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(b)
	if err != nil {
		return nil, fmt.Errorf("x509.ParseCertificate: %v", err)
	}
	cm.certs[name] = &tls.Certificate{
		Certificate: [][]byte{b},
		PrivateKey:  key,
		Leaf:        cert,
	}
	return cm.certs[name], nil
}

// HTTPHandler returns its fallback arguments. It exists only to mimic the
// autocert API.
func (cm *CertManager) HTTPHandler(fallback http.Handler) http.Handler {
	return fallback
}
