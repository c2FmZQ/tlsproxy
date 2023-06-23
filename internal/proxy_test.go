// MIT License
//
// Copyright (c) 2023 TTBT Enterprises LLC
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

package internal

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestProxyBackends(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	extCA := newTestCA(t, "root-ca.example.com")
	intCA := newTestCA(t, "internal-ca.example.com")
	// Backends without TLS.
	be1 := newTCPServer(t, ctx, "backend1", nil)
	be2 := newTCPServer(t, ctx, "backend2", nil)
	// Backends with TLS enabled.
	be3 := newTCPServer(t, ctx, "backend3", intCA)
	be4 := newTCPServer(t, ctx, "backend4", intCA)

	cfg := &Config{
		HTTPAddr: "localhost:0",
		TLSAddr:  "localhost:0",
		CacheDir: t.TempDir(),
		MaxOpen:  100,
		Backends: []*Backend{
			// Plaintext backends.
			{
				ServerNames: []string{
					"example.com",
					"www.example.com",
				},
				Addresses: []string{
					be1.listener.Addr().String(),
					be2.listener.Addr().String(),
				},
			},
			// TLS backends.
			{
				ServerNames: []string{
					"other.example.com",
				},
				Addresses: []string{
					be3.listener.Addr().String(),
				},
				UseTLS:            true,
				ForwardRootCAs:    string(intCA.caCertPEM),
				ForwardServerName: "other-internal.example.com",
			},
			// TLS backends, require clients to present a certificate.
			{
				ServerNames: []string{
					"secure.example.com",
				},
				Addresses: []string{
					be4.listener.Addr().String(),
				},
				UseTLS:            true,
				ForwardRootCAs:    string(intCA.caCertPEM),
				ForwardServerName: "secure-internal.example.com",
				ClientAuth:        true,
				ClientCAs:         string(intCA.caCertPEM),
			},
		},
	}
	proxy := newTestProxy(cfg, extCA)
	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}
	get := func(host, certName string) (string, error) {
		var certs []tls.Certificate
		if certName != "" {
			c, err := intCA.getCertificate(certName)
			if err != nil {
				t.Fatalf("intCA.getCertificate: %v", err)
			}
			certs = append(certs, *c)
		}
		body, err := tlsGet(host, proxy.listener.Addr().String(), extCA, certs)
		if err != nil {
			return "", err
		}
		return body, nil
	}

	for _, tc := range []struct {
		desc, host, want string
		certName         string
		expError         bool
	}{
		{desc: "Hit backend1", host: "example.com", want: "Hello from backend1\n"},
		{desc: "Hit backend2", host: "example.com", want: "Hello from backend2\n"},
		{desc: "Hit backend1 again", host: "www.example.com", want: "Hello from backend1\n"},
		{desc: "Hit backend2 again", host: "www.example.com", want: "Hello from backend2\n"},
		{desc: "Hit backend3", host: "other.example.com", want: "Hello from backend3\n"},
		{desc: "Hit backend4", host: "secure.example.com", want: "Hello from backend4\n", certName: "client.example.com"},
		{desc: "Hit backend4 no cert", host: "secure.example.com", expError: true},
		{desc: "Unknown server name", host: "foo.example.com", expError: true},
	} {
		got, err := get(tc.host, tc.certName)
		if tc.expError != (err != nil) {
			t.Errorf("%s: Got error %v, want %v", tc.desc, (err != nil), tc.expError)
			continue
		}
		if err != nil {
			continue
		}
		if got != tc.want {
			t.Errorf("%s: Got %q, want %q", tc.desc, got, tc.want)
		}
	}
}

func newTestProxy(cfg *Config, ca *testCA) *Proxy {
	p := &Proxy{certManager: ca}
	p.Reconfigure(cfg)
	return p
}

func tlsGet(name, addr string, rootCA *testCA, clientCerts []tls.Certificate) (string, error) {
	c, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName:   name,
		RootCAs:      rootCA.pool,
		Certificates: clientCerts,
	})
	if err != nil {
		return "", err
	}
	defer c.Close()
	b, err := io.ReadAll(c)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func newTCPServer(t *testing.T, ctx context.Context, name string, ca *testCA) *tcpServer {
	var l net.Listener
	var err error
	if ca == nil {
		l, err = net.Listen("tcp", "localhost:0")
	} else {
		l, err = tls.Listen("tcp", "localhost:0", ca.TLSConfig())
	}
	if err != nil {
		t.Fatalf("[%s] Listen: %v", name, err)
	}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					break
				}
				t.Logf("[%s] Accept: %v", name, err)
				continue
			}
			t.Logf("[%s] Received connection from %s", name, conn.RemoteAddr())
			go func(c net.Conn) {
				fmt.Fprintf(c, "Hello from %s\n", name)
				c.Close()
			}(conn)
		}
	}()
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	return &tcpServer{
		t:        t,
		listener: l,
	}
}

type tcpServer struct {
	t        *testing.T
	listener net.Listener
}

type testCA struct {
	t *testing.T

	name      string
	key       *rsa.PrivateKey
	caCert    *x509.Certificate
	caCertPEM []byte
	pool      *x509.CertPool

	mu    sync.Mutex
	certs map[string]*tls.Certificate
}

func newTestCA(t *testing.T, name string) *testCA {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
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
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(b)
	if err != nil {
		t.Fatalf("x509.ParseCertificate: %v", err)
	}
	caCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: b,
	})
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	//t.Logf("[%s] CERT\n%s", name, caCertPEM)

	return &testCA{
		t:         t,
		name:      name,
		key:       key,
		caCert:    caCert,
		caCertPEM: caCertPEM,
		pool:      pool,
		certs:     make(map[string]*tls.Certificate),
	}
}

func (ca *testCA) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: ca.GetCertificate,
	}
}

func (ca *testCA) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return ca.getCertificate(hello.ServerName)
}

func (ca *testCA) getCertificate(name string) (*tls.Certificate, error) {
	t := ca.t
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if c := ca.certs[name]; c != nil {
		return c, nil
	}

	t.Logf("[%s] getCertificate(%q)", ca.name, name)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
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
	b, err := x509.CreateCertificate(rand.Reader, templ, ca.caCert, key.Public(), ca.key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(b)
	if err != nil {
		t.Fatalf("x509.ParseCertificate: %v", err)
	}
	ca.certs[name] = &tls.Certificate{
		Certificate: [][]byte{b},
		PrivateKey:  key,
		Leaf:        cert,
	}
	return ca.certs[name], nil
}

func (ca *testCA) HTTPHandler(fallback http.Handler) http.Handler {
	return fallback
}
