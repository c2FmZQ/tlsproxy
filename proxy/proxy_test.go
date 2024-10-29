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

package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/c2FmZQ/storage"
	"github.com/c2FmZQ/storage/crypto"
	"github.com/c2FmZQ/tpm"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/pires/go-proxyproto"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/c2FmZQ/tlsproxy/certmanager"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/ocspcache"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/pki"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/tokenmanager"
)

func TestProxyBackends(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	extCA, err := certmanager.New("root-ca.example.com", t.Logf)
	if err != nil {
		t.Fatalf("certmanager.New: %v", err)
	}
	intCA, err := certmanager.New("internal-ca.example.com", t.Logf)
	if err != nil {
		t.Fatalf("certmanager.New: %v", err)
	}

	proxy := newTestProxy(
		&Config{
			HTTPAddr: "localhost:0",
			TLSAddr:  "localhost:0",
			CacheDir: t.TempDir(),
			MaxOpen:  100,
			PKI: []*ConfigPKI{
				{Name: "TEST CA"},
			},
		},
		extCA,
	)
	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}

	pkiCert, err := newPKICert(proxy.pkis["TEST CA"], "tls-pki-internal.example.com")
	if err != nil {
		t.Fatalf("newPKICert: %v", err)
	}

	// Backends without TLS.
	be1 := newTCPServer(t, ctx, "backend1", nil)
	be2 := newTCPServer(t, ctx, "backend2", nil)
	// Backends with TLS enabled.
	be3 := newTCPServer(t, ctx, "backend3", intCA)
	be4 := newTCPServer(t, ctx, "backend4", caWithClientAuth{intCA, extCA})
	// Backends with special proto.
	be5 := newTCPServer(t, ctx, "backend5", intCA)
	be6 := newTCPServer(t, ctx, "backend6", intCA)
	// Backend for TLS passthrough
	be7 := newTCPServer(t, ctx, "backend7", extCA)
	// Backends for HTTP and HTTPS.
	be8 := newHTTPServer(t, ctx, "backend8", nil)
	be9 := newHTTPServer(t, ctx, "backend9", intCA)
	// Backend with PKI cert.
	be10 := newTCPServer(t, ctx, "backend10", pkiCert)
	// Backends with HTTP/HTTPS and proxy protocol
	be11 := newHTTPServerProxyProtocol(t, ctx, "backend11", nil)
	be12 := newHTTPServerProxyProtocol(t, ctx, "backend12", intCA)
	// Backend with TCP and proxy protocol
	be13 := newProxyProtocolServer(t, ctx, "backend12", nil)

	trueValue := true
	h2Value := "h2"

	cfg := &Config{
		MaxOpen: 100,
		PKI: []*ConfigPKI{
			{Name: "TEST CA"},
		},
		DefaultServerName: "http.example.com",
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
					"øäåé©©.example.com",
				},
				Addresses: []string{
					be3.listener.Addr().String(),
				},
				Mode:              "TLS",
				ForwardRootCAs:    []string{intCA.RootCAPEM()},
				ForwardServerName: "øäåé©©-internal.example.com",
			},
			// TLS backends, require clients to present a certificate.
			{
				ServerNames: []string{
					"secure.example.com",
				},
				Addresses: []string{
					be4.listener.Addr().String(),
				},
				Mode:              "TLS",
				ForwardRootCAs:    []string{intCA.RootCAPEM()},
				ForwardServerName: "secure-internal.example.com",
				ClientAuth: &ClientAuth{
					RootCAs: []string{intCA.RootCAPEM()},
				},
			},
			// TLS backend with imap proto.
			{
				ServerNames: []string{
					"secure.example.com",
				},
				Addresses: []string{
					be5.listener.Addr().String(),
				},
				Mode:              "TLS",
				ForwardRootCAs:    []string{intCA.RootCAPEM()},
				ForwardServerName: "imap-internal.example.com",
				ALPNProtos:        &[]string{"imap"},
			},
			// TLS backend without ALPN.
			{
				ServerNames: []string{
					"noproto.example.com",
				},
				Addresses: []string{
					be6.listener.Addr().String(),
				},
				Mode:              "TLS",
				ForwardRootCAs:    []string{intCA.RootCAPEM()},
				ForwardServerName: "noproto-internal.example.com",
				ALPNProtos:        &[]string{},
			},
			// TLS passthrough
			{
				ServerNames: []string{
					"passthrough.example.com",
				},
				Addresses: []string{
					be7.listener.Addr().String(),
				},
				Mode: "TLSPASSTHROUGH",
			},
			// HTTP
			{
				ServerNames: []string{
					"http.example.com",
				},
				Addresses: []string{
					be8.String(),
				},
				Mode: "HTTP",
				ForwardHTTPHeaders: map[string]string{
					"x-test": "foo",
				},
				PathOverrides: []*PathOverride{
					{
						Paths: []string{
							"/foo/",
						},
						Addresses: []string{
							be9.String(),
						},
						Mode:              "HTTPS",
						ForwardRootCAs:    []string{intCA.RootCAPEM()},
						ForwardServerName: "https-internal.example.com",
						ForwardHTTPHeaders: &map[string]string{
							"x-test": "bar",
						},
					},
					{
						Paths: []string{
							"/bar/",
						},
						Addresses: []string{
							be9.String(),
						},
						Mode:              "HTTPS",
						ForwardRootCAs:    []string{intCA.RootCAPEM()},
						ForwardServerName: "https-internal.example.com",
						SanitizePath:      &trueValue,
					},
				},
				SanitizePath: new(bool), // false
			},
			// HTTP H2C
			{
				ServerNames: []string{
					"h2c.example.com",
				},
				Addresses: []string{
					be8.String(),
				},
				Mode:         "HTTP",
				BackendProto: &h2Value,
			},
			// HTTPS
			{
				ServerNames: []string{
					"https.example.com",
				},
				Addresses: []string{
					be9.String(),
				},
				Mode:              "HTTPS",
				ForwardRootCAs:    []string{intCA.RootCAPEM()},
				ForwardServerName: "https-internal.example.com",
				ClientAuth: &ClientAuth{
					RootCAs:             []string{intCA.RootCAPEM()},
					AddClientCertHeader: []string{"cert", "dns", "subject", "hash"},
				},
			},
			// TLS backend w/ PKI
			{
				ServerNames: []string{
					"tls-pki.example.com",
				},
				Addresses: []string{
					be10.listener.Addr().String(),
				},
				Mode:              "TLS",
				ForwardRootCAs:    []string{"TEST CA"},
				ForwardServerName: "tls-pki-internal.example.com",
				ClientAuth: &ClientAuth{
					RootCAs: []string{intCA.RootCAPEM()},
				},
			},
			// HTTP + PROXY Protocol
			{
				ServerNames: []string{
					"http-proxy.example.com",
				},
				Addresses: []string{
					be11.String(),
				},
				Mode:                 "HTTP",
				ProxyProtocolVersion: "v1",
			},
			// HTTPS + PROXY Protocol
			{
				ServerNames: []string{
					"https-proxy.example.com",
				},
				Addresses: []string{
					be12.String(),
				},
				Mode:                 "HTTPS",
				ProxyProtocolVersion: "v2",
				ForwardRootCAs:       []string{intCA.RootCAPEM()},
				ForwardServerName:    "https-proxy-internal.example.com",
			},
			// TCP + PROXY Protocol
			{
				ServerNames: []string{
					"tcp-proxy.example.com",
				},
				Addresses: []string{
					be13.listener.Addr().String(),
				},
				Mode:                 "TCP",
				ProxyProtocolVersion: "v2",
			},
			// HTTPS loop
			{
				ServerNames: []string{
					"loop.example.com",
				},
				Addresses: []string{
					proxy.listener.Addr().String(),
				},
				Mode:              "HTTPS",
				ForwardRootCAs:    []string{extCA.RootCAPEM()},
				ForwardServerName: "loop.example.com",
			},
		},
	}
	if err := proxy.Reconfigure(cfg); err != nil {
		t.Fatalf("proxy.Reconfigure: %v", err)
	}

	if _, err := proxyProtoGet("example.com", proxy.listener.Addr().String(), "Hello!\n", extCA); err == nil {
		t.Errorf("proxyProtoGet should have failed")
	}

	get := func(host, certName string, protos []string, httpPath string) (string, string, error) {
		var certs []tls.Certificate
		if certName != "" {
			c, err := intCA.GetCert(certName)
			if err != nil {
				t.Fatalf("intCA.GetCert: %v", err)
			}
			certs = append(certs, *c)
		}
		var body string
		var localAddr string
		var err error
		if httpPath != "" {
			body, localAddr, err = httpGet(host, proxy.listener.Addr().String(), httpPath, extCA, certs)
		} else {
			body, localAddr, err = tlsGet(host, proxy.listener.Addr().String(), "Hello!\n", extCA, certs, protos)
		}
		return body, localAddr, err
	}

	for _, tc := range []struct {
		desc, host, want string
		certName         string
		protos           []string
		http             string
		expError         bool
	}{
		{desc: "Hit backend1", host: "example.com", want: "Hello from backend1\n"},
		{desc: "Hit backend2", host: "example.com", want: "Hello from backend2\n"},
		{desc: "Hit backend1 http2", host: "example.com", want: "Hello from backend1\n", protos: []string{"h2", "http/1.1"}},
		{desc: "Hit backend2 http/1.1", host: "example.com", want: "Hello from backend2\n", protos: []string{"http/1.1"}},
		{desc: "Hit backend1 again", host: "www.example.com", want: "Hello from backend1\n"},
		{desc: "Hit backend2 again", host: "www.example.com", want: "Hello from backend2\n"},
		{desc: "Hit backend3", host: "øäåé©©.example.com", want: "Hello from backend3\n"},
		{desc: "Hit backend3 http2", host: "øäåé©©.example.com", want: "Hello from backend3\n", protos: []string{"h2"}},
		{desc: "Hit backend4", host: "secure.example.com", want: "Hello from backend4\n", certName: "client.example.com"},
		{desc: "Hit backend4 no cert", host: "secure.example.com", expError: true},
		{desc: "Hit backend4 bad proto", host: "secure.example.com", certName: "client.example.com", protos: []string{"ftp"}, expError: true},
		{desc: "Hit backend5 proto:imap", host: "secure.example.com", want: "Hello from backend5\n", protos: []string{"imap"}},
		{desc: "Hit backend5 proto:h2", host: "secure.example.com", protos: []string{"ftp"}, expError: true},
		{desc: "Hit backend6", host: "noproto.example.com", want: "Hello from backend6\n"},
		{desc: "Hit backend6 random proto", host: "noproto.example.com", want: "Hello from backend6\n", protos: []string{"foo", "bar"}},
		{desc: "Unknown server name", host: "foo.example.com", expError: true},
		{desc: "Hit backend7", host: "passthrough.example.com", want: "Hello from backend7\n"},
		{desc: "Hit backend8", host: "http.example.com", want: "[backend8] /", http: "/"},
		{desc: "Hit backend8 /abc/.../xyz/", host: "http.example.com", want: "[backend8] /abc/.../xyz/", http: "/abc/.../xyz/"},
		{desc: "Hit backend8 /foo", host: "http.example.com", want: "[backend9] /foo/", http: "/foo"},
		{desc: "Hit backend8 /foo//", host: "http.example.com", want: "[backend9] /foo//", http: "/foo//"},
		{desc: "Hit backend8 /bar//", host: "http.example.com", want: "[backend9] /bar/", http: "/bar//"},
		{desc: "Hit backend8 header", host: "http.example.com", want: "[backend8] /?header=x-test\nx-test=foo\n", http: "/?header=x-test"},
		{desc: "Hit backend8 header /foo", host: "http.example.com", want: "[backend9] /foo/?header=x-test\nx-test=bar\n", http: "/foo/?header=x-test"},
		{desc: "Hit backend8 header /bar", host: "http.example.com", want: "[backend9] /bar/?header=x-test\nx-test=foo\n", http: "/bar/?header=x-test"},
		{desc: "Hit backend8 h2c", host: "h2c.example.com", want: "[backend8] /", http: "/"},
		{desc: "Hit backend9", host: "https.example.com", want: "[backend9] /", http: "/", certName: "client.example.com"},
		{desc: "Hit backend9 /abc/../xyz/", host: "https.example.com", want: "[backend9] /xyz/", http: "/abc/../xyz/", certName: "client.example.com"},
		{desc: "Hit backend10", host: "tls-pki.example.com", want: "Hello from backend10\n", certName: "client.example.com"},
		{desc: "Hit backend11", host: "http-proxy.example.com", want: "[backend11] LOCALADDR /", http: "/"},
		{desc: "Hit backend12", host: "https-proxy.example.com", want: "[backend12] LOCALADDR /", http: "/"},
		{desc: "Hit backend13", host: "tcp-proxy.example.com", want: "Hello LOCALADDR from backend12\n"},
		{desc: "Hit loop", host: "loop.example.com", want: "508 Loop Detected", http: "/"},
		{desc: "Hit default backend with IP address as host", host: "", want: "421 Misdirected Request", http: "/"},
	} {
		got, localAddr, err := get(tc.host, tc.certName, tc.protos, tc.http)
		if tc.expError != (err != nil) {
			t.Fatalf("%s: Got error %v, want %v. Body: %q err: %v", tc.desc, (err != nil), tc.expError, got, err)
			continue
		}
		if err != nil {
			continue
		}
		want := strings.Replace(tc.want, "LOCALADDR", localAddr, 1)
		if tc.http != "" {
			if !strings.Contains(got, want) {
				t.Errorf("%s: Got %q, want %q", tc.desc, got, want)
			}
		} else if got != want {
			t.Errorf("%s: Got %q, want %q", tc.desc, got, want)
		}
	}

	pc, err := x509.ParseCertificate(pkiCert.cert.Certificate[0])
	if err != nil {
		t.Fatalf("x509.ParseCertificate: %v", err)
	}
	if err := proxy.pkis["TEST CA"].RevokeCertificate(pc.SerialNumber, 0); err != nil {
		t.Fatalf("RevokeCertificate: %v", err)
	}
	if got, _, err := get("tls-pki.example.com", "client.example.com", nil, ""); got != "" {
		t.Errorf("get with revoked cert should return nothing: %q, %v", got, err)
	}
}

func TestAuthnAuthz(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	extCA, err := certmanager.New("root-ca.example.com", t.Logf)
	if err != nil {
		t.Fatalf("certmanager.New: %v", err)
	}
	intCA, err := certmanager.New("internal-ca.example.com", t.Logf)
	if err != nil {
		t.Fatalf("certmanager.New: %v", err)
	}
	cfg := &Config{
		HTTPAddr: "localhost:0",
		TLSAddr:  "localhost:0",
		CacheDir: t.TempDir(),
		MaxOpen:  100,
		PKI: []*ConfigPKI{
			{Name: "TEST CA"},
		},
		Backends: []*Backend{
			{
				ServerNames: []string{
					"noacl.example.com",
				},
				Mode: "CONSOLE",
				ClientAuth: &ClientAuth{
					RootCAs: []string{intCA.RootCAPEM()},
				},
			},
			{
				ServerNames: []string{
					"emptyacl.example.com",
				},
				Mode: "CONSOLE",
				ClientAuth: &ClientAuth{
					RootCAs: []string{intCA.RootCAPEM()},
					ACL:     &[]string{},
				},
			},
			{
				ServerNames: []string{
					"acl.example.com",
				},
				Mode: "CONSOLE",
				ClientAuth: &ClientAuth{
					RootCAs: []string{intCA.RootCAPEM()},
					ACL: &[]string{
						"CN=client1",
						"DNS:client2",
					},
				},
			},
			{
				ServerNames: []string{
					"pkitest.example.com",
				},
				Mode: "CONSOLE",
				ClientAuth: &ClientAuth{
					RootCAs: []string{"TEST CA"},
					ACL: &[]string{
						"EMAIL:bob@example.com",
					},
				},
			},
		},
	}
	proxy := newTestProxy(cfg, extCA)
	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}
	if got, want := len(proxy.pkis), 1; got != want {
		t.Fatalf("len(pkis) = %d, want %d", got, want)
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	rawCert, err := proxy.pkis["TEST CA"].IssueCertificate(&x509.CertificateRequest{
		PublicKey:      &privKey.PublicKey,
		EmailAddresses: []string{"bob@example.com"},
	})
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	pkiCert, err := x509.ParseCertificate(rawCert)
	if err != nil {
		t.Fatalf("x509.ParseCertificate: %v", err)
	}
	pkiTLSCert := tls.Certificate{
		Certificate: [][]byte{rawCert},
		PrivateKey:  privKey,
	}

	get := func(host, certName string) (string, error) {
		var certs []tls.Certificate
		if certName == "pki" {
			certs = append(certs, pkiTLSCert)
		} else if certName != "" {
			c, err := intCA.GetCert(certName)
			if err != nil {
				t.Fatalf("intCA.GetCert: %v", err)
			}
			certs = append(certs, *c)
		}
		body, _, err := httpGet(host, proxy.listener.Addr().String(), "/", extCA, certs)
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
		{desc: "no ACL, no cert", host: "noacl.example.com", expError: true},
		{desc: "no ACL, with cert", host: "noacl.example.com", certName: "foo", want: "HTTP/2.0 200 OK"},
		{desc: "empty ACL, with cert", host: "emptyacl.example.com", certName: "foo", expError: true},
		{desc: "ACL, no cert", host: "acl.example.com", expError: true},
		{desc: "ACL, client1", host: "acl.example.com", certName: "client1", want: "HTTP/2.0 200 OK"},
		{desc: "ACL, client2", host: "acl.example.com", certName: "client2", want: "HTTP/2.0 200 OK"},
		{desc: "ACL, wrong cert", host: "acl.example.com", certName: "foo", expError: true},
		{desc: "PKI client", host: "pkitest.example.com", certName: "pki", want: "HTTP/2.0 200 OK"},
		{desc: "Check console1", host: "acl.example.com", certName: "client1", want: "allow X509 [SUBJECT:CN=client1;DNS:client1] to acl.example.com"},
		{desc: "Check console2", host: "acl.example.com", certName: "client1", want: "allow X509 [SUBJECT:CN=client2;DNS:client2] to acl.example.com"},
		{desc: "Check console3", host: "acl.example.com", certName: "client1", want: "allow X509 [SUBJECT:CN=foo;DNS:foo] to noacl.example.com"},
		{desc: "Check console4", host: "acl.example.com", certName: "client1", want: "deny X509 [SUBJECT:CN=foo;DNS:foo] to acl.example.com"},
		{desc: "Check console5", host: "acl.example.com", certName: "client1", want: "deny X509 [SUBJECT:CN=foo;DNS:foo] to emptyacl.example.com"},
		{desc: "Check console6", host: "acl.example.com", certName: "client1", want: "allow X509 [EMAIL:bob@example.com] to pkitest.example.com"},
	} {
		got, err := get(tc.host, tc.certName)
		if tc.expError != (err != nil) {
			t.Errorf("%s: Got error %v, want %v", tc.desc, (err != nil), tc.expError)
			t.Logf("Body: %q err: %v", got, err)
			continue
		}
		if err != nil {
			continue
		}
		if !strings.Contains(got, tc.want) {
			t.Errorf("%s: Got %q, want %q", tc.desc, got, tc.want)
		}
	}

	if err := proxy.pkis["TEST CA"].RevokeCertificate(pkiCert.SerialNumber, 0); err != nil {
		t.Fatalf("RevokeCertificate: %v", err)
	}
	if _, err := get("pkitest.example.com", "pki"); err == nil {
		t.Error("get with revoked cert should have failed")
	}
}

func TestConcurrency(t *testing.T) {
	openFileLimit()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ca, err := certmanager.New("root-ca.example.com", t.Logf)
	if err != nil {
		t.Fatalf("certmanager.New: %v", err)
	}
	be1 := newHTTPServer(t, ctx, "http-server", nil)
	be2 := newHTTPServer(t, ctx, "https-server", ca)
	be3 := newHTTPServer(t, ctx, "tcp-server", nil)
	be4 := newHTTPServer(t, ctx, "tls-server", ca)
	be5 := newHTTPServer(t, ctx, "passthru.example.com", ca)

	proxy := newTestProxy(
		&Config{
			HTTPAddr: "localhost:0",
			TLSAddr:  "localhost:0",
			CacheDir: t.TempDir(),
			MaxOpen:  5000,
			Backends: []*Backend{
				{
					ServerNames: []string{
						"http.example.com",
					},
					Mode: "HTTP",
					Addresses: []string{
						be1.String(),
					},
					ForwardRateLimit: 1000,
				},
				{
					ServerNames: []string{
						"https.example.com",
					},
					Mode: "HTTPS",
					Addresses: []string{
						be2.String(),
					},
					ForwardRateLimit:  1000,
					ForwardRootCAs:    []string{ca.RootCAPEM()},
					ForwardServerName: "https-server",
				},
				{
					ServerNames: []string{
						"tcp.example.com",
					},
					Mode:       "TCP",
					ALPNProtos: &[]string{},
					Addresses: []string{
						be3.String(),
					},
					ForwardRateLimit: 1000,
				},
				{
					ServerNames: []string{
						"tls.example.com",
					},
					Mode:       "TLS",
					ALPNProtos: &[]string{},
					Addresses: []string{
						be4.String(),
					},
					ForwardRateLimit:  1000,
					ForwardRootCAs:    []string{ca.RootCAPEM()},
					ForwardServerName: "tls-server",
				},
				{
					ServerNames: []string{
						"passthru.example.com",
					},
					Mode: "TLSPASSTHROUGH",
					Addresses: []string{
						be5.String(),
					},
					ForwardRateLimit: 1000,
				},
			},
		},
		ca,
	)
	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}

	hosts := []string{
		"http.example.com",
		"https.example.com",
		"tcp.example.com",
		"tls.example.com",
		"passthru.example.com",
	}
	failCh := make(chan bool)
	client := func(id int, wg *sync.WaitGroup) {
		defer wg.Done()
		host := hosts[id%len(hosts)]
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{
			RootCAs:    ca.RootCACertPool(),
			ServerName: host,
		}
		client := http.Client{
			Transport: transport,
		}
		for n := 0; n < 50; n++ {
			req := &http.Request{
				Method: "GET",
				URL: &url.URL{
					Scheme: "https",
					Host:   proxy.listener.Addr().String(),
					Path:   "/",
				},
				Host: host,
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Errorf("[%d] get failed: %v", id, err)
				failCh <- true
				return
			}
			if _, err := io.ReadAll(resp.Body); err != nil {
				t.Errorf("[%d] body read: %v", id, err)
			}
			if err := resp.Body.Close(); err != nil {
				t.Errorf("[%d] body close: %v", id, err)
			}
			if resp.StatusCode != 200 {
				t.Errorf("[%d] Status: %s", id, resp.Status)
				failCh <- true
				return
			}
		}
	}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go client(i, &wg)
	}
	go func() {
		wg.Wait()
		close(failCh)
	}()
	if _, ok := <-failCh; ok {
		t.FailNow()
	}
}

func TestBackendHTTPHeaders(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	extCA, err := certmanager.New("root-ca.example.com", t.Logf)
	if err != nil {
		t.Fatalf("certmanager.New: %v", err)
	}

	be := newHTTPServer(t, ctx, "backend", nil)

	proxy := newTestProxy(
		&Config{
			HTTPAddr: "localhost:0",
			TLSAddr:  "localhost:0",
			CacheDir: t.TempDir(),
			MaxOpen:  100,
			Backends: []*Backend{
				// HTTP
				{
					ServerNames: []string{
						"www.example.com",
					},
					Addresses: []string{
						be.String(),
					},
					Mode: "HTTP",
					ForwardHTTPHeaders: map[string]string{
						"x-test": "FOO ${REMOTE_ADDR} ${SERVER_NAME} ${NETWORK} // ${JWT:email}",
					},
				},
			},
		},
		extCA,
	)
	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}

	get := func(httpPath string) (string, string, error) {
		return httpGet("www.example.com", proxy.listener.Addr().String(), httpPath, extCA, nil)
	}

	got, localAddr, err := get("/?header=x-test")
	if err != nil {
		t.Fatalf("Got err: %v, body: %q", err, got)
	}
	want := "HTTP/2.0 200 OK\n[backend] /?header=x-test\nx-test=FOO " + localAddr + " www.example.com tcp //\n"
	if got != want {
		t.Errorf("Body = %q, want %q", got, want)
	}
}

func TestBandwidthLimit(t *testing.T) {
	t.Skip()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ca, err := certmanager.New("root-ca.example.com", t.Logf)
	if err != nil {
		t.Fatalf("certmanager.New: %v", err)
	}
	be := newHTTPServer(t, ctx, "server", nil)

	proxy := newTestProxy(
		&Config{
			HTTPAddr: "localhost:0",
			TLSAddr:  "localhost:0",
			CacheDir: t.TempDir(),
			MaxOpen:  2000,
			BWLimits: []*BWLimit{
				{
					Name:    "slowingress",
					Ingress: 100000,
					Egress:  10000000,
				},
				{
					Name:    "slowegress",
					Ingress: 10000000,
					Egress:  100000,
				},
			},
			Backends: []*Backend{
				{
					ServerNames: []string{
						"slowingress.example.com",
					},
					Mode: "HTTP",
					Addresses: []string{
						be.String(),
					},
					BWLimit:          "slowingress",
					ForwardRateLimit: 1000,
				},
				{
					ServerNames: []string{
						"slowegress.example.com",
					},
					Mode: "HTTP",
					Addresses: []string{
						be.String(),
					},
					BWLimit:          "slowegress",
					ForwardRateLimit: 1000,
				},
			},
		},
		ca,
	)
	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}

	get := func(host string) time.Duration {
		start := time.Now()
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{
			RootCAs:    ca.RootCACertPool(),
			ServerName: host,
		}
		client := http.Client{
			Transport: transport,
		}
		req := &http.Request{
			Method: "POST",
			URL: &url.URL{
				Scheme: "https",
				Host:   proxy.listener.Addr().String(),
				Path:   "/",
			},
			Body: io.NopCloser(bytes.NewReader(make([]byte, 300000))),
			Host: host,
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Errorf("[%s] get failed: %v", host, err)
			return 0
		}
		if _, err := io.ReadAll(resp.Body); err != nil {
			t.Errorf("[%s] body read: %v", host, err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Errorf("[%s] body close: %v", host, err)
		}
		if resp.StatusCode != 200 {
			t.Errorf("[%s] Status: %s", host, resp.Status)
			return 0
		}
		return time.Since(start)
	}
	if d := get("slowingress.example.com"); d < time.Second {
		t.Errorf("[ingress] d = %s < 1s", d)
	}
	if d := get("slowegress.example.com"); d > time.Second {
		t.Errorf("[egress] d = %s > 1s", d)
	}
}

func TestIncomingProxyProto(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	extCA, err := certmanager.New("root-ca.example.com", t.Logf)
	if err != nil {
		t.Fatalf("certmanager.New: %v", err)
	}
	be1 := newProxyProtocolServer(t, ctx, "backend1", nil)

	proxy := newTestProxy(
		&Config{
			HTTPAddr: "localhost:0",
			TLSAddr:  "localhost:0",
			CacheDir: t.TempDir(),
			MaxOpen:  100,
			AcceptProxyHeaderFrom: []string{
				"127.0.0.1/32",
				"::1/128",
			},
			Backends: []*Backend{
				{
					ServerNames: []string{
						"example.com",
					},
					Addresses: []string{
						be1.listener.Addr().String(),
					},
					ProxyProtocolVersion: "v2",
				},
			},
		},
		extCA,
	)
	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}

	got, err := proxyProtoGet("example.com", proxy.listener.Addr().String(), "Hello\n", extCA)
	if err != nil {
		t.Fatalf("proxyProtoGet() returned %v", err)
	}
	if want := "Hello 1.2.3.4:12345 from backend1\n"; got != want {
		t.Errorf("Body = %q, want %q", got, want)
	}
}

func TestProxyProtoIsolation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	extCA, err := certmanager.New("root-ca.example.com", t.Logf)
	if err != nil {
		t.Fatalf("certmanager.New: %v", err)
	}

	be1 := newHTTPServerProxyProtocol(t, ctx, "backend1", nil)

	proxy := newTestProxy(
		&Config{
			HTTPAddr: "localhost:0",
			TLSAddr:  "localhost:0",
			CacheDir: t.TempDir(),
			MaxOpen:  100,
			Backends: []*Backend{
				{
					ServerNames: []string{
						"www.example.com",
					},
					Addresses: []string{
						be1.String(),
					},
					Mode:                 "HTTP",
					ProxyProtocolVersion: "v1",
				},
			},
		},
		extCA,
	)
	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}

	for i := 0; i < 5; i++ {
		p := fmt.Sprintf("/%d", i)
		got, localAddr, err := httpGet("www.example.com", proxy.listener.Addr().String(), p, extCA, nil)
		if err != nil {
			t.Errorf("%s: %v", p, err)
		}
		if want := fmt.Sprintf("[backend1] %s %s", localAddr, p); !strings.Contains(got, want) {
			t.Errorf("%s: Got %q, want %q", p, got, want)
		}
	}
}

func TestProxyTPM(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	extCA, err := certmanager.New("root-ca.example.com", t.Logf)
	if err != nil {
		t.Fatalf("certmanager.New: %v", err)
	}

	be1 := newHTTPServer(t, ctx, "backend1", nil)
	dir := t.TempDir()
	cfg := &Config{
		HTTPAddr: "localhost:0",
		TLSAddr:  "localhost:0",
		CacheDir: dir,
		HWBacked: true,
		MaxOpen:  100,
		Backends: []*Backend{
			{
				ServerNames: []string{
					"www.example.com",
				},
				Addresses: []string{
					be1.String(),
				},
				Mode: "HTTP",
			},
		},
	}
	proxy := newTestProxy(cfg, extCA)
	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}
	if _, _, err := httpGet("www.example.com", proxy.listener.Addr().String(), "/", extCA, nil); err != nil {
		t.Fatalf("httpGet: %v", err)
	}

	mkFile := filepath.Join(dir, "mk")
	if err := proxy.mk.Save([]byte("foo"), mkFile); err != nil {
		t.Fatalf("mk.Save: %v", err)
	}
	if _, err := crypto.ReadMasterKey([]byte("foo"), mkFile); err == nil {
		t.Fatal("crypto.ReadMasterKey without TPM should fail")
	}
}

func TestCheckIP(t *testing.T) {
	cfg := &Config{
		HTTPAddr: "localhost:0",
		TLSAddr:  "localhost:0",
		CacheDir: t.TempDir(),
		MaxOpen:  100,
		Backends: []*Backend{
			{
				ServerNames: []string{"example.com"},
				Addresses:   []string{"192.168.0.1:80"},
				AllowIPs: &[]string{
					"192.168.10.0/24",
				},
				DenyIPs: &[]string{
					"192.168.10.1/32",
				},
			},
			{
				ServerNames: []string{"www.example.com"},
				Addresses:   []string{"192.168.0.2:80"},
				AllowIPs: &[]string{
					"192.168.20.0/24",
				},
			},
			{
				ServerNames: []string{"foo.example.com"},
				Addresses:   []string{"192.168.0.3:80"},
				DenyIPs: &[]string{
					"192.168.30.0/24",
				},
			},
		},
	}
	if err := cfg.Check(); err != nil {
		t.Fatalf("cfg.Check: %v", err)
	}
	for _, tc := range []struct {
		desc  string
		addr  net.Addr
		allow bool
		be    *Backend
	}{
		{
			desc:  "BE0 Deny 127.0.0.1",
			addr:  &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)},
			allow: false,
			be:    cfg.Backends[0],
		},
		{
			desc:  "BE0 Deny 192.168.10.1",
			addr:  &net.TCPAddr{IP: net.IPv4(192, 168, 10, 1)},
			allow: false,
			be:    cfg.Backends[0],
		},
		{
			desc:  "BE0 Allow 192.168.10.2",
			addr:  &net.TCPAddr{IP: net.IPv4(192, 168, 10, 2)},
			allow: true,
			be:    cfg.Backends[0],
		},
		{
			desc:  "BE1 Allow 192.168.20.111",
			addr:  &net.TCPAddr{IP: net.IPv4(192, 168, 20, 111)},
			allow: true,
			be:    cfg.Backends[1],
		},
		{
			desc:  "BE1 Deny 5.5.5.5",
			addr:  &net.TCPAddr{IP: net.IPv4(5, 5, 5, 5)},
			allow: false,
			be:    cfg.Backends[1],
		},
		{
			desc:  "BE2 Deny 192.168.30.111",
			addr:  &net.TCPAddr{IP: net.IPv4(192, 168, 30, 111)},
			allow: false,
			be:    cfg.Backends[2],
		},
		{
			desc:  "BE2 Allow 40.40.40.40",
			addr:  &net.TCPAddr{IP: net.IPv4(40, 40, 40, 40)},
			allow: true,
			be:    cfg.Backends[2],
		},
	} {
		if got := tc.be.checkIP(tc.addr); (got == nil) != tc.allow {
			t.Errorf("%s: Got %v, want error %v", tc.desc, got, tc.allow)
		}
	}
}

func newTestProxy(cfg *Config, cm *certmanager.CertManager) *Proxy {
	mkOpts := []crypto.Option{
		crypto.WithLogger(logger{}),
		crypto.WithStrictWipe(false),
	}
	var tpmSim *tpm.TPM
	if cfg.HWBacked {
		rwc, err := simulator.Get()
		if err != nil {
			panic(err)
		}
		tpm, err := tpm.New(tpm.WithTPM(rwc))
		if err != nil {
			panic(err)
		}
		tpmSim = tpm
		mkOpts = append(mkOpts, crypto.WithTPM(tpmSim))
	}
	mk, err := crypto.CreateMasterKey(mkOpts...)
	if err != nil {
		panic(err)
	}
	store := storage.New(filepath.Join(cfg.CacheDir, "test"), mk)
	tm, err := tokenmanager.New(store, tpmSim)
	if err != nil {
		panic(err)
	}
	p := &Proxy{
		certManager:  cm,
		mk:           mk,
		tpm:          tpmSim,
		store:        store,
		tokenManager: tm,
		ocspCache:    ocspcache.New(store),
		bwLimits:     make(map[string]*bwLimit),
		inConns:      newConnTracker(),
		outConns:     newConnTracker(),
	}
	p.Reconfigure(cfg)
	return p
}

func tlsGet(name, addr, msg string, rootCA *certmanager.CertManager, clientCerts []tls.Certificate, protos []string) (string, string, error) {
	name = idnaToASCII(name)
	c, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName:         name,
		InsecureSkipVerify: name == "",
		RootCAs:            rootCA.RootCACertPool(),
		Certificates:       clientCerts,
		NextProtos:         protos,
	})
	if err != nil {
		return "", "", err
	}
	localAddr := c.LocalAddr().String()
	defer c.Close()
	if _, err := c.Write([]byte(msg)); err != nil {
		return "", "", err
	}
	b, err := io.ReadAll(c)
	return string(b), localAddr, err
}

func proxyProtoGet(name, addr, msg string, rootCA *certmanager.CertManager) (string, error) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return "", err
	}
	header := proxyproto.HeaderProxyFromAddrs(2, &net.TCPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 12345}, &net.TCPAddr{IP: net.IPv4(5, 6, 7, 8), Port: 23456})
	header.Command = proxyproto.PROXY
	if _, err := header.WriteTo(c); err != nil {
		c.Close()
		return "", err
	}
	tlsConn := tls.Client(c, &tls.Config{
		ServerName:         idnaToASCII(name),
		InsecureSkipVerify: name == "",
		RootCAs:            rootCA.RootCACertPool(),
	})
	defer tlsConn.Close()
	if _, err := tlsConn.Write([]byte(msg)); err != nil {
		return "", err
	}
	b, err := io.ReadAll(tlsConn)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func httpGet(name, addr, path string, rootCA *certmanager.CertManager, clientCerts []tls.Certificate) (string, string, error) {
	return httpOp(name, addr, path, "GET", nil, rootCA, clientCerts)
}

func httpOp(name, addr, path, method string, body io.ReadCloser, rootCA *certmanager.CertManager, clientCerts []tls.Certificate) (string, string, error) {
	var localAddr string
	var mu sync.Mutex
	name = idnaToASCII(name)
	client := &http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
				c, err := tls.Dial("tcp", addr, &tls.Config{
					ServerName:         name,
					InsecureSkipVerify: name == "",
					RootCAs:            rootCA.RootCACertPool(),
					Certificates:       clientCerts,
					NextProtos:         []string{"h2", "http/1.1"},
				})
				if err != nil {
					return nil, err
				}
				mu.Lock()
				localAddr = c.LocalAddr().String()
				mu.Unlock()
				return c, nil
			},
			ForceAttemptHTTP2: true,
		},
		Timeout: 5 * time.Second,
	}
	host := name
	if host == "" {
		host = addr
	}
	req, err := http.NewRequest(method, "https://"+host+path, body)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Host", host)
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}
	mu.Lock()
	defer mu.Unlock()
	return resp.Proto + " " + resp.Status + "\n" + string(b), localAddr, nil
}

func newHTTPServer(t *testing.T, ctx context.Context, name string, ca *certmanager.CertManager) net.Addr {
	var l net.Listener
	var err error
	if ca == nil {
		l, err = net.Listen("tcp", "localhost:0")
	} else {
		tlsCfg := ca.TLSConfig()
		tlsCfg.NextProtos = []string{"h2", "http/1.1"}
		l, err = tls.Listen("tcp", "localhost:0", tlsCfg)
	}
	if err != nil {
		t.Fatalf("[%s] Listen: %v", name, err)
	}
	s := &http.Server{
		Handler: h2c.NewHandler(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Body != nil {
					defer r.Body.Close()
				}
				t.Logf("[%s] ContentLength=%d", name, r.ContentLength)
				if v := r.Header.Get(xFCCHeader); v != "" {
					t.Logf("[%s] %s: %s", name, xFCCHeader, v)
				}
				if v := r.Header.Get("Content-Length"); v != "" {
					if l, err := strconv.Atoi(v); err != nil || l < 0 {
						t.Errorf("[%s] Content-Length: %q", name, v)
					}
				}
				switch r.Method {
				case "GET":
					fmt.Fprintf(w, "[%s] %s\n", name, r.RequestURI)
				case "POST":
					b, _ := io.ReadAll(r.Body)
					fmt.Fprintf(w, "[%s] POST %s %s\n", name, r.RequestURI, b)
				default:
					fmt.Fprintf(w, "[%s] %s %s\n", name, r.Method, r.RequestURI)
				}
				r.ParseForm()
				if h := r.Form.Get("header"); h != "" {
					fmt.Fprintf(w, "%s=%s\n", h, r.Header.Get(h))
				}
			}), &http2.Server{}),
		ErrorLog: log.New(os.Stderr, "["+name+"] ", 0),
	}
	go s.Serve(l)
	go func() {
		<-ctx.Done()
		s.Close()
	}()
	return l.Addr()
}

func newHTTPServerProxyProtocol(t *testing.T, ctx context.Context, name string, ca *certmanager.CertManager) net.Addr {
	netListener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("[%s] Listen: %v", name, err)
	}
	proxyListener := &proxyproto.Listener{
		Listener:          netListener,
		ReadHeaderTimeout: time.Second,
	}
	var l net.Listener = proxyListener
	if ca != nil {
		tlsCfg := ca.TLSConfig()
		tlsCfg.NextProtos = []string{"h2", "http/1.1"}
		l = tls.NewListener(l, tlsCfg)
	}
	s := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			switch conn := req.Context().Value(connCtxKey).(type) {
			case *proxyproto.Conn:
				f, _ := conn.ProxyHeader().Format()
				t.Logf("[%s] PROXY HEADER: %q", name, f)
			case *tls.Conn:
				f, _ := conn.NetConn().(*proxyproto.Conn).ProxyHeader().Format()
				t.Logf("[%s] TLS PROXY HEADER: %q", name, f)
			default:
				t.Fatalf("Unexpected conn type: %T", conn)
			}
			fmt.Fprintf(w, "[%s] %s %s\n", name, req.RemoteAddr, req.RequestURI)
		}),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connCtxKey, c)
		},
		ErrorLog: log.New(os.Stderr, "["+name+"] ", 0),
	}
	go s.Serve(l)
	go func() {
		<-ctx.Done()
		s.Close()
	}()
	return proxyListener.Addr()
}

type tcProvider interface {
	TLSConfig() *tls.Config
}

type caWithClientAuth struct {
	tcProvider
	rootCA interface {
		RootCACertPool() *x509.CertPool
	}
}

func (ca caWithClientAuth) TLSConfig() *tls.Config {
	tc := ca.tcProvider.TLSConfig()
	tc.ClientAuth = tls.RequireAndVerifyClientCert
	tc.ClientCAs = ca.rootCA.RootCACertPool()
	return tc
}

func newTCPServer(t *testing.T, ctx context.Context, name string, ca tcProvider) *tcpServer {
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
				t.Errorf("[%s] Accept: %v", name, err)
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

func newProxyProtocolServer(t *testing.T, ctx context.Context, name string, ca tcProvider) *tcpServer {
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
	l = &proxyproto.Listener{
		Listener:          l,
		ReadHeaderTimeout: time.Second,
	}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					break
				}
				t.Errorf("[%s] Accept: %v", name, err)
				continue
			}
			t.Logf("[%s] Received connection from %s", name, conn.RemoteAddr())
			f, _ := conn.(*proxyproto.Conn).ProxyHeader().Format()
			t.Logf("[%s] PROXY HEADER: %q", name, f)
			if got, want := isProxyProtoConn(conn), true; got != want {
				t.Errorf("isProxyProtoConn() = %v, want %v", got, want)
			}
			if got, want := localNetConn(conn), conn.(*proxyproto.Conn).Raw(); got != want {
				t.Errorf("localNetConn() = %v, want %v", got, want)
			}
			go func(c net.Conn) {
				fmt.Fprintf(c, "Hello %s from %s\n", c.RemoteAddr(), name)
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

type pkiCert struct {
	cert tls.Certificate
}

func newPKICert(m *pki.PKIManager, name string) (*pkiCert, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	rawCert, err := m.IssueCertificate(&x509.CertificateRequest{
		PublicKey: &privKey.PublicKey,
		DNSNames:  []string{name},
	})
	if err != nil {
		return nil, err
	}
	c := &pkiCert{
		cert: tls.Certificate{
			Certificate: [][]byte{rawCert},
			PrivateKey:  privKey,
		},
	}
	return c, nil
}

func (c *pkiCert) TLSConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{c.cert},
	}
}
