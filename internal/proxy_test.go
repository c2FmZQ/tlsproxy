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

package internal

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/c2FmZQ/tlsproxy/internal/certmanager"
	"github.com/c2FmZQ/tlsproxy/internal/netw"
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
	// Backends without TLS.
	be1 := newTCPServer(t, ctx, "backend1", nil)
	be2 := newTCPServer(t, ctx, "backend2", nil)
	// Backends with TLS enabled.
	be3 := newTCPServer(t, ctx, "backend3", intCA)
	be4 := newTCPServer(t, ctx, "backend4", intCA)
	// Backends with special proto.
	be5 := newTCPServer(t, ctx, "backend5", intCA)
	be6 := newTCPServer(t, ctx, "backend6", intCA)
	// Backend for TLS passthrough
	be7 := newTCPServer(t, ctx, "backend7", extCA)

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
				Mode:              "TLS",
				ForwardRootCAs:    intCA.RootCAPEM(),
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
				Mode:              "TLS",
				ForwardRootCAs:    intCA.RootCAPEM(),
				ForwardServerName: "secure-internal.example.com",
				ClientAuth:        true,
				ClientCAs:         intCA.RootCAPEM(),
			},
			// TLS backend with imap proto.
			{
				ServerNames: []string{
					"imap.example.com",
				},
				Addresses: []string{
					be5.listener.Addr().String(),
				},
				Mode:              "TLS",
				ForwardRootCAs:    intCA.RootCAPEM(),
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
				ForwardRootCAs:    intCA.RootCAPEM(),
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
		},
	}
	proxy := newTestProxy(cfg, extCA)
	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}
	get := func(host, certName string, protos []string) (string, error) {
		var certs []tls.Certificate
		if certName != "" {
			c, err := intCA.GetCert(certName)
			if err != nil {
				t.Fatalf("intCA.GetCert: %v", err)
			}
			certs = append(certs, *c)
		}
		body, err := tlsGet(host, proxy.listener.Addr().String(), extCA, certs, protos)
		if err != nil {
			return "", err
		}
		return body, nil
	}

	for _, tc := range []struct {
		desc, host, want string
		certName         string
		protos           []string
		expError         bool
	}{
		{desc: "Hit backend1", host: "example.com", want: "Hello from backend1\n"},
		{desc: "Hit backend2", host: "example.com", want: "Hello from backend2\n"},
		{desc: "Hit backend1 http2", host: "example.com", want: "Hello from backend1\n", protos: []string{"h2", "http/1.1"}},
		{desc: "Hit backend2 http/1.1", host: "example.com", want: "Hello from backend2\n", protos: []string{"http/1.1"}},
		{desc: "Hit backend1 again", host: "www.example.com", want: "Hello from backend1\n"},
		{desc: "Hit backend2 again", host: "www.example.com", want: "Hello from backend2\n"},
		{desc: "Hit backend3", host: "other.example.com", want: "Hello from backend3\n"},
		{desc: "Hit backend3 http2", host: "other.example.com", want: "Hello from backend3\n", protos: []string{"h2"}},
		{desc: "Hit backend4", host: "secure.example.com", want: "Hello from backend4\n", certName: "client.example.com"},
		{desc: "Hit backend4 no cert", host: "secure.example.com", expError: true},
		{desc: "Hit backend4 bad proto", host: "secure.example.com", certName: "client.example.com", protos: []string{"ftp"}, expError: true},
		{desc: "Hit backend5", host: "imap.example.com", want: "Hello from backend5\n"},
		{desc: "Hit backend5 proto:imap", host: "imap.example.com", want: "Hello from backend5\n", protos: []string{"imap"}},
		{desc: "Hit backend5 proto:h2", host: "imap.example.com", protos: []string{"h2"}, expError: true},
		{desc: "Hit backend6", host: "noproto.example.com", want: "Hello from backend6\n"},
		{desc: "Hit backend6 random proto", host: "noproto.example.com", want: "Hello from backend6\n", protos: []string{"foo", "bar"}},
		{desc: "Unknown server name", host: "foo.example.com", expError: true},
		{desc: "Hit backend7", host: "passthrough.example.com", want: "Hello from backend7\n"},
	} {
		got, err := get(tc.host, tc.certName, tc.protos)
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

func newTestProxy(cfg *Config, cm *certmanager.CertManager) *Proxy {
	p := &Proxy{
		certManager: cm,
		connections: make(map[connKey]*netw.Conn),
	}
	p.Reconfigure(cfg)
	return p
}

func tlsGet(name, addr string, rootCA *certmanager.CertManager, clientCerts []tls.Certificate, protos []string) (string, error) {
	c, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName:   name,
		RootCAs:      rootCA.RootCACertPool(),
		Certificates: clientCerts,
		NextProtos:   protos,
	})
	if err != nil {
		return "", err
	}
	defer c.Close()
	if _, err := c.Write([]byte("Hello\n")); err != nil {
		return "", err
	}
	b, err := io.ReadAll(c)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func newTCPServer(t *testing.T, ctx context.Context, name string, ca *certmanager.CertManager) *tcpServer {
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
