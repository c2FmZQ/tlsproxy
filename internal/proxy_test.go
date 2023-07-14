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
	"strings"
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
		body, err := tlsGet(host, proxy.listener.Addr().String(), "Hello!\n", extCA, certs, protos)
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
		Backends: []*Backend{
			{
				ServerNames: []string{
					"noacl.example.com",
				},
				Mode:       "CONSOLE",
				ClientAuth: true,
				ClientCAs:  intCA.RootCAPEM(),
			},
			{
				ServerNames: []string{
					"emptyacl.example.com",
				},
				Mode:       "CONSOLE",
				ClientAuth: true,
				ClientCAs:  intCA.RootCAPEM(),
				ClientACL:  &[]string{},
			},
			{
				ServerNames: []string{
					"acl.example.com",
				},
				Mode:       "CONSOLE",
				ClientAuth: true,
				ClientCAs:  intCA.RootCAPEM(),
				ClientACL: &[]string{
					"CN=client1",
					"CN=client2",
				},
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
			c, err := intCA.GetCert(certName)
			if err != nil {
				t.Fatalf("intCA.GetCert: %v", err)
			}
			certs = append(certs, *c)
		}
		body, err := httpGet(host, proxy.listener.Addr().String(), extCA, certs)
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
		{desc: "no ACL, with cert", host: "noacl.example.com", certName: "foo", want: "HTTP/1.0 200 OK"},
		{desc: "empty ACL, with cert", host: "emptyacl.example.com", certName: "foo", expError: true},
		{desc: "ACL, no cert", host: "acl.example.com", expError: true},
		{desc: "ACL, client1", host: "acl.example.com", certName: "client1", want: "HTTP/1.0 200 OK"},
		{desc: "ACL, client2", host: "acl.example.com", certName: "client2", want: "HTTP/1.0 200 OK"},
		{desc: "ACL, wrong cert", host: "acl.example.com", certName: "foo", expError: true},
		{desc: "Check console1", host: "acl.example.com", certName: "client1", want: "allow [CN=client1] to acl.example.com"},
		{desc: "Check console2", host: "acl.example.com", certName: "client1", want: "allow [CN=client2] to acl.example.com"},
		{desc: "Check console3", host: "acl.example.com", certName: "client1", want: "allow [CN=foo] to noacl.example.com"},
		{desc: "Check console4", host: "acl.example.com", certName: "client1", want: "deny [CN=foo] to acl.example.com"},
		{desc: "Check console5", host: "acl.example.com", certName: "client1", want: "deny [CN=foo] to emptyacl.example.com"},
	} {
		got, err := get(tc.host, tc.certName)
		if tc.expError != (err != nil) {
			t.Errorf("%s: Got error %v, want %v", tc.desc, (err != nil), tc.expError)
			continue
		}
		if err != nil {
			continue
		}
		if !strings.Contains(got, tc.want) {
			t.Errorf("%s: Got %q, want %q", tc.desc, got, tc.want)
		}
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
	p := &Proxy{
		certManager: cm,
		connections: make(map[connKey]*netw.Conn),
	}
	p.Reconfigure(cfg)
	return p
}

func tlsGet(name, addr, msg string, rootCA *certmanager.CertManager, clientCerts []tls.Certificate, protos []string) (string, error) {
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
	if _, err := c.Write([]byte(msg)); err != nil {
		return "", err
	}
	b, err := io.ReadAll(c)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func httpGet(name, addr string, rootCA *certmanager.CertManager, clientCerts []tls.Certificate) (string, error) {
	return tlsGet(name, addr, "GET / HTTP/1.0\nHost: "+name+"\n\n", rootCA, clientCerts, nil)
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
