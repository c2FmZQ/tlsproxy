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
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/c2FmZQ/storage"
	"github.com/c2FmZQ/storage/crypto"
	"github.com/c2FmZQ/tlsproxy/certmanager"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/netw"
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
		},
		extCA,
	)
	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("proxy.Start: %v", err)
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
	// Backends for HTTP and HTTPS.
	be8 := newHTTPServer(t, ctx, "backend8", nil)
	be9 := newHTTPServer(t, ctx, "backend9", intCA)

	cfg := &Config{
		MaxOpen:           100,
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
				ClientAuth: &ClientAuth{
					RootCAs: intCA.RootCAPEM(),
				},
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
			// HTTP
			{
				ServerNames: []string{
					"http.example.com",
				},
				Addresses: []string{
					be8.String(),
				},
				Mode: "HTTP",
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
				ForwardRootCAs:    intCA.RootCAPEM(),
				ForwardServerName: "https-internal.example.com",
				ClientAuth: &ClientAuth{
					RootCAs: intCA.RootCAPEM(),
				},
				AddClientCertHeader: []string{"cert", "dns", "subject", "hash"},
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
				ForwardRootCAs:    extCA.RootCAPEM(),
				ForwardServerName: "loop.example.com",
			},
		},
	}
	if err := proxy.Reconfigure(cfg); err != nil {
		t.Fatalf("proxy.Reconfigure: %v", err)
	}

	get := func(host, certName string, protos []string, http bool) (string, error) {
		var certs []tls.Certificate
		if certName != "" {
			c, err := intCA.GetCert(certName)
			if err != nil {
				t.Fatalf("intCA.GetCert: %v", err)
			}
			certs = append(certs, *c)
		}
		var body string
		var err error
		if http {
			body, err = httpGet(host, proxy.listener.Addr().String(), extCA, certs)
		} else {
			body, err = tlsGet(host, proxy.listener.Addr().String(), "Hello!\n", extCA, certs, protos)
		}
		if err != nil {
			return "", err
		}
		return body, nil
	}

	for _, tc := range []struct {
		desc, host, want string
		certName         string
		protos           []string
		http             bool
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
		{desc: "Hit backend8", host: "http.example.com", want: "[backend8] /", http: true},
		{desc: "Hit backend9", host: "https.example.com", want: "[backend9] /", http: true, certName: "client.example.com"},
		{desc: "Hit loop", host: "loop.example.com", want: "508 Loop Detected", http: true},
		{desc: "Hit default backend with IP address as host", host: "", want: "421 Misdirected Request", http: true},
	} {
		got, err := get(tc.host, tc.certName, tc.protos, tc.http)
		if tc.expError != (err != nil) {
			t.Errorf("%s: Got error %v, want %v", tc.desc, (err != nil), tc.expError)
			t.Logf("Body: %q err: %v", got, err)
			continue
		}
		if err != nil {
			continue
		}
		if tc.http {
			if !strings.Contains(got, tc.want) {
				t.Errorf("%s: Got %q, want %q", tc.desc, got, tc.want)
			}
		} else if got != tc.want {
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
				Mode: "CONSOLE",
				ClientAuth: &ClientAuth{
					RootCAs: intCA.RootCAPEM(),
				},
			},
			{
				ServerNames: []string{
					"emptyacl.example.com",
				},
				Mode: "CONSOLE",
				ClientAuth: &ClientAuth{
					RootCAs: intCA.RootCAPEM(),
					ACL:     &[]string{},
				},
			},
			{
				ServerNames: []string{
					"acl.example.com",
				},
				Mode: "CONSOLE",
				ClientAuth: &ClientAuth{
					RootCAs: intCA.RootCAPEM(),
					ACL: &[]string{
						"CN=client1",
						"CN=client2",
					},
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

func TestConcurrency(t *testing.T) {
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
			MaxOpen:  2000,
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
					ForwardRootCAs:    ca.RootCAPEM(),
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
					ForwardRootCAs:    ca.RootCAPEM(),
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
		for n := 0; n < 100; n++ {
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
				return
			}
		}
	}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go client(i, &wg)
	}
	wg.Wait()
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
	mk, err := crypto.CreateAESMasterKeyForTest()
	if err != nil {
		panic(err)
	}
	store := storage.New(filepath.Join(cfg.CacheDir, "test"), mk)
	tm, err := tokenmanager.New(store)
	if err != nil {
		panic(err)
	}
	p := &Proxy{
		certManager:  cm,
		connections:  make(map[connKey]*netw.Conn),
		store:        store,
		tokenManager: tm,
	}
	p.Reconfigure(cfg)
	return p
}

func tlsGet(name, addr, msg string, rootCA *certmanager.CertManager, clientCerts []tls.Certificate, protos []string) (string, error) {
	c, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName:         name,
		InsecureSkipVerify: name == "",
		RootCAs:            rootCA.RootCACertPool(),
		Certificates:       clientCerts,
		NextProtos:         protos,
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
	host := name
	if host == "" {
		host = addr
	}
	return tlsGet(name, addr, "GET / HTTP/1.0\nHost: "+host+"\n\n", rootCA, clientCerts, nil)
}

func newHTTPServer(t *testing.T, ctx context.Context, name string, ca *certmanager.CertManager) net.Addr {
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
	s := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if v := r.Header.Get(xFCCHeader); v != "" {
				t.Logf("[%s] %s: %s", name, xFCCHeader, v)
			}
			fmt.Fprintf(w, "[%s] %s\n", name, r.RequestURI)
		}),
	}
	go s.Serve(l)
	go func() {
		<-ctx.Done()
		s.Close()
	}()
	return l.Addr()
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
