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

//go:build !noquic

package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/c2FmZQ/http3-go"
	quicapi "github.com/c2FmZQ/quic-api"
	"github.com/quic-go/quic-go"

	"github.com/c2FmZQ/tlsproxy/certmanager"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/netw"
)

func TestQUICConnections(t *testing.T) {
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

	be1 := newTCPServer(t, ctx, "TCP Backend", nil)
	be2 := newQUICServer(t, ctx, "QUIC Backend", []string{"h3", "imap"}, intCA)
	be3 := newHTTPServer(t, ctx, "HTTPS Backend", intCA)
	be4 := newHTTPServer(t, ctx, "HTTP Backend", nil)

	h2Value := "h2"

	cfg := &Config{
		HTTPAddr: newPtr("localhost:0"),
		TLSAddr:  newPtr("localhost:0"),
		CacheDir: newPtr(t.TempDir()),
		MaxOpen:  newPtr(1000),
		Backends: []*Backend{
			// TCP backend
			{
				ServerNames: Strings{
					"tcp.example.com",
				},
				Mode: "TCP",
				Addresses: Strings{
					be1.listener.Addr().String(),
				},
				ALPNProtos: &Strings{
					"h2",
					"http/1.1",
				},
				ForwardRateLimit: 1000,
			},
			// QUIC backend
			{
				ServerNames: Strings{
					"quic.example.com",
				},
				Mode: "QUIC",
				Addresses: Strings{
					be2.listener.Addr().String(),
				},
				ALPNProtos: &Strings{
					"h3",
					"imap",
				},
				ForwardRootCAs:    Strings{intCA.RootCAPEM()},
				ForwardServerName: "quic-internal.example.com",
				ForwardRateLimit:  1000,
			},
			// HTTPS backend
			{
				ServerNames: Strings{
					"https.example.com",
				},
				Addresses: Strings{
					be3.String(),
				},
				Mode:              "HTTPS",
				BackendProto:      &h2Value,
				ForwardRootCAs:    Strings{intCA.RootCAPEM()},
				ForwardServerName: "https-internal.example.com",
			},
			// HTTP backend
			{
				ServerNames: Strings{
					"http.example.com",
				},
				Addresses: Strings{
					be4.String(),
				},
				Mode:         "HTTP",
				BackendProto: &h2Value,
			},
			// Local backend
			{
				ServerNames: Strings{
					"local.example.com",
				},
				Mode: "LOCAL",
				ALPNProtos: &Strings{
					"h3",
				},
				DocumentRoot: ".",
			},
		},
	}
	proxy := newTestProxy(cfg, extCA)
	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}

	for _, tc := range []struct {
		desc, host, want string
		protos           []string
		expError         bool
		quic             bool
		datagram         bool
		http             bool
	}{
		{desc: "Hit TCP backend with TLS", host: "tcp.example.com", want: "Hello from TCP Backend\n", protos: []string{"http/1.1"}},
		{desc: "Hit TCP backend with QUIC", host: "tcp.example.com", want: "Hello from TCP Backend\n", protos: []string{"http/1.1"}, quic: true},
		{desc: "Hit TCP backend with TLS", host: "tcp.example.com", want: "Hello from TCP Backend\n", protos: []string{"h2"}},
		{desc: "Hit TCP backend with QUIC", host: "tcp.example.com", want: "Hello from TCP Backend\n", protos: []string{"h2"}, quic: true},
		{desc: "Hit HTTPS backend with QUIC", host: "https.example.com", want: "HTTP/3.0 200 OK\n[HTTPS Backend] /proxy.go\n", http: true},
		{desc: "Hit HTTP (H2C) backend with QUIC", host: "http.example.com", want: "HTTP/3.0 200 OK\n[HTTP Backend] /proxy.go\n", http: true},
		{desc: "Hit QUIC backend with TLS h3", host: "quic.example.com", want: "Hello from QUIC Backend\n", protos: []string{"h3"}, expError: true},
		{desc: "Hit QUIC backend with TLS imap", host: "quic.example.com", want: "Hello from QUIC Backend\n", protos: []string{"imap"}},
		{desc: "Hit QUIC backend with QUIC h3", host: "quic.example.com", want: "Hello from QUIC Backend\n", protos: []string{"h3"}, quic: true},
		{desc: "Hit QUIC backend with QUIC imap", host: "quic.example.com", want: "Hello from QUIC Backend\n", protos: []string{"imap"}, quic: true},
		{desc: "Hit QUIC backend with QUIC datagram", host: "quic.example.com", want: "Received 7-byte datagram", protos: []string{"h3"}, datagram: true},
		{desc: "Hit LOCAL backend with QUIC h3", host: "local.example.com", want: "HTTP/3.0 200 OK", protos: []string{"h3"}, http: true},
	} {
		var got string
		var err error
		if tc.datagram {
			got, err = quicDatagram(tc.host, proxy.quicTransport.(*netw.QUICTransport).Addr().String(), "Hello!\n", extCA, tc.protos)
		} else if tc.http {
			got, err = h3Get(tc.host, proxy.quicTransport.(*netw.QUICTransport).Addr().String(), "/proxy.go", extCA)
		} else if tc.quic {
			got, err = quicGet(tc.host, proxy.quicTransport.(*netw.QUICTransport).Addr().String(), "Hello!\n", extCA, tc.protos)
		} else {
			got, _, err = tlsGet(tc.host, proxy.listener.Addr().String(), "Hello!\n", extCA, nil, tc.protos)
		}
		if tc.expError != (err != nil) {
			t.Errorf("%s: Got error %v, want %v", tc.desc, (err != nil), tc.expError)
			t.Logf("Body: %q err: %v", got, err)
			continue
		}
		if err != nil {
			continue
		}
		if tc.http {
			if !strings.HasPrefix(got, tc.want) {
				t.Errorf("%s: Got %q, want %q", tc.desc, got, tc.want)
			}
		} else if got != tc.want {
			t.Errorf("%s: Got %q, want %q", tc.desc, got, tc.want)
		}
	}
}

func TestReverseProxyGetPost(t *testing.T) {
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
			HTTPAddr: newPtr("localhost:0"),
			TLSAddr:  newPtr("localhost:0"),
			CacheDir: newPtr(t.TempDir()),
			MaxOpen:  newPtr(100),
		},
		extCA,
	)
	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}

	// Backends for HTTP and HTTPS.
	be1 := newHTTPServer(t, ctx, "http", nil)
	be2 := newHTTPServer(t, ctx, "https", intCA)

	h2Value := "h2"

	cfg := &Config{
		MaxOpen: newPtr(100),
		Backends: []*Backend{
			// HTTP
			{
				ServerNames: Strings{
					"http.example.com",
				},
				Addresses: Strings{
					be1.String(),
				},
				Mode: "HTTP",
			},
			// HTTP H2C
			{
				ServerNames: Strings{
					"h2c.example.com",
				},
				Addresses: Strings{
					be1.String(),
				},
				Mode:         "HTTP",
				BackendProto: &h2Value,
			},
			// HTTPS
			{
				ServerNames: Strings{
					"https.example.com",
				},
				Addresses: Strings{
					be2.String(),
				},
				Mode:              "HTTPS",
				ForwardRootCAs:    Strings{intCA.RootCAPEM()},
				ForwardServerName: "https-internal.example.com",
			},
		},
	}
	if err := proxy.Reconfigure(cfg); err != nil {
		t.Fatalf("proxy.Reconfigure: %v", err)
	}

	dir := t.TempDir()
	filename := filepath.Join(dir, "postdata")
	if err := os.WriteFile(filename, []byte("foo bar 1 2 3"), 0o644); err != nil {
		t.Fatalf("os.Writefile: %v", err)
	}

	openOrDie := func(name string) *os.File {
		f, err := os.Open(name)
		if err != nil {
			t.Fatalf("os.Open(%q): %v", name, err)
		}
		return f
	}

	doReq := func(method, host, path string, body io.ReadCloser, http3 bool) (string, error) {
		if !http3 {
			body, _, err := httpOp(host, proxy.listener.Addr().String(), path, method, body, extCA, nil)
			return body, err
		}
		qt, ok := proxy.quicTransport.(*netw.QUICTransport)
		if !ok {
			t.Fatalf("proxy.quicTransport is %T", proxy.quicTransport)
		}
		return h3Op(host, qt.Addr().String(), path, method, body, extCA)
	}

	for _, tc := range []struct {
		desc, host, method, path string
		http3                    bool
		body                     io.ReadCloser
		want                     string
	}{
		{
			desc:   "HTTP GET /",
			host:   "http.example.com",
			method: "GET",
			path:   "/",
			want:   "HTTP/2.0 200 OK\n[http] /\n",
		},
		{
			desc:   "H2C HTTP GET /",
			host:   "h2c.example.com",
			method: "GET",
			path:   "/",
			want:   "HTTP/2.0 200 OK\n[http] /\n",
		},
		{
			desc:   "H3 HTTP GET /",
			host:   "http.example.com",
			method: "GET",
			path:   "/",
			http3:  true,
			want:   "HTTP/3.0 200 OK\n[http] /\n",
		},
		{
			desc:   "HTTP POST /",
			host:   "http.example.com",
			method: "POST",
			path:   "/",
			body:   io.NopCloser(bytes.NewReader([]byte("foo"))),
			want:   "HTTP/2.0 200 OK\n[http] POST / foo\n",
		},
		{
			desc:   "H2C HTTP POST /",
			host:   "h2c.example.com",
			method: "POST",
			path:   "/",
			body:   io.NopCloser(bytes.NewReader([]byte("foo"))),
			want:   "HTTP/2.0 200 OK\n[http] POST / foo\n",
		},
		{
			desc:   "H3 HTTP POST /",
			host:   "http.example.com",
			method: "POST",
			path:   "/",
			body:   io.NopCloser(bytes.NewReader([]byte("bar"))),
			http3:  true,
			want:   "HTTP/3.0 200 OK\n[http] POST / bar\n",
		},
		{
			desc:   "HTTP POST /",
			host:   "http.example.com",
			method: "POST",
			path:   "/",
			body:   openOrDie(filename),
			want:   "HTTP/2.0 200 OK\n[http] POST / foo bar 1 2 3\n",
		},
		{
			desc:   "H3 HTTP POST /",
			host:   "http.example.com",
			method: "POST",
			path:   "/",
			body:   openOrDie(filename),
			http3:  true,
			want:   "HTTP/3.0 200 OK\n[http] POST / foo bar 1 2 3\n",
		},
		{
			desc:   "HTTPS POST /",
			host:   "https.example.com",
			method: "POST",
			path:   "/",
			body:   openOrDie(filename),
			want:   "HTTP/2.0 200 OK\n[https] POST / foo bar 1 2 3\n",
		},
		{
			desc:   "H3 HTTPS POST /",
			host:   "https.example.com",
			method: "POST",
			path:   "/",
			body:   openOrDie(filename),
			http3:  true,
			want:   "HTTP/3.0 200 OK\n[https] POST / foo bar 1 2 3\n",
		},
	} {
		got, err := doReq(tc.method, tc.host, tc.path, tc.body, tc.http3)
		if err != nil {
			t.Fatalf("%s: doReq() = %q, %v", tc.desc, got, err)
			continue
		}
		if want := tc.want; got != want {
			t.Errorf("%s: Got %q, want %q", tc.desc, got, want)
		}
	}
}
func TestQUICMultiStream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ca, err := certmanager.New("root-ca.example.com", t.Logf)
	if err != nil {
		t.Fatalf("certmanager.New: %v", err)
	}

	tc := ca.TLSConfig()
	tc.NextProtos = []string{"foo"}

	ln, err := quicapi.ListenAddr("localhost:0", tc, &quic.Config{})
	if err != nil {
		t.Fatalf("ListenAddr: %v", err)
	}
	defer ln.Close()
	t.Logf("QUIC LISTENER: %s", ln.Addr())

	server := &quicNode{t: t, name: "SERVER"}
	client := &quicNode{t: t, name: "CLIENT"}

	ch := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept(ctx)
			if err != nil {
				t.Logf("Accept: %v", err)
				return
			}
			t.Logf("Accepted connection")
			server.run(conn)
			ch <- struct{}{}
		}
	}()

	cfg := &Config{
		HTTPAddr: newPtr("localhost:0"),
		TLSAddr:  newPtr("localhost:0"),
		CacheDir: newPtr(t.TempDir()),
		MaxOpen:  newPtr(1000),
		Backends: []*Backend{
			{
				ServerNames: Strings{
					"quic.example.com",
				},
				Mode: "QUIC",
				Addresses: Strings{
					ln.Addr().String(),
				},
				ALPNProtos: &Strings{
					"foo",
				},
				ForwardRootCAs:    Strings{ca.RootCAPEM()},
				ForwardServerName: "quic-internal.example.com",
				ForwardRateLimit:  1000,
			},
		},
	}
	proxy := newTestProxy(cfg, ca)
	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}

	clientTC := &tls.Config{
		ServerName: "quic.example.com",
		RootCAs:    ca.RootCACertPool(),
		NextProtos: []string{"foo"},
	}

	dests := []string{
		ln.Addr().String(),
		proxy.quicTransport.(*netw.QUICTransport).Addr().String(),
	}

	for _, dest := range dests {
		conn, err := quicapi.DialAddr(ctx, dest, clientTC, &quic.Config{})
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		t.Logf("Dialed connection to %s", dest)
		client.run(conn)
		<-ch
		conn.CloseWithError(0, "done")

		if got, want := client.received, server.sent; !reflect.DeepEqual(got, want) {
			t.Errorf("Client received = %#v, want %#v", got, want)
		}
		if got, want := server.received, client.sent; !reflect.DeepEqual(got, want) {
			t.Errorf("Server received = %#v, want %#v", got, want)
		}

		client.reset()
		server.reset()
	}
}

func quicGet(name, addr, msg string, rootCA *certmanager.CertManager, protos []string) (string, error) {
	ctx := context.Background()
	tc := &tls.Config{
		ServerName: name,
		RootCAs:    rootCA.RootCACertPool(),
		NextProtos: protos,
	}

	conn, err := quicapi.DialAddr(ctx, addr, tc, &quic.Config{})
	if err != nil {
		return "", err
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return "", err
	}
	defer stream.Close()
	defer stream.CancelRead(0)
	if _, err := stream.Write([]byte(msg)); err != nil {
		return "", err
	}
	b, err := io.ReadAll(stream)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func h3Get(name, addr, path string, rootCA *certmanager.CertManager) (string, error) {
	return h3Op(name, addr, path, "GET", nil, rootCA)
}

func h3Op(name, addr, path, method string, body io.ReadCloser, rootCA *certmanager.CertManager) (string, error) {
	name = idnaToASCII(name)
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		return "", err
	}
	tr := quicapi.WrapTransport(&quic.Transport{Conn: conn})
	roundTripper := &http3.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         name,
			InsecureSkipVerify: name == "",
			RootCAs:            rootCA.RootCACertPool(),
			NextProtos:         []string{"h3"},
		},
		Dial: func(ctx context.Context, _ string, tc *tls.Config, qc *quic.Config) (quicapi.Conn, error) {
			a, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				return nil, err
			}
			c, err := tr.DialEarly(ctx, a, tc, qc)
			if err != nil {
				return nil, err
			}
			return c, nil
		},
	}
	defer roundTripper.Close()
	client := &http.Client{Transport: roundTripper}
	host := name
	if host == "" {
		host = addr
	}
	req, err := http.NewRequest(method, "https://"+host+path, body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Host", host)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return resp.Proto + " " + resp.Status + "\n" + string(b), nil
}

func quicDatagram(name, addr, msg string, rootCA *certmanager.CertManager, protos []string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	tc := &tls.Config{
		ServerName: name,
		RootCAs:    rootCA.RootCACertPool(),
		NextProtos: protos,
	}

	conn, err := quicapi.DialAddr(ctx, addr, tc, &quic.Config{EnableDatagrams: true})
	if err != nil {
		return "", err
	}
	go func() {
		for {
			conn.SendDatagram([]byte(msg))
			select {
			case <-ctx.Done():
				return
			case <-time.After(50 * time.Millisecond):
			}
		}
	}()
	b, err := conn.ReceiveDatagram(ctx)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

type quicServer struct {
	t        *testing.T
	listener quicapi.Listener
}

func newQUICServer(t *testing.T, ctx context.Context, name string, protos []string, ca tcProvider) *quicServer {
	tc := ca.TLSConfig()
	tc.NextProtos = protos
	ln, err := quicapi.ListenAddr("localhost:0", tc, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatalf("[%s] ListenAddr: %v", name, err)
	}
	go func() {
		for {
			conn, err := ln.Accept(ctx)
			if err != nil {
				if errors.Is(err, quic.ErrServerClosed) || errors.Is(err, context.Canceled) {
					break
				}
				t.Logf("[%s] Accept: %v", name, err)
				continue
			}
			t.Logf("[%s] Received connection from %s", name, conn.RemoteAddr())
			go func() {
				for {
					stream, err := conn.AcceptStream(ctx)
					if err != nil {
						conn.CloseWithError(0x11, err.Error())
						break
					}
					go func(s quicapi.Stream) {
						fmt.Fprintf(s, "Hello from %s\n", name)
						s.CancelRead(0)
						s.Close()
					}(stream)
				}
			}()
			go func() {
				for {
					stream, err := conn.AcceptUniStream(ctx)
					if err != nil {
						conn.CloseWithError(0x11, err.Error())
						break
					}
					go func(s quicapi.ReceiveStream) {
						if _, err := io.ReadAll(s); err != nil {
							t.Logf("[%s] ReadAll: %v", name, err)
						}
						s.CancelRead(0)
					}(stream)
				}
			}()
			go func() {
				for {
					b, err := conn.ReceiveDatagram(ctx)
					if err != nil {
						conn.CloseWithError(0x11, err.Error())
						break
					}
					if err := conn.SendDatagram([]byte(fmt.Sprintf("Received %d-byte datagram", len(b)))); err != nil {
						t.Logf("[%s] SendDatagram: %v", name, err)
					}
				}
			}()
		}
	}()
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	return &quicServer{
		t:        t,
		listener: ln,
	}
}

type quicNode struct {
	t        *testing.T
	name     string
	mu       sync.Mutex
	sent     []string
	received []string
}

func (n *quicNode) reset() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sent = nil
	n.received = nil
}

func (n *quicNode) send(stream quicapi.SendStream, format string, args ...any) error {
	m := fmt.Sprintf(format, args...)
	if _, err := stream.Write([]byte(m)); err != nil {
		n.t.Errorf("[%s] Write: %v", n.name, err)
		return err
	}
	if err := stream.Close(); err != nil {
		n.t.Errorf("[%s] Close: %v", n.name, err)
		return err
	}
	n.mu.Lock()
	n.sent = append(n.sent, m)
	n.mu.Unlock()
	return nil
}

func (n *quicNode) recv(stream quicapi.ReceiveStream) error {
	b, err := io.ReadAll(stream)
	if err != nil {
		n.t.Errorf("[%s] ReadAll: %v", n.name, err)
		return err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.received = append(n.received, string(b))
	return nil
}

func (n *quicNode) run(conn quicapi.Conn) {
	n.t.Logf("MultiStreamNode[%s]", n.name)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			stream, err := conn.AcceptStream(conn.Context())
			if err != nil {
				n.t.Logf("[%s] AcceptStream: %v", n.name, err)
				break
			}
			ch := make(chan error)
			go func() {
				ch <- n.recv(stream)
			}()
			n.send(stream, "Hello accept bidi stream %02d from %s", i+1, n.name)
			<-ch
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			stream, err := conn.AcceptUniStream(conn.Context())
			if err != nil {
				n.t.Logf("[%s] AcceptUniStream: %v", n.name, err)
				break
			}
			n.recv(stream)
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			stream, err := conn.OpenStreamSync(conn.Context())
			if err != nil {
				n.t.Errorf("[%s] OpenStream: %v", n.name, err)
				break
			}
			ch := make(chan error)
			go func() {
				ch <- n.recv(stream)
			}()
			n.send(stream, "Hello open bidi stream %02d from %s", i+1, n.name)
			<-ch
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			stream, err := conn.OpenUniStreamSync(conn.Context())
			if err != nil {
				n.t.Errorf("[%s] OpenUniStream: %v", n.name, err)
				break
			}
			n.send(stream, "Hello open uni stream %02d from %s", i+1, n.name)
		}
	}()
	wg.Wait()

	n.mu.Lock()
	defer n.mu.Unlock()
	sort.Strings(n.sent)
	sort.Strings(n.received)
	for _, e := range n.received {
		n.t.Logf("[%s] received: %s", n.name, e)
	}
}
