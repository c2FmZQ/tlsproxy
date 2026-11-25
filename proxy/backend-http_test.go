// MIT License
//
// Copyright (c) 2024 TTBT Enterprises LLC
// Copyright (c) 2024 Robin Thellend <rthellend@rthellend.com>
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
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/c2FmZQ/websocket"
	jwt "github.com/golang-jwt/jwt/v5"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"golang.org/x/time/rate"

	"github.com/c2FmZQ/tlsproxy/certmanager"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/fromctx"
)

func TestExpandVars(t *testing.T) {
	ctx := fromctx.WithClaims(context.Background(), jwt.MapClaims{
		"email": "bob@example.com",
		"name":  "Bob",
	})
	ctx = context.WithValue(ctx, connCtxKey, mockConn{
		localAddr: &net.TCPAddr{
			IP:   net.IPv4(1, 2, 3, 4),
			Port: 443,
		},
		remoteAddr: &net.TCPAddr{
			IP:   net.IPv4(11, 22, 33, 44),
			Port: 5678,
		},
		annotations: map[string]any{
			serverNameKey: "www.example.com",
		},
	})
	req, err := http.NewRequestWithContext(ctx, "GET", "https://www.example.com/", nil)
	if err != nil {
		t.Fatalf("http.NewRequestWithContext: %v", err)
	}

	for _, tc := range []struct {
		in, out string
	}{
		{in: "FOO", out: "FOO"},
		{in: "$LOCAL_ADDR", out: "1.2.3.4:443"},
		{in: "$LOCAL_IP", out: "1.2.3.4"},
		{in: "$REMOTE_ADDR", out: "11.22.33.44:5678"},
		{in: "$REMOTE_IP", out: "11.22.33.44"},
		{in: "$SERVER_NAME", out: "www.example.com"},
		{in: "${JWT:email}", out: "bob@example.com"},
		{in: "${JWT:name}", out: "Bob"},
		{in: "${JWT:foo}", out: ""},
		{in: "FOO ${SERVER_NAME} ${NETWORK} ${LOCAL_IP} BAR", out: "FOO www.example.com tcp 1.2.3.4 BAR"},
	} {
		if got, want := expandVars(tc.in, req), tc.out; got != want {
			t.Errorf("expandVars(%q) = %q, want %q", tc.in, got, want)
		}
	}

}

type mockConn struct {
	localAddr   net.Addr
	remoteAddr  net.Addr
	annotations map[string]any
}

func (c mockConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c mockConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (mockConn) Close() error {
	return nil
}

func (c mockConn) Annotation(key string, defaultValue any) any {
	if v, ok := c.annotations[key]; ok {
		return v
	}
	return defaultValue
}

func (c mockConn) SetAnnotation(key string, value any) {
	c.annotations[key] = value
}

func (mockConn) BytesSent() int64 {
	return 0
}

func (mockConn) BytesReceived() int64 {
	return 0
}

func (mockConn) ByteRateSent() float64 {
	return 0
}

func (mockConn) ByteRateReceived() float64 {
	return 0
}

func TestMisdirectedRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	extCA, err := certmanager.New("root-ca.example.com", t.Logf)
	if err != nil {
		t.Fatalf("certmanager.New: %v", err)
	}
	be := newHTTPServer(t, ctx, "https", nil)

	proxy := newTestProxy(
		&Config{
			HTTPAddr: newPtr("localhost:0"),
			TLSAddr:  newPtr("localhost:0"),
			CacheDir: newPtr(t.TempDir()),
			MaxOpen:  newPtr(100),
			Backends: []*Backend{
				{
					ServerNames:  Strings{"local.example.com"},
					Mode:         "LOCAL",
					DocumentRoot: ".",
				},
				{
					ServerNames: Strings{"http.example.com"},
					Mode:        "HTTP",
					Addresses:   Strings{be.String()},
				},
				{
					ServerNames:  Strings{"other.example.com"},
					Mode:         "LOCAL",
					DocumentRoot: ".",
				},
			},
		},
		extCA,
	)
	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}
	defer proxy.Stop()

	for _, tc := range []struct {
		sni, host, want string
	}{
		{"local.example.com", "local.example.com", "HTTP/1.1 200 OK"},
		{"local.example.com", "local.example.com:443", "HTTP/1.1 200 OK"},
		{"local.example.com", "other.example.com", "HTTP/1.1 421 Misdirected Request"},
		{"http.example.com", "http.example.com", "HTTP/1.1 200 OK"},
		{"http.example.com", "other.example.com", "HTTP/1.1 421 Misdirected Request"},
	} {
		msg := "GET /proxy.go HTTP/1.1\r\nHost: " + tc.host + "\r\nConnection: close\r\n\r\n"
		got, _, err := tlsGet(tc.sni, proxy.listener.Addr().String(), msg, extCA, nil, []string{"http/1.1"})
		if err != nil {
			t.Fatalf("tlsGet(%q, %q): %v", tc.sni, tc.host, err)
		}
		if !strings.HasPrefix(got, tc.want) {
			first, _, _ := strings.Cut(got, "\r\n")
			t.Errorf("SNI %q Host %q: got %q, want %q", tc.sni, tc.host, first, tc.want)
		}
	}
}

func TestForwardedHeaders(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	extCA, err := certmanager.New("root-ca.example.com", t.Logf)
	if err != nil {
		t.Fatalf("certmanager.New: %v", err)
	}

	// A backend that returns all the request headers.
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	beServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			var lines []string
			for k, v := range req.Header {
				lines = append(lines, fmt.Sprintf("%s: %s", k, strings.Join(v, ",")))
			}
			slices.Sort(lines)
			fmt.Fprintln(w, strings.Join(lines, "\n"))
		}),
	}
	go beServer.Serve(l)
	defer beServer.Close()

	proxy := newTestProxy(
		&Config{
			HTTPAddr: newPtr("localhost:0"),
			TLSAddr:  newPtr("localhost:0"),
			CacheDir: newPtr(t.TempDir()),
			MaxOpen:  newPtr(100),
			Backends: []*Backend{
				{
					ServerNames: Strings{"http.example.com"},
					Mode:        "HTTP",
					Addresses:   Strings{l.Addr().String()},
					ForwardHTTPHeaders: map[string]string{
						"X-Server-Name": "${SERVER_NAME}",
					},
				},
			},
		},
		extCA,
	)
	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}
	defer proxy.Stop()

	msg := "GET / HTTP/1.1\r\n" +
		"Host: http.example.com\r\n" +
		"X_tlsproxy_user_id: admin@example.com\r\n" +
		"x-tlsproxy-user-id: admin@example.com\r\n" +
		"X_Server_Name: evil.example.com\r\n" +
		"X_Forwarded_For: 1.2.3.4\r\n" +
		"X-Forwarded-Host: evil.example.com\r\n" +
		"X-Forwarded-Proto: http\r\n" +
		"Forwarded: for=1.2.3.4\r\n" +
		"X-Other: foo\r\n" +
		"Connection: close\r\n\r\n"
	got, _, err := tlsGet("http.example.com", proxy.listener.Addr().String(), msg, extCA, nil, []string{"http/1.1"})
	if err != nil {
		t.Fatalf("tlsGet: %v", err)
	}
	_, body, _ := strings.Cut(got, "\r\n\r\n")
	headers := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
		if k, v, ok := strings.Cut(line, ": "); ok {
			headers[k] = v
		}
	}
	for k, want := range map[string]string{
		"X-Server-Name":     "http.example.com",
		"X-Forwarded-Host":  "http.example.com",
		"X-Forwarded-Proto": "https",
		"X-Other":           "foo",
	} {
		if got := headers[k]; got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	for _, k := range []string{"X_tlsproxy_user_id", "X-Tlsproxy-User-Id", "X_server_name", "X_forwarded_for", "Forwarded"} {
		if v, ok := headers[k]; ok {
			t.Errorf("unexpected header %s: %q", k, v)
		}
	}
	if got := headers["X-Forwarded-For"]; got == "" || strings.Contains(got, "1.2.3.4") {
		t.Errorf("X-Forwarded-For = %q", got)
	}
	t.Logf("Headers:\n%s", body)
}

func TestMaxOpenPerIP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	extCA, err := certmanager.New("root-ca.example.com", t.Logf)
	if err != nil {
		t.Fatalf("certmanager.New: %v", err)
	}
	proxy := newTestProxy(
		&Config{
			HTTPAddr:     newPtr("localhost:0"),
			TLSAddr:      newPtr("localhost:0"),
			CacheDir:     newPtr(t.TempDir()),
			MaxOpen:      newPtr(100),
			MaxOpenPerIP: newPtr(2),
			Backends: []*Backend{
				{
					ServerNames:  Strings{"local.example.com"},
					Mode:         "LOCAL",
					DocumentRoot: ".",
				},
			},
		},
		extCA,
	)
	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}
	defer proxy.Stop()

	dial := func() (*tls.Conn, error) {
		conn, err := tls.Dial("tcp", proxy.listener.Addr().String(), &tls.Config{
			ServerName: "local.example.com",
			RootCAs:    extCA.RootCACertPool(),
			NextProtos: []string{"http/1.1"},
		})
		if err != nil {
			return nil, err
		}
		// Make sure the proxy accepted the connection.
		if _, err := conn.Write([]byte("HEAD /proxy.go HTTP/1.1\r\nHost: local.example.com\r\n\r\n")); err != nil {
			conn.Close()
			return nil, err
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "HEAD"})
		if err != nil {
			conn.Close()
			return nil, err
		}
		resp.Body.Close()
		return conn, nil
	}

	c1, err := dial()
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}
	c2, err := dial()
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	defer c2.Close()
	if c3, err := dial(); err == nil {
		c3.Close()
		t.Fatal("dial 3: unexpected success")
	}
	c1.Close()
	// Wait for the proxy to see that c1 is closed.
	var c4 *tls.Conn
	for range 50 {
		if c4, err = dial(); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial 4: %v", err)
	}
	c4.Close()
}

func TestWaitConnLimit(t *testing.T) {
	// One token every 100 seconds.
	be := &Backend{connLimit: rate.NewLimiter(rate.Every(100*time.Second), 1)}
	if err := be.waitConnLimit(context.Background()); err != nil {
		t.Fatalf("waitConnLimit: %v", err)
	}
	// The next token would take longer than maxConnLimitWait.
	start := time.Now()
	if err := be.waitConnLimit(context.Background()); err == nil {
		t.Fatal("waitConnLimit: unexpected success")
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("waitConnLimit took %s", d)
	}
}

func TestRedactConfig(t *testing.T) {
	if runtime.MemProfileRate == 1 {
		t.Errorf("runtime.MemProfileRate = 1 by default, want default sampling rate")
	}
	poHeaders := map[string]string{"Authorization": "Bearer S3CR3T3"}
	cfg := &Config{
		ECH: &ECH{
			WebHooks: Strings{"https://hooks.example.com/services/S3CR3T1?token=S3CR3T2"},
		},
		OIDCProviders: []*ConfigOIDC{{ClientSecret: "S3CR3T4"}},
		Backends: []*Backend{
			{
				ForwardHTTPHeaders: map[string]string{
					"X-Api-Key": "S3CR3T5",
					"X-User":    "${JWT:email}",
					"X-Mixed":   "Bearer S3CR3T7-${JWT:email}",
				},
				PathOverrides: []*PathOverride{{ForwardHTTPHeaders: &poHeaders}},
				SSO: &BackendSSO{
					LocalOIDCServer: &LocalOIDCServer{
						Clients: []*LocalOIDCClient{{ID: "foo", Secret: "S3CR3T6"}},
					},
				},
			},
		},
	}
	redactConfig(cfg)
	out := string(cfg.serialize())
	if strings.Contains(out, "S3CR3T") {
		t.Errorf("redacted config contains secrets:\n%s", out)
	}
	for _, want := range []string{"https://hooks.example.com/", "${JWT:email}"} {
		if !strings.Contains(out, want) {
			t.Errorf("redacted config doesn't contain %q:\n%s", want, out)
		}
	}
}

func TestBackendCannotSetProxyCookies(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	extCA, err := certmanager.New("root-ca.example.com", t.Logf)
	if err != nil {
		t.Fatalf("certmanager.New: %v", err)
	}
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	beServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			for _, c := range []string{
				"TLSPROXYNONCE=evil; Domain=example.com; Path=/",
				"TLSPROXYSAMLNONCE=evil; Domain=example.com; Path=/",
				"TLSPROXYAUTH=evil; Path=/",
				"tlsproxyidtoken=evil; Path=/",
				"__tlsproxySid=evil; Path=/",
				"app=ok; Path=/",
			} {
				w.Header().Add("Set-Cookie", c)
			}
			w.Write([]byte("ok"))
		}),
	}
	go beServer.Serve(l)
	defer beServer.Close()

	proxy := newTestProxy(
		&Config{
			HTTPAddr: newPtr("localhost:0"),
			TLSAddr:  newPtr("localhost:0"),
			CacheDir: newPtr(t.TempDir()),
			MaxOpen:  newPtr(100),
			Backends: []*Backend{
				{
					ServerNames: Strings{"http.example.com"},
					Mode:        "HTTP",
					Addresses:   Strings{l.Addr().String()},
				},
			},
		},
		extCA,
	)
	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}
	defer proxy.Stop()

	msg := "GET / HTTP/1.1\r\nHost: http.example.com\r\nConnection: close\r\n\r\n"
	got, _, err := tlsGet("http.example.com", proxy.listener.Addr().String(), msg, extCA, nil, []string{"http/1.1"})
	if err != nil {
		t.Fatalf("tlsGet: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(got)), nil)
	if err != nil {
		t.Fatalf("http.ReadResponse: %v", err)
	}
	var names []string
	for _, c := range resp.Cookies() {
		names = append(names, c.Name)
	}
	if want := []string{"app"}; !slices.Equal(names, want) {
		t.Errorf("Cookies = %v, want %v", names, want)
	}
}

func TestConnectionHeaderStripping(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	extCA, err := certmanager.New("root-ca.example.com", t.Logf)
	if err != nil {
		t.Fatalf("certmanager.New: %v", err)
	}
	clientCA, err := certmanager.New("client-ca.example.com", t.Logf)
	if err != nil {
		t.Fatalf("certmanager.New: %v", err)
	}

	var gotHeaders http.Header
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	s := http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			gotHeaders = req.Header.Clone()
			w.WriteHeader(http.StatusOK)
		}),
	}
	go s.Serve(l)
	defer s.Close()

	proxy := newTestProxy(
		&Config{
			HTTPAddr: newPtr("localhost:0"),
			TLSAddr:  newPtr("localhost:0"),
			CacheDir: newPtr(t.TempDir()),
			MaxOpen:  newPtr(100),
			Backends: []*Backend{
				{
					ServerNames: Strings{"http.example.com"},
					Mode:        "HTTP",
					Addresses:   Strings{l.Addr().String()},
					ForwardHTTPHeaders: map[string]string{
						"X-Custom-Header": "custom-value",
					},
					ClientAuth: &ClientAuth{
						RootCAs:             Strings{clientCA.RootCAPEM()},
						AddClientCertHeader: Strings{"subject"},
					},
				},
			},
		},
		extCA,
	)
	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}
	defer proxy.Stop()

	clientCert, err := clientCA.GetCert("client.example.com")
	if err != nil {
		t.Fatalf("clientCA.GetCert: %v", err)
	}

	msg := "GET / HTTP/1.1\r\n" +
		"Host: http.example.com\r\n" +
		"Connection: Via, X-Forwarded-Client-Cert, X-Forwarded-Host, X-Forwarded-Proto, X-Custom-Header, close\r\n\r\n"
	got, _, err := tlsGet("http.example.com", proxy.listener.Addr().String(), msg, extCA, []tls.Certificate{*clientCert}, []string{"http/1.1"})
	if err != nil {
		t.Fatalf("tlsGet: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(got)), nil)
	if err != nil {
		t.Fatalf("http.ReadResponse: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("StatusCode = %d, want 200", resp.StatusCode)
	}
	for _, h := range []string{"Via", "X-Forwarded-Client-Cert", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Custom-Header"} {
		if gotHeaders.Get(h) == "" {
			t.Errorf("Backend did not receive %s header (stripped via Connection header)", h)
		}
	}

	// Also verify that multi-line Via header loop detection inspects all Via headers.
	msg2 := "GET / HTTP/1.1\r\nHost: http.example.com\r\nConnection: close\r\n\r\n"
	if _, _, err := tlsGet("http.example.com", proxy.listener.Addr().String(), msg2, extCA, []tls.Certificate{*clientCert}, []string{"http/1.1"}); err != nil {
		t.Fatalf("tlsGet(2): %v", err)
	}
	viaLine := gotHeaders.Get("Via")
	_, me, _ := strings.Cut(viaLine, " ")
	loopMsg := "GET / HTTP/1.1\r\n" +
		"Host: http.example.com\r\n" +
		"Via: HTTP/1.1 other-proxy\r\n" +
		"Via: HTTP/1.1 " + me + "\r\n" +
		"Connection: close\r\n\r\n"
	gotLoop, _, err := tlsGet("http.example.com", proxy.listener.Addr().String(), loopMsg, extCA, []tls.Certificate{*clientCert}, []string{"http/1.1"})
	if err != nil {
		t.Fatalf("tlsGet(loop): %v", err)
	}
	respLoop, err := http.ReadResponse(bufio.NewReader(strings.NewReader(gotLoop)), nil)
	if err != nil {
		t.Fatalf("http.ReadResponse(loop): %v", err)
	}
	if respLoop.StatusCode != http.StatusLoopDetected {
		t.Errorf("Loop StatusCode = %d, want %d", respLoop.StatusCode, http.StatusLoopDetected)
	}
}

func TestForwardRateLimitKeepAlive(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	extCA, err := certmanager.New("root-ca.example.com", t.Logf)
	if err != nil {
		t.Fatalf("certmanager.New: %v", err)
	}
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	s := http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	}
	go s.Serve(l)
	defer s.Close()

	proxy := newTestProxy(
		&Config{
			HTTPAddr: newPtr("localhost:0"),
			TLSAddr:  newPtr("localhost:0"),
			CacheDir: newPtr(t.TempDir()),
			MaxOpen:  newPtr(100),
			Backends: []*Backend{
				{
					ServerNames: Strings{"http.example.com"},
					Mode:        "HTTP",
					Addresses:   Strings{l.Addr().String()},
				},
			},
		},
		extCA,
	)
	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}
	defer proxy.Stop()

	// Allow 1 token every 100s (taken by initial TLS connection establishment).
	proxy.mu.Lock()
	for _, b := range proxy.backends {
		b.connLimit = rate.NewLimiter(rate.Every(100*time.Second), 1)
	}
	proxy.mu.Unlock()

	conn, err := tls.Dial("tcp", proxy.listener.Addr().String(), &tls.Config{
		ServerName: "http.example.com",
		RootCAs:    extCA.RootCACertPool(),
		NextProtos: []string{"http/1.1"},
	})
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	defer conn.Close()

	br := bufio.NewReader(conn)
	// First request on the connection uses the token already consumed at connection time.
	if _, err := conn.Write([]byte("HEAD / HTTP/1.1\r\nHost: http.example.com\r\n\r\n")); err != nil {
		t.Fatalf("Write #1: %v", err)
	}
	resp1, err := http.ReadResponse(br, &http.Request{Method: "HEAD"})
	if err != nil {
		t.Fatalf("ReadResponse #1: %v", err)
	}
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("resp1.StatusCode = %d, want 200", resp1.StatusCode)
	}

	// Second request on the same keep-alive TLS connection must be rate-limited.
	if _, err := conn.Write([]byte("HEAD / HTTP/1.1\r\nHost: http.example.com\r\n\r\n")); err != nil {
		t.Fatalf("Write #2: %v", err)
	}
	resp2, err := http.ReadResponse(br, &http.Request{Method: "HEAD"})
	if err != nil {
		t.Fatalf("ReadResponse #2: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode == http.StatusOK {
		t.Fatalf("resp2.StatusCode = %d, want rate limit failure (500)", resp2.StatusCode)
	}
}

func TestWebSocketAndConnectionUpgrade(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	extCA, err := certmanager.New("root-ca.example.com", t.Logf)
	if err != nil {
		t.Fatalf("certmanager.New: %v", err)
	}

	// Backend HTTP/1.1 server that handles Upgrade requests.
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	s := http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
				hj, ok := w.(http.Hijacker)
				if !ok {
					http.Error(w, "no hijacker", http.StatusInternalServerError)
					return
				}
				conn, rw, err := hj.Hijack()
				if err != nil {
					return
				}
				defer conn.Close()
				rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nupgraded")
				rw.Flush()
				return
			}
			w.WriteHeader(http.StatusOK)
		}),
	}
	go s.Serve(l)
	defer s.Close()

	// TCP echo server for WebSocket bridge.
	tcpListener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("net.Listen(tcp): %v", err)
	}
	defer tcpListener.Close()
	go func() {
		for {
			c, err := tcpListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						c.Write(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()

	proxy := newTestProxy(
		&Config{
			HTTPAddr: newPtr("localhost:0"),
			TLSAddr:  newPtr("localhost:0"),
			CacheDir: newPtr(t.TempDir()),
			MaxOpen:  newPtr(100),
			WebSockets: []*WebSocketConfig{
				{
					Endpoint: "https://http.example.com/ws",
					Address:  tcpListener.Addr().String(),
				},
			},
			Backends: []*Backend{
				{
					ServerNames:  Strings{"http.example.com"},
					Mode:         "HTTP",
					BackendProto: newPtr("h2"),
					Addresses:    Strings{l.Addr().String()},
				},
			},
		},
		extCA,
	)
	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}
	defer proxy.Stop()

	// 1. Multi-token Connection: keep-alive, Upgrade must use HTTP/1.1 transport even when BackendProto is "h2".
	rt := proxy.cfg.Backends[0].reverseProxyTransport()
	reqCtx := context.WithValue(ctx, connCtxKey, mockConn{annotations: map[string]any{}})
	upReq, err := http.NewRequestWithContext(reqCtx, "GET", "http://http.example.com/chat", nil)
	if err != nil {
		t.Fatalf("http.NewRequestWithContext: %v", err)
	}
	upReq.Header.Set("Connection", "keep-alive, Upgrade")
	upReq.Header.Set("Upgrade", "websocket")
	upResp, err := rt.RoundTrip(upReq)
	if err != nil {
		t.Fatalf("rt.RoundTrip(upgrade): %v", err)
	}
	upResp.Body.Close()
	if upResp.StatusCode != http.StatusSwitchingProtocols {
		t.Errorf("Multi-token Connection upgrade StatusCode = %d, want 101 Switching Protocols", upResp.StatusCode)
	}

	// 2. WebSocket endpoint should handle concurrent ping/pong without data race and reject non-binary frames.
	origPing := wsPingInterval
	wsPingInterval = 5 * time.Millisecond
	defer func() { wsPingInterval = origPing }()

	dialer := websocket.Dialer{
		NetDialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return tls.Dial(network, proxy.listener.Addr().String(), &tls.Config{
				ServerName: "http.example.com",
				RootCAs:    extCA.RootCACertPool(),
				NextProtos: []string{"http/1.1"},
			})
		},
	}
	wsConn, resp, err := dialer.DialContext(ctx, "wss://http.example.com/ws", nil)
	if err != nil {
		t.Fatalf("dialer.DialContext: %v", err)
	}
	resp.Body.Close()
	defer wsConn.Close()
	wsConn.SetPingHandler(func(string) error { return nil })

	for range 5 {
		if err := wsConn.WriteControl(websocket.PongMessage, []byte("pong"), time.Now().Add(time.Second)); err != nil {
			t.Fatalf("WriteControl(Pong): %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := wsConn.WriteMessage(websocket.TextMessage, []byte("not binary")); err != nil {
		t.Fatalf("WriteMessage(TextMessage): %v", err)
	}
	wsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, err = wsConn.ReadMessage()
	if !websocket.IsCloseError(err, websocket.CloseUnsupportedData) {
		t.Errorf("ReadMessage after TextMessage: err = %v, want CloseUnsupportedData (1003)", err)
	}
}

func TestCheckRequestHostAndOpaqueURI(t *testing.T) {
	be := &Backend{
		ServerNames: Strings{"http.example.com"},
		recordEvent: func(string) {},
	}
	ctx := context.WithValue(context.Background(), connCtxKey, mockConn{
		annotations: map[string]any{
			serverNameKey: "http.example.com",
		},
	})

	// 1. Opaque URL must be rejected with 400 Bad Request.
	reqOpaque, err := http.NewRequestWithContext(ctx, "GET", "http://http.example.com/ok", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	reqOpaque.URL.Opaque = "//evil.example.com/admin"
	w := httptest.NewRecorder()
	if be.checkRequestHost(w, reqOpaque) {
		t.Errorf("checkRequestHost accepted request with non-empty URL.Opaque")
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("Opaque URL status = %d, want 400", w.Code)
	}

	// 2. Mismatched req.URL.Host and req.Host must be rejected with 400 Bad Request.
	reqMismatch, err := http.NewRequestWithContext(ctx, "GET", "http://evil.example.com/ok", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	reqMismatch.Host = "http.example.com"
	w = httptest.NewRecorder()
	if be.checkRequestHost(w, reqMismatch) {
		t.Errorf("checkRequestHost accepted request with mismatched URL.Host and Host")
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("Mismatched URL.Host status = %d, want 400", w.Code)
	}

	// 3. Relative path (not starting with '/') must be rejected with 400 Bad Request.
	reqRel, err := http.NewRequestWithContext(ctx, "GET", "http://http.example.com/ok", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	reqRel.URL.Host = ""
	reqRel.URL.Path = "relative/path"
	w = httptest.NewRecorder()
	if be.checkRequestHost(w, reqRel) {
		t.Errorf("checkRequestHost accepted request with non-slash URL.Path")
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("Relative path status = %d, want 400", w.Code)
	}

	// 4. OPTIONS * must be accepted.
	reqOpt, err := http.NewRequestWithContext(ctx, "OPTIONS", "http://http.example.com/*", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	reqOpt.URL.Host = ""
	reqOpt.URL.Path = ""
	reqOpt.RequestURI = "*"
	w = httptest.NewRecorder()
	if !be.checkRequestHost(w, reqOpt) {
		t.Errorf("checkRequestHost rejected valid OPTIONS * request (code=%d)", w.Code)
	}
}

func TestBWLimitConfigAndOneSided(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	extCA, err := certmanager.New("root-ca.example.com", t.Logf)
	if err != nil {
		t.Fatalf("certmanager.New: %v", err)
	}

	// Negative Ingress must be rejected by Config.Check().
	badCfg := &Config{
		HTTPAddr: newPtr("localhost:0"),
		TLSAddr:  newPtr("localhost:0"),
		CacheDir: newPtr(t.TempDir()),
		BWLimits: []*BWLimit{
			{Name: "neg", Ingress: -1, Egress: 1000},
		},
	}
	if err := badCfg.Check(); err == nil {
		t.Errorf("Config.Check() accepted negative BWLimit.Ingress")
	}

	// One-sided BWLimit (Ingress: 0, Egress: 1000000) must leave ingress nil and set egress non-nil.
	cfg := &Config{
		HTTPAddr: newPtr("localhost:0"),
		TLSAddr:  newPtr("localhost:0"),
		CacheDir: newPtr(t.TempDir()),
		MaxOpen:  newPtr(100),
		BWLimits: []*BWLimit{
			{Name: "egress-only", Ingress: 0, Egress: 1000000},
		},
		Backends: []*Backend{
			{
				ServerNames: Strings{"local.example.com"},
				Mode:        "LOCAL",
				BWLimit:     "egress-only",
			},
		},
	}
	proxy := newTestProxy(cfg, extCA)
	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}
	defer proxy.Stop()

	grp := proxy.bwLimits["egress-only"]
	if grp == nil {
		t.Fatalf("bwLimits[\"egress-only\"] is nil")
	}
	if grp.ingress != nil {
		t.Errorf("grp.ingress = %v, want nil when Ingress is 0", grp.ingress)
	}
	if grp.egress == nil {
		t.Errorf("grp.egress is nil, want non-nil when Egress > 0")
	}
}

type bufferedTestConn struct {
	net.Conn
	r io.Reader
}

func (c *bufferedTestConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

type closeCallbackReadCloser struct {
	io.ReadCloser
	onClose func()
	once    sync.Once
}

func (c *closeCallbackReadCloser) Close() error {
	err := c.ReadCloser.Close()
	c.once.Do(c.onClose)
	return err
}

func h2TransportSupportsExtendedConnect() bool {
	probeErr := errors.New("dial-probe")
	tr := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(context.Context, string, string, *tls.Config) (net.Conn, error) {
			return nil, probeErr
		},
	}
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Scheme: "http", Host: "127.0.0.1:1", Path: "/"},
		Header: http.Header{":protocol": {"websocket"}},
	}
	_, err := tr.RoundTrip(req)
	return !isH2TransportProtocolHeaderUnsupported(err)
}

// doH2Connect performs a raw HTTP/2 CONNECT (regular when path == "" and
// extProto == "", or RFC 8441 Extended CONNECT otherwise) using http2.Framer so
// tests work even on Go 1.27 where net/http.Transport rejects ":protocol".
func doH2Connect(t *testing.T, tlsAddr string, extCA *certmanager.CertManager, serverName, path, extProto string, extraHeaders http.Header, reqBody io.Reader) (*http.Response, error) {
	t.Helper()
	conn, err := tls.Dial("tcp", tlsAddr, &tls.Config{
		ServerName: serverName,
		RootCAs:    extCA.RootCACertPool(),
		NextProtos: []string{"h2"},
	})
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		conn.Close()
		return nil, err
	}

	fr := http2.NewFramer(conn, conn)
	var wmu sync.Mutex
	wmu.Lock()
	err = fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})
	if err == nil {
		err = fr.WriteWindowUpdate(0, 1<<20)
	}
	wmu.Unlock()
	if err != nil {
		conn.Close()
		return nil, err
	}

	settingsCh := make(chan bool, 1)
	respCh := make(chan *http.Response, 1)
	errCh := make(chan error, 1)
	pr, pw := io.Pipe()

	go func() {
		var gotServerSettings bool
		var sentResp bool
		respHdr := make(http.Header)
		var statusCode int
		dec := hpack.NewDecoder(4096, func(f hpack.HeaderField) {
			if f.Name == ":status" {
				statusCode, _ = strconv.Atoi(f.Value)
				return
			}
			if !strings.HasPrefix(f.Name, ":") {
				respHdr.Add(f.Name, f.Value)
			}
		})
		var hdrBuf bytes.Buffer

		for {
			f, err := fr.ReadFrame()
			if err != nil {
				if !sentResp {
					select {
					case errCh <- err:
					default:
					}
				}
				pw.CloseWithError(err)
				return
			}
			switch f := f.(type) {
			case *http2.SettingsFrame:
				if f.IsAck() {
					continue
				}
				wmu.Lock()
				_ = fr.WriteSettingsAck()
				wmu.Unlock()
				if !gotServerSettings {
					gotServerSettings = true
					var extAllowed bool
					f.ForeachSetting(func(s http2.Setting) error {
						if s.ID == http2.SettingEnableConnectProtocol && s.Val == 1 {
							extAllowed = true
						}
						return nil
					})
					settingsCh <- extAllowed
				}
			case *http2.PingFrame:
				if !f.IsAck() {
					wmu.Lock()
					_ = fr.WritePing(true, f.Data)
					wmu.Unlock()
				}
			case *http2.HeadersFrame:
				if f.StreamID != 1 {
					continue
				}
				hdrBuf.Write(f.HeaderBlockFragment())
				if f.HeadersEnded() {
					if _, err := dec.Write(hdrBuf.Bytes()); err != nil {
						select {
						case errCh <- err:
						default:
						}
						pw.CloseWithError(err)
						return
					}
					_ = dec.Close()
					sentResp = true
					respCh <- &http.Response{
						StatusCode: statusCode,
						Header:     respHdr,
						Body: &closeCallbackReadCloser{
							ReadCloser: pr,
							onClose:    func() { _ = conn.Close() },
						},
					}
					if f.StreamEnded() {
						pw.Close()
						return
					}
				}
			case *http2.ContinuationFrame:
				if f.StreamID != 1 {
					continue
				}
				hdrBuf.Write(f.HeaderBlockFragment())
				if f.HeadersEnded() {
					if _, err := dec.Write(hdrBuf.Bytes()); err != nil {
						select {
						case errCh <- err:
						default:
						}
						pw.CloseWithError(err)
						return
					}
					_ = dec.Close()
					sentResp = true
					respCh <- &http.Response{
						StatusCode: statusCode,
						Header:     respHdr,
						Body: &closeCallbackReadCloser{
							ReadCloser: pr,
							onClose:    func() { _ = conn.Close() },
						},
					}
				}
			case *http2.DataFrame:
				if f.StreamID != 1 {
					continue
				}
				data := append([]byte(nil), f.Data()...)
				if len(data) > 0 {
					wmu.Lock()
					_ = fr.WriteWindowUpdate(0, uint32(len(data)))
					_ = fr.WriteWindowUpdate(1, uint32(len(data)))
					wmu.Unlock()
					if _, err := pw.Write(data); err != nil {
						return
					}
				}
				if f.StreamEnded() {
					pw.Close()
					return
				}
			case *http2.RSTStreamFrame:
				if f.StreamID == 1 {
					rerr := fmt.Errorf("RST_STREAM: %v", f.ErrCode)
					if !sentResp {
						select {
						case errCh <- rerr:
						default:
						}
					}
					pw.CloseWithError(rerr)
					return
				}
			}
		}
	}()

	select {
	case extAllowed := <-settingsCh:
		if extProto != "" && !extAllowed {
			conn.Close()
			return nil, errors.New("server did not advertise SETTINGS_ENABLE_CONNECT_PROTOCOL=1")
		}
	case err := <-errCh:
		conn.Close()
		return nil, err
	case <-time.After(5 * time.Second):
		conn.Close()
		return nil, errors.New("timeout waiting for HTTP/2 server SETTINGS")
	}

	var hbuf bytes.Buffer
	enc := hpack.NewEncoder(&hbuf)
	_ = enc.WriteField(hpack.HeaderField{Name: ":method", Value: http.MethodConnect})
	if extProto != "" {
		_ = enc.WriteField(hpack.HeaderField{Name: ":protocol", Value: extProto})
	}
	if path != "" {
		_ = enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
		_ = enc.WriteField(hpack.HeaderField{Name: ":authority", Value: serverName})
		_ = enc.WriteField(hpack.HeaderField{Name: ":path", Value: path})
	} else {
		_ = enc.WriteField(hpack.HeaderField{Name: ":authority", Value: serverName})
	}
	for k, vv := range extraHeaders {
		lk := strings.ToLower(k)
		for _, v := range vv {
			_ = enc.WriteField(hpack.HeaderField{Name: lk, Value: v})
		}
	}

	wmu.Lock()
	err = fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: hbuf.Bytes(),
		EndHeaders:    true,
		EndStream:     reqBody == nil,
	})
	wmu.Unlock()
	if err != nil {
		conn.Close()
		return nil, err
	}

	if reqBody != nil {
		go func() {
			buf := make([]byte, 16384)
			for {
				n, rerr := reqBody.Read(buf)
				if n > 0 {
					wmu.Lock()
					werr := fr.WriteData(1, false, buf[:n])
					wmu.Unlock()
					if werr != nil {
						return
					}
				}
				if rerr != nil {
					if rerr == io.EOF {
						wmu.Lock()
						_ = fr.WriteData(1, true, nil)
						wmu.Unlock()
					}
					return
				}
			}
		}()
	}

	select {
	case resp := <-respCh:
		return resp, nil
	case err := <-errCh:
		conn.Close()
		return nil, err
	case <-time.After(5 * time.Second):
		conn.Close()
		return nil, errors.New("timeout waiting for HTTP/2 response headers")
	}
}

func buildMaskedWSFrame(opcode byte, payload []byte) []byte {
	var b bytes.Buffer
	b.WriteByte(0x80 | opcode)
	n := len(payload)
	switch {
	case n < 126:
		b.WriteByte(0x80 | byte(n))
	case n <= 65535:
		b.WriteByte(0x80 | 126)
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(n))
		b.Write(ext[:])
	default:
		b.WriteByte(0x80 | 127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(n))
		b.Write(ext[:])
	}
	mask := [4]byte{0x12, 0x34, 0x56, 0x78}
	b.Write(mask[:])
	masked := make([]byte, n)
	for i := range payload {
		masked[i] = payload[i] ^ mask[i&3]
	}
	b.Write(masked)
	return b.Bytes()
}

func readUnmaskedWSFrame(r io.Reader) (opcode byte, payload []byte, err error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	opcode = hdr[0] & 0x0f
	if hdr[1]&0x80 != 0 {
		return 0, nil, fmt.Errorf("unexpected masked server frame")
	}
	length := uint64(hdr[1] & 0x7f)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	payload = make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return opcode, payload, nil
}

func readWSDataBytes(r io.Reader, want int) ([]byte, error) {
	var out []byte
	for len(out) < want {
		op, payload, err := readUnmaskedWSFrame(r)
		if err != nil {
			return out, err
		}
		switch op {
		case websocket.BinaryMessage, websocket.TextMessage, 0:
			out = append(out, payload...)
		case websocket.PingMessage, websocket.PongMessage:
			continue
		default:
			return out, fmt.Errorf("unexpected opcode %d", op)
		}
	}
	return out, nil
}

func TestExtendedConnect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	extCA, err := certmanager.New("root-ca.example.com", t.Logf)
	if err != nil {
		t.Fatalf("certmanager.New: %v", err)
	}

	// Config validation check for BackendProto.
	{
		badProtoCfg := &Config{
			HTTPAddr: newPtr("localhost:0"),
			TLSAddr:  newPtr("localhost:0"),
			CacheDir: newPtr(t.TempDir()),
			Backends: []*Backend{
				{
					ServerNames:  Strings{"http.example.com"},
					Mode:         "HTTP",
					BackendProto: newPtr("invalid-proto"),
					Addresses:    Strings{"localhost:1234"},
				},
			},
		}
		if err := badProtoCfg.Check(); err == nil {
			t.Errorf("Config.Check() accepted invalid BackendProto")
		}
	}

	// TCP echo server for local WebSocket endpoint.
	tcpListener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer tcpListener.Close()
	go func() {
		for {
			c, err := tcpListener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()

	// HTTP/2 backend server that echoes Extended CONNECT streams.
	h2BackendLn, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer h2BackendLn.Close()
	h2Protocols := new(http.Protocols)
	h2Protocols.SetUnencryptedHTTP2(true)
	h2Srv := &http.Server{
		Protocols: h2Protocols,
		// Go 1.28+: HTTP2: &http.HTTP2Config{EnableConnectProtocol: true},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if req.Method != http.MethodConnect || req.Header.Get(":protocol") == "" {
				http.Error(w, "not extended connect", http.StatusBadRequest)
				return
			}
			w.Header().Set("X-Backend-Protocol", req.Header.Get(":protocol"))
			w.Header().Set("X-Got-XFF", req.Header.Get("X-Forwarded-For"))
			w.Header().Set("X-Got-Via", req.Header.Get("Via"))
			w.WriteHeader(http.StatusOK)
			rc := http.NewResponseController(w)
			rc.Flush()
			buf := make([]byte, 4096)
			for {
				n, err := req.Body.Read(buf)
				if n > 0 {
					w.Write(buf[:n])
					rc.Flush()
				}
				if err != nil {
					return
				}
			}
		}),
	}
	go h2Srv.Serve(h2BackendLn)
	defer h2Srv.Close()

	// HTTP/1.1 + HTTP/2 (without Extended CONNECT) backend server that serves HTTP/1.1 WebSockets.
	h1WSRawLn, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer h1WSRawLn.Close()
	h1ConnCh := make(chan net.Conn, 16)
	defer close(h1ConnCh)
	go func() {
		for {
			c, err := h1WSRawLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				br := bufio.NewReader(c)
				peek, err := br.Peek(4)
				if err != nil {
					c.Close()
					return
				}
				if bytes.Equal(peek, []byte("PRI ")) {
					defer c.Close()
					preface := make([]byte, len(http2.ClientPreface))
					if _, err := io.ReadFull(br, preface); err != nil || string(preface) != http2.ClientPreface {
						return
					}
					fr := http2.NewFramer(c, br)
					// Advertise empty SETTINGS (without ENABLE_CONNECT_PROTOCOL).
					if err := fr.WriteSettings(); err != nil {
						return
					}
					for {
						f, err := fr.ReadFrame()
						if err != nil {
							return
						}
						if sf, ok := f.(*http2.SettingsFrame); ok && !sf.IsAck() {
							_ = fr.WriteSettingsAck()
						}
					}
				}
				select {
				case h1ConnCh <- &bufferedTestConn{Conn: c, r: br}:
				case <-ctx.Done():
					c.Close()
				}
			}(c)
		}
	}()
	wsUpgrader := &websocket.Upgrader{
		Subprotocols: []string{"chat-v1"},
		CheckOrigin:  func(*http.Request) bool { return true },
	}
	h1WSSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if req.URL.Path == "/denied" {
				http.Error(w, "denied", http.StatusForbidden)
				return
			}
			_ = wsUpgrader.Serve(w, req, http.Header{"X-WS-XFF": []string{req.Header.Get("X-Forwarded-For")}}, func(c *websocket.Conn) {
				for {
					mt, msg, err := c.ReadMessage()
					if err != nil {
						return
					}
					if err := c.WriteMessage(mt, msg); err != nil {
						return
					}
				}
			})
		}),
	}
	go h1WSSrv.Serve(&proxyListener{ch: h1ConnCh, closedCh: make(chan struct{})})
	defer h1WSSrv.Close()

	proxy := newTestProxy(
		&Config{
			HTTPAddr: newPtr("localhost:0"),
			TLSAddr:  newPtr("localhost:0"),
			CacheDir: newPtr(t.TempDir()),
			MaxOpen:  newPtr(100),
			WebSockets: []*WebSocketConfig{
				{
					Endpoint: "https://enabled.example.com/ws",
					Address:  tcpListener.Addr().String(),
				},
				{
					Endpoint: "https://h1only.example.com/ws",
					Address:  tcpListener.Addr().String(),
				},
			},
			Backends: []*Backend{
				{
					ServerNames:  Strings{"enabled.example.com"},
					Mode:         "HTTP",
					BackendProto: newPtr("h2"),
					Addresses:    Strings{h2BackendLn.Addr().String()},
				},
				{
					ServerNames:  Strings{"h1only.example.com"},
					Mode:         "HTTP",
					ALPNProtos:   &Strings{"http/1.1"},
					BackendProto: newPtr("h2"),
					Addresses:    Strings{h2BackendLn.Addr().String()},
				},
				{
					ServerNames:  Strings{"h1backend.example.com"},
					Mode:         "HTTP",
					BackendProto: newPtr("http/1.1"),
					Addresses:    Strings{h1WSRawLn.Addr().String()},
				},
				{
					ServerNames:  Strings{"h2noext.example.com"},
					Mode:         "HTTP",
					BackendProto: newPtr("h2"),
					Addresses:    Strings{h1WSRawLn.Addr().String()},
				},
			},
		},
		extCA,
	)
	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}
	defer proxy.Stop()

	proxyTLSAddr := proxy.listener.Addr().String()
	h2ClientSupportsExt := h2TransportSupportsExtendedConnect()

	// 1. Full-duplex interactive HTTP/2 Extended CONNECT forwarded to h2 backend (with XFF & Via)
	// when the runtime's HTTP/2 client supports ":protocol" (Go 1.28+ or -tags http2legacy),
	// or 501 Not Implemented on Go 1.27 stdlib net/http.Transport.
	{
		pr, pw := io.Pipe()
		defer pr.Close()
		defer pw.Close()
		resp, err := doH2Connect(t, proxyTLSAddr, extCA, "enabled.example.com", "/ext", "custom-proto", nil, pr)
		if err != nil {
			t.Fatalf("doH2Connect: %v", err)
		}
		defer resp.Body.Close()
		if !h2ClientSupportsExt {
			if resp.StatusCode != http.StatusNotImplemented {
				t.Fatalf("h2 extended CONNECT status on Go 1.27 = %d, want 501", resp.StatusCode)
			}
		} else {
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("h2 extended CONNECT status = %d, want 200", resp.StatusCode)
			}
			if got := resp.Header.Get("X-Backend-Protocol"); got != "custom-proto" {
				t.Errorf("X-Backend-Protocol = %q, want custom-proto", got)
			}
			if got := resp.Header.Get("X-Got-XFF"); got == "" {
				t.Errorf("X-Got-XFF is empty, want client IP")
			}
			if got := resp.Header.Get("X-Got-Via"); !strings.HasPrefix(got, "HTTP/2.0 ") {
				t.Errorf("X-Got-Via = %q, want prefix 'HTTP/2.0 '", got)
			}
			for _, msg := range []string{"chunk-1", "chunk-2", "chunk-3"} {
				if _, err := pw.Write([]byte(msg)); err != nil {
					t.Fatalf("pw.Write: %v", err)
				}
				got := make([]byte, len(msg))
				if _, err := io.ReadFull(resp.Body, got); err != nil {
					t.Fatalf("io.ReadFull: %v", err)
				}
				if string(got) != msg {
					t.Errorf("echo = %q, want %q", got, msg)
				}
			}
		}
		pw.Close()
	}

	// 2. HTTP/2 Extended CONNECT to local WebSocket endpoint with >100 KB payload (verifying no MaxBytesReader cap).
	{
		pr, pw := io.Pipe()
		defer pr.Close()
		defer pw.Close()
		resp, err := doH2Connect(t, proxyTLSAddr, extCA, "enabled.example.com", "/ws", "websocket", http.Header{
			"Sec-Websocket-Version": {"13"},
		}, pr)
		if err != nil {
			t.Fatalf("h2 ws doH2Connect: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("h2 ws CONNECT status = %d, want 200", resp.StatusCode)
		}

		largePayload := bytes.Repeat([]byte("A"), 150*1024)
		go func() {
			_, _ = pw.Write(buildMaskedWSFrame(websocket.BinaryMessage, largePayload))
		}()
		echoed, err := readWSDataBytes(resp.Body, len(largePayload))
		if err != nil {
			t.Fatalf("readWSDataBytes (>100KB local H2 WS): %v", err)
		}
		if !bytes.Equal(echoed, largePayload) {
			t.Errorf("echoed len = %d, want %d", len(echoed), len(largePayload))
		}
		pw.Close()
	}

	// 3. Regular HTTP/2 CONNECT (405) and malformed :protocol="HTTP/1.1" (400).
	{
		resp, err := doH2Connect(t, proxyTLSAddr, extCA, "enabled.example.com", "", "", nil, nil)
		if err != nil {
			t.Fatalf("regular CONNECT doH2Connect: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("regular CONNECT status = %d, want 405", resp.StatusCode)
		}

		badResp, err := doH2Connect(t, proxyTLSAddr, extCA, "enabled.example.com", "/ext", "HTTP/1.1", nil, nil)
		if err != nil {
			t.Fatalf("bad :protocol doH2Connect: %v", err)
		}
		badResp.Body.Close()
		if badResp.StatusCode != http.StatusBadRequest {
			t.Errorf("malformed :protocol='HTTP/1.1' status = %d, want 400", badResp.StatusCode)
		}
	}

	// 4. Setting ALPNProtos to ["http/1.1"] disables h2 while HTTP/1.1 WebSocket works as usual.
	{
		if c, err := tls.Dial("tcp", proxyTLSAddr, &tls.Config{
			ServerName: "h1only.example.com",
			RootCAs:    extCA.RootCACertPool(),
			NextProtos: []string{"h2"},
		}); err == nil {
			c.Close()
			t.Errorf("expected TLS ALPN error for h2 on h1only.example.com, got nil")
		}

		dialer := websocket.Dialer{
			NetDialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return tls.Dial(network, proxyTLSAddr, &tls.Config{
					ServerName: "h1only.example.com",
					RootCAs:    extCA.RootCACertPool(),
					NextProtos: []string{"http/1.1"},
				})
			},
		}
		wsConn, resp, err := dialer.DialContext(ctx, "wss://h1only.example.com/ws", nil)
		if err != nil {
			t.Fatalf("h1 ws DialContext on h1only backend: %v", err)
		}
		resp.Body.Close()
		wsConn.Close()
	}

	// 5. Dynamic conversion of Extended CONNECT :protocol=websocket to HTTP/1.1 WebSocket
	// (both when BackendProto=="http/1.1" and when BackendProto=="h2" without upstream Extended CONNECT),
	// while non-websocket Extended CONNECT to http/1.1 backend still returns 501.
	for _, host := range []string{"h1backend.example.com", "h2noext.example.com"} {
		pr, pw := io.Pipe()
		resp, err := doH2Connect(t, proxyTLSAddr, extCA, host, "/chat", "websocket", http.Header{
			"Sec-Websocket-Version":  {"13"},
			"Sec-Websocket-Protocol": {"other, chat-v1"},
		}, pr)
		if err != nil {
			pr.Close()
			pw.Close()
			t.Fatalf("%s ws doH2Connect: %v", host, err)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			pr.Close()
			pw.Close()
			t.Fatalf("%s ws status = %d, want 200", host, resp.StatusCode)
		}
		if got := resp.Header.Get("Sec-Websocket-Protocol"); got != "chat-v1" {
			t.Errorf("%s Sec-Websocket-Protocol = %q, want chat-v1", host, got)
		}
		if got := resp.Header.Get("Sec-Websocket-Accept"); got != "" {
			t.Errorf("%s leaked HTTP/1.1 Sec-Websocket-Accept = %q", host, got)
		}
		if got := resp.Header.Get("X-WS-XFF"); got == "" {
			t.Errorf("%s X-WS-XFF is empty, want client IP", host)
		}

		payload := bytes.Repeat([]byte("W"), 120*1024)
		go func() {
			_, _ = pw.Write(buildMaskedWSFrame(websocket.TextMessage, payload))
		}()
		op, gotPayload, err := readUnmaskedWSFrame(resp.Body)
		if err != nil {
			t.Fatalf("%s readUnmaskedWSFrame: %v", host, err)
		}
		if op != websocket.TextMessage || !bytes.Equal(gotPayload, payload) {
			t.Errorf("%s echoed op=%d len=%d, want TextMessage len=%d", host, op, len(gotPayload), len(payload))
		}
		pw.Close()
		resp.Body.Close()
		pr.Close()

		// Non-101 response from HTTP/1.1 backend propagates status cleanly.
		deniedResp, err := doH2Connect(t, proxyTLSAddr, extCA, host, "/denied", "websocket", http.Header{
			"Sec-Websocket-Version": {"13"},
		}, nil)
		if err != nil {
			t.Fatalf("%s /denied doH2Connect: %v", host, err)
		}
		deniedResp.Body.Close()
		if deniedResp.StatusCode != http.StatusForbidden {
			t.Errorf("%s /denied status = %d, want 403", host, deniedResp.StatusCode)
		}
	}

	{
		resp, err := doH2Connect(t, proxyTLSAddr, extCA, "h1backend.example.com", "/ext", "custom-proto", nil, nil)
		if err != nil {
			t.Fatalf("h1backend doH2Connect: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotImplemented {
			t.Errorf("h1backend non-websocket extended CONNECT status = %d, want 501", resp.StatusCode)
		}
	}
}
