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
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
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
