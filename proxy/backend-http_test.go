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
	"context"
	"net"
	"net/http"
	"strings"
	"testing"

	jwt "github.com/golang-jwt/jwt/v5"

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
