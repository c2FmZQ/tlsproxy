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
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"

	"github.com/c2FmZQ/tlsproxy/proxy/internal/netw"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/tokenmanager"
)

func TestAuthenticateUser(t *testing.T) {
	proxy := newBackendSSOTestProxy(t)

	// No auth token.
	req := httptest.NewRequest("GET", "https://example.com/", nil)
	req.Header.Set("x-tlsproxy-user-id", "imposter")
	w := httptest.NewRecorder()

	if cont := proxy.cfg.Backends[0].authenticateUser(w, &req); !cont {
		t.Fatal("authenticateUser() = false")
	}
	if req.Header.Get("x-tlsproxy-user-id") != "" {
		t.Fatalf("request has x-tlsproxy-user-id")
	}
	if c := claimsFromCtx(req.Context()); c != nil {
		t.Fatalf("claimsFromCtx() = %v", c)
	}

	// Add a valid auth token.
	if err := setAuthCookie(req, "bob@", "example.com", "https://example.com/", proxy.tokenManager); err != nil {
		t.Fatalf("setAuthCookie: %v", err)
	}

	// With GenerateIDTokens = false, we expect the header and claims to be set.
	proxy.cfg.Backends[0].SSO.GenerateIDTokens = false
	w = httptest.NewRecorder()
	if got, want := proxy.cfg.Backends[0].authenticateUser(w, &req), true; got != want {
		t.Fatalf("authenticateUser() = %v, want %v", got, want)
	}
	if got, want := req.Header.Get("x-tlsproxy-user-id"), "bob@"; got != want {
		t.Errorf("x-tlsproxy-user-id = %q, want %q", got, want)
	}
	if c := claimsFromCtx(req.Context()); c == nil || c["email"] != "bob@" {
		t.Fatalf("claimsFromCtx() = %v", c)
	}
	if got, want := w.Code, 200; got != want {
		t.Errorf("response code = %d, want %d", got, want)
	}

	// With GenerateIDTokens = true, we expect a new ID cookie and a redirect.
	proxy.cfg.Backends[0].SSO.GenerateIDTokens = true
	w = httptest.NewRecorder()
	if got, want := proxy.cfg.Backends[0].authenticateUser(w, &req), false; got != want {
		t.Fatalf("authenticateUser() = %v, want %v", got, want)
	}
	if got, want := w.Code, 302; got != want {
		t.Errorf("response code = %d, want %d", got, want)
	}
	idCookie := w.Header().Get("set-cookie")
	if idCookie == "" {
		t.Fatal("no ID cookie in response")
	}

	// Add the ID token.
	req.Header.Set("Cookie", req.Header.Get("Cookie")+"; "+idCookie)
	w = httptest.NewRecorder()
	if got, want := proxy.cfg.Backends[0].authenticateUser(w, &req), true; got != want {
		t.Fatalf("authenticateUser() = %v, want %v", got, want)
	}
	if got, want := req.Header.Get("x-tlsproxy-user-id"), "bob@"; got != want {
		t.Errorf("x-tlsproxy-user-id = %q, want %q", got, want)
	}
	if c := claimsFromCtx(req.Context()); c == nil || c["email"] != "bob@" {
		t.Fatalf("claimsFromCtx() = %v", c)
	}
	if got, want := w.Code, 200; got != want {
		t.Errorf("response code = %d, want %d", got, want)
	}
}

func TestEnforceSSOPolicy(t *testing.T) {
	proxy := newBackendSSOTestProxy(t)

	req := httptest.NewRequest("GET", "https://example.com/", nil)
	conn := netw.NewConnForTest(testConn{})
	conn.SetAnnotation(serverNameKey, "example.com")

	ctx := context.Background()
	ctx = context.WithValue(ctx, authCtxKey, jwt.MapClaims{
		"email": "bob@example.org",
	})
	ctx = context.WithValue(ctx, connCtxKey, conn)

	req = req.WithContext(ctx)

	// No ACL
	proxy.cfg.Backends[0].SSO.Rules[0].ACL = nil
	w := httptest.NewRecorder()
	if got, want := proxy.cfg.Backends[0].enforceSSOPolicy(w, req), true; got != want {
		t.Fatalf("encorceSSOPolicy() = %v, want %v", got, want)
	}
	if got, want := w.Code, 200; got != want {
		t.Fatalf("response code = %d, want %d", got, want)
	}

	// bob not allowed.
	proxy.cfg.Backends[0].SSO.Rules[0].ACL = &Strings{
		"alice@example.org",
	}
	w = httptest.NewRecorder()
	if got, want := proxy.cfg.Backends[0].enforceSSOPolicy(w, req), false; got != want {
		t.Fatalf("encorceSSOPolicy() = %v, want %v", got, want)
	}
	if got, want := w.Code, 403; got != want {
		t.Fatalf("response code = %d, want %d", got, want)
	}

	// bob is allowed.
	proxy.cfg.Backends[0].SSO.Rules[0].ACL = &Strings{
		"alice@example.org",
		"bob@example.org",
	}
	w = httptest.NewRecorder()
	if got, want := proxy.cfg.Backends[0].enforceSSOPolicy(w, req), true; got != want {
		t.Fatalf("encorceSSOPolicy() = %v, want %v", got, want)
	}
	if got, want := w.Code, 200; got != want {
		t.Fatalf("response code = %d, want %d", got, want)
	}

	// bob's domain is allowed.
	proxy.cfg.Backends[0].SSO.Rules[0].ACL = &Strings{
		"@example.org",
	}
	w = httptest.NewRecorder()
	if got, want := proxy.cfg.Backends[0].enforceSSOPolicy(w, req), true; got != want {
		t.Fatalf("encorceSSOPolicy() = %v, want %v", got, want)
	}
	if got, want := w.Code, 200; got != want {
		t.Fatalf("response code = %d, want %d", got, want)
	}

	// ForceReAuth fail
	proxy.cfg.Backends[0].SSO.Rules[0].ForceReAuth = 5 * time.Minute
	w = httptest.NewRecorder()
	if got, want := proxy.cfg.Backends[0].enforceSSOPolicy(w, req), false; got != want {
		t.Fatalf("encorceSSOPolicy() = %v, want %v", got, want)
	}
	if got, want := w.Code, 403; got != want {
		t.Fatalf("response code = %d, want %d", got, want)
	}

	// ForceReAuth ok
	hh := sha256.Sum256([]byte("example.com"))
	ctx = context.WithValue(req.Context(), authCtxKey, jwt.MapClaims{
		"email": "bob@example.org",
		"hhash": hex.EncodeToString(hh[:]),
		"iat":   float64(time.Now().Unix()),
	})
	req = req.WithContext(ctx)
	w = httptest.NewRecorder()
	if got, want := proxy.cfg.Backends[0].enforceSSOPolicy(w, req), true; got != want {
		t.Errorf("encorceSSOPolicy() = %v, want %v", got, want)
	}
	if got, want := w.Code, 200; got != want {
		t.Fatalf("response code = %d, want %d", got, want)
	}
}

func newBackendSSOTestProxy(t *testing.T) *Proxy {
	return newTestProxy(
		&Config{
			HTTPAddr: newPtr("localhost:0"),
			TLSAddr:  newPtr("localhost:0"),
			CacheDir: newPtr(t.TempDir()),
			MaxOpen:  newPtr(100),
			OIDCProviders: []*ConfigOIDC{
				{
					Name:          "test-idp",
					AuthEndpoint:  "https://idp/authorization",
					TokenEndpoint: "https://idp/token",
					RedirectURL:   "https://example.com/redirect",
					ClientID:      "CLIENTID",
					ClientSecret:  "CLIENTSECRET",
					Domain:        "example.com",
				},
			},
			Backends: []*Backend{
				{
					ServerNames: []string{
						"example.com",
					},
					Mode: "LOCAL",
					SSO: &BackendSSO{
						Provider:         "test-idp",
						GenerateIDTokens: true,
						SetUserIDHeader:  true,
					},
				},
			},
		},
		nil,
	)
}

func setAuthCookie(req *http.Request, email, host, issuer string, tm *tokenmanager.TokenManager) error {
	hh := sha256.Sum256([]byte(host))
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iat":       now.Unix(),
		"exp":       now.Add(20 * time.Hour).Unix(),
		"iss":       issuer,
		"aud":       issuer,
		"sub":       "12345",
		"email":     email,
		"proxyauth": issuer,
		"provider":  "test-idp",
		"hhash":     hex.EncodeToString(hh[:]),
		"sid":       "abc123",
	}
	token, err := tm.CreateToken(claims, "" /* default */)
	if err != nil {
		return err
	}
	req.AddCookie(&http.Cookie{
		Name:     "TLSPROXYAUTH",
		Value:    token,
		Domain:   "example.com",
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
		HttpOnly: true,
	})
	return nil
}

type testConn struct {
}

func (testConn) Read(b []byte) (n int, err error) {
	return 0, io.EOF
}

func (testConn) Write(b []byte) (n int, err error) {
	return 0, io.EOF
}

func (testConn) Close() error {
	return nil
}

func (testConn) LocalAddr() net.Addr {
	return testAddr{}
}

func (testConn) RemoteAddr() net.Addr {
	return testAddr{}
}

func (testConn) SetDeadline(t time.Time) error {
	return nil
}

func (testConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (testConn) SetWriteDeadline(t time.Time) error {
	return nil
}

type testAddr struct {
}

func (testAddr) Network() string {
	return "test"
}

func (testAddr) String() string {
	return "12.34.56.78:90"
}
