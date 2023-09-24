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
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/c2FmZQ/storage"
	"github.com/c2FmZQ/storage/crypto"
	jwt "github.com/golang-jwt/jwt/v5"

	"github.com/c2FmZQ/tlsproxy/certmanager"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/oidc"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/tokenmanager"
)

func TestSSOEnforce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	idp := newIDPServer(t)
	defer idp.Close()

	ca, err := certmanager.New("root-ca.example.com", t.Logf)
	if err != nil {
		t.Fatalf("certmanager.New: %v", err)
	}
	be := newHTTPServer(t, ctx, "https-server", ca)

	proxy := newTestProxy(
		&Config{
			HTTPAddr: "localhost:0",
			TLSAddr:  "localhost:0",
			CacheDir: t.TempDir(),
			MaxOpen:  100,
			OIDCProviders: []*ConfigOIDC{
				{
					Name:          "test-idp",
					AuthEndpoint:  idp.URL + "/authorization",
					TokenEndpoint: idp.URL + "/token",
					RedirectURL:   "https://oauth2.example.com/redirect",
					ClientID:      "CLIENTID",
					ClientSecret:  "CLIENTSECRET",
					Domain:        "example.com",
				},
			},
			Backends: []*Backend{
				{
					ServerNames: []string{
						"https.example.com",
					},
					Mode: "HTTPS",
					Addresses: []string{
						be.String(),
					},
					ForwardServerName: "https-server",
					ForwardRateLimit:  1000,
					ForwardRootCAs:    ca.RootCAPEM(),
					SSO: &BackendSSO{
						Provider:         "test-idp",
						GenerateIDTokens: true,
					},
				},
				{
					ServerNames: []string{
						"oauth2.example.com",
					},
					Mode:             "HTTPS",
					ForwardRateLimit: 1000,
					SSO: &BackendSSO{
						Provider: "test-idp",
					},
				},
			},
		},
		ca,
	)
	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}

	get := func(urlToGet string, hdr http.Header) (int, string, map[string]string) {
		u, err := url.Parse(urlToGet)
		if err != nil {
			t.Fatalf("%q: %v", urlToGet, err)
		}
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{
			RootCAs: ca.RootCACertPool(),
		}
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			if strings.Contains(addr, "example.com") {
				return d.DialContext(ctx, "tcp", proxy.listener.Addr().String())
			}
			return d.DialContext(ctx, network, addr)
		}
		jar, err := cookiejar.New(nil)
		if err != nil {
			t.Fatalf("cookiejar: %v", err)
		}
		client := http.Client{
			Transport: transport,
			Jar:       jar,
		}
		req := &http.Request{
			Method: "GET",
			URL:    u,
			Host:   u.Host,
		}
		if hdr != nil {
			req.Header = hdr
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: get failed: %v", urlToGet, err)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("%s: body read: %v", urlToGet, err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Fatalf("%s: body close: %v", urlToGet, err)
		}
		cookies := make(map[string]string)
		log.Printf("COOKIES:")
		for _, c := range jar.Cookies(u) {
			if c.Name == "TLSPROXYAUTH" || c.Name == "TLSPROXYIDTOKEN" {
				cookies[c.Name] = c.Value
			}
			log.Printf("  %s: %s\n", c.Name, c.Value)
		}
		return resp.StatusCode, string(body), cookies
	}

	code, body, cookies := get("https://https.example.com/blah", nil)
	if got, want := code, 200; got != want {
		t.Errorf("Code = %v, want %v", got, want)
	}
	if got, want := body, "[https-server] /blah\n"; got != want {
		t.Errorf("Body = %v, want %v", got, want)
	}
	if got, want := len(cookies), 2; got != want {
		t.Errorf("len(cookies) = %v, want %v", got, want)
	}

	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer "+cookies["TLSPROXYIDTOKEN"])
	code, body, cookies = get("https://https.example.com/blah", hdr)
	if got, want := code, 200; got != want {
		t.Errorf("Code = %v, want %v", got, want)
	}
	if got, want := body, "[https-server] /blah\n"; got != want {
		t.Errorf("Body = %v, want %v", got, want)
	}
	if got, want := len(cookies), 0; got != want {
		t.Errorf("len(cookies) = %v, want %v", got, want)
	}
}

type testEventRecorder struct {
	events []string
}

func (er *testEventRecorder) record(e string) {
	er.events = append(er.events, e)
}

type idpServer struct {
	*httptest.Server
	t          *testing.T
	oidcServer *oidc.ProviderServer
}

func newIDPServer(t *testing.T) *idpServer {
	dir := t.TempDir()
	mk, err := crypto.CreateAESMasterKeyForTest()
	if err != nil {
		t.Fatalf("crypto.CreateMasterKey: %v", err)
	}
	store := storage.New(dir, mk)
	tm, err := tokenmanager.New(store)
	if err != nil {
		t.Fatalf("tokenmanager.New: %v", err)
	}
	opts := oidc.ServerOptions{
		TokenManager: tm,
		Issuer:       "https://idp.example.com",
		ClaimsFromCtx: func(context.Context) jwt.Claims {
			return jwt.MapClaims{
				"sub": "bob@example.com",
			}
		},
		Clients: []oidc.Client{
			{ID: "CLIENTID", Secret: "CLIENTSECRET", RedirectURI: []string{"https://oauth2.example.com/redirect"}},
		},
		EventRecorder: eventRecorder{record: func(string) {}},
	}

	idp := &idpServer{
		t:          t,
		oidcServer: oidc.NewServer(opts),
	}
	mux := http.NewServeMux()
	log := func(next http.HandlerFunc) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			t.Logf("[IDP SERVER] %s %s", req.Method, req.RequestURI)
			req.ParseForm()
			for k, v := range req.Form {
				t.Logf("[IDP SERVER]  %s: %v", k, v)
			}
			next.ServeHTTP(w, req)
		})
	}
	mux.Handle("/.well-known/openid-configuration", log(idp.oidcServer.ServeConfig))
	mux.Handle("/authorization", log(idp.oidcServer.ServeAuthorization))
	mux.Handle("/token", log(idp.oidcServer.ServeToken))
	mux.Handle("/jwks", log(tm.ServeJWKS))
	idp.Server = httptest.NewServer(mux)
	return idp
}
