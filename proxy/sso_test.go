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
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	jwt "github.com/golang-jwt/jwt/v5"
	jwttest "github.com/golang-jwt/jwt/v5/test"

	"github.com/c2FmZQ/tlsproxy/certmanager"
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
					AuthEndpoint:  idp.URL + "/auth",
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

	get := func(urlToGet string) (int, string, map[string]string) {
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

	code, body, cookies := get("https://https.example.com/blah")
	if got, want := code, 200; got != want {
		t.Errorf("Code = %v, want %v", got, want)
	}
	if got, want := body, "[https-server] /blah\n"; got != want {
		t.Errorf("Body = %v, want %v", got, want)
	}
	if got, want := len(cookies), 2; got != want {
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
	t *testing.T

	mu    sync.Mutex
	codes map[string]string
}

func newIDPServer(t *testing.T) *idpServer {
	idp := &idpServer{
		t:     t,
		codes: make(map[string]string),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/auth", idp.auth)
	mux.HandleFunc("/token", idp.token)
	idp.Server = httptest.NewServer(mux)
	return idp
}

func (idp *idpServer) auth(w http.ResponseWriter, req *http.Request) {
	log.Printf("IDP %s %s", req.Method, req.RequestURI)
	idp.mu.Lock()
	defer idp.mu.Unlock()
	req.ParseForm()
	for _, v := range []string{"response_type", "client_id", "scope", "redirect_uri", "state", "nonce"} {
		log.Printf("IDP [/auth] %s: %s", v, req.Form.Get(v))
	}
	code := fmt.Sprintf("CODE-%d", len(idp.codes))
	idp.codes[code] = req.Form.Get("nonce")

	url := req.Form.Get("redirect_uri") + "?" +
		"code=" + url.QueryEscape(code) +
		"&state=" + url.QueryEscape(req.Form.Get("state"))
	log.Printf("IDP [/auth] redirect to %s", url)
	http.Redirect(w, req, url, http.StatusFound)
}

func (idp *idpServer) token(w http.ResponseWriter, req *http.Request) {
	log.Printf("IDP %s %s", req.Method, req.RequestURI)
	idp.mu.Lock()
	defer idp.mu.Unlock()
	req.ParseForm()
	for _, v := range []string{"code", "client_id", "client_secret", "redirect_uri", "grant_type"} {
		log.Printf("IDP [/token] %s: %s", v, req.PostForm.Get(v))
	}
	nonce := idp.codes[req.Form.Get("code")]

	var data struct {
		IDToken string `json:"id_token"`
	}
	token := jwttest.MakeSampleToken(
		jwt.MapClaims{
			"email":          "john@example.net",
			"email_verified": true,
			"nonce":          nonce,
		},
		jwt.SigningMethodHS256,
		[]byte("key"),
	)
	data.IDToken = token
	log.Printf("IDP [/token] Return %+v", data)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(data); err != nil {
		idp.t.Errorf("token encode: %v", err)
	}
}
