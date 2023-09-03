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
	"net/url"
	"strings"
	"testing"

	"github.com/c2FmZQ/tlsproxy/certmanager"
)

func TestRedirectHostAndPort(t *testing.T) {
	er := &eventRecorder{}
	cfg := ConfigOIDC{
		AuthEndpoint:  "https://idp.example.com/auth",
		TokenEndpoint: "https://idp.example.com/token",
		RedirectURL:   "https://oauth2.example.org/redirect",
	}
	p, err := newOIDCProvider(cfg, er.record, nil)
	if err != nil {
		t.Fatalf("newOIDCProvider: %v", err)
	}

	host, path, err := p.callbackHostAndPath()
	if err != nil {
		t.Fatalf("callbackHostAndPath: %v", err)
	}
	if got, want := host, "oauth2.example.org"; got != want {
		t.Errorf("Host = %q, want %q", got, want)
	}
	if got, want := path, "/redirect"; got != want {
		t.Errorf("Host = %q, want %q", got, want)
	}
}

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
						Provider: "test-idp",
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

	get := func(urlToGet string) (int, string, bool) {
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
		var hasCookie bool
		log.Printf("COOKIES:")
		for _, c := range jar.Cookies(u) {
			if c.Name == "TLSPROXYAUTH" {
				hasCookie = true
			}
			log.Printf("  %s: %s\n", c.Name, c.Value)
		}
		return resp.StatusCode, string(body), hasCookie
	}

	code, body, hasCookie := get("https://https.example.com/blah")
	if got, want := code, 200; got != want {
		t.Errorf("Code = %v, want %v", got, want)
	}
	if got, want := body, "[https-server] /blah\n"; got != want {
		t.Errorf("Body = %v, want %v", got, want)
	}
	if got, want := hasCookie, true; got != want {
		t.Errorf("HasCookie = %v, want %v", got, want)
	}
}
