// MIT License
//
// Copyright (c) 2025 TTBT Enterprises LLC
// Copyright (c) 2025 Robin Thellend <rthellend@rthellend.com>
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
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/c2FmZQ/tlsproxy/certmanager"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/saml"
)

func TestSSOEnforceSAML(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ca, err := certmanager.New("root-ca.example.com", t.Logf)
	if err != nil {
		t.Fatalf("certmanager.New: %v", err)
	}

	idpCert, err := ca.GetCert("idp.example.com")
	if err != nil {
		t.Fatalf("ca.GetCert: %v", err)
	}

	idp := newSAMLIDPServer(t, *idpCert)
	defer idp.Close()

	be := newHTTPServer(t, ctx, "https-server", ca)

	proxy := newTestProxy(
		&Config{
			HTTPAddr: newPtr("localhost:0"),
			TLSAddr:  newPtr("localhost:0"),
			CacheDir: newPtr(t.TempDir()),
			MaxOpen:  newPtr(100),
			SAMLProviders: []*ConfigSAML{
				{
					Name:     "test-idp",
					SSOURL:   idp.URL,
					EntityID: "https.example.com",
					Certs:    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: idpCert.Certificate[0]})) + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: idpCert.Certificate[1]})),
					ACSURL:   "https://sso.example.com/saml/acs",
					Domain:   "example.com",
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
					ForwardRootCAs:    []string{ca.RootCAPEM()},
					SSO: &BackendSSO{
						Provider: "test-idp",
					},
				},
				{
					ServerNames: []string{
						"sso.example.com",
					},
					Mode: "HTTPS",
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
	defer proxy.Stop()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}

	get := func(urlToGet string, hdr http.Header, postBody []byte) (int, string, string) {
		if postBody == nil {
			t.Logf("GET(%q)", urlToGet)
		} else {
			t.Logf("POST(%q)", urlToGet)
		}
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{
			RootCAs: ca.RootCACertPool(),
		}
		var host string
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			host = addr
			var d net.Dialer
			if strings.Contains(addr, "example.com") {
				return d.DialContext(ctx, "tcp", proxy.listener.Addr().String())
			}
			return d.DialContext(ctx, network, addr)
		}
		client := http.Client{
			Transport: transport,
			Jar:       jar,
		}
		req, err := http.NewRequest("GET", urlToGet, nil)
		if err != nil {
			t.Fatalf("http.NewRequest: %v", err)
		}
		if postBody != nil {
			req.Method = "POST"
			req.Body = io.NopCloser(bytes.NewReader(postBody))
		}
		if hdr != nil {
			req.Header = hdr
		}
		if req.Method == "POST" {
			for _, c := range jar.Cookies(req.URL) {
				req.AddCookie(c)
				if c.Name == "__tlsproxySid" {
					t.Logf("%s = %q", c.Name, c.Value)
					req.Header.Set("x-csrf-token", c.Value)
					break
				}
			}
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
		return resp.StatusCode, string(body), host
	}

	code, body, _ := get("https://https.example.com/blah", http.Header{"x-skip-login-confirmation": []string{"yes"}}, nil)
	if got, want := code, 200; got != want {
		t.Errorf("Code = %v, want %v", got, want)
	}
	m := regexp.MustCompile(`<form method="POST" action="([^"]*)"><input type="hidden" name="([^"]*)" value="([^"]*)"`).FindStringSubmatch(body)
	if len(m) != 4 {
		t.Fatalf("FindStringSubmatch: %v", m)
	}
	action := m[1]
	name := m[2]
	value := strings.ReplaceAll((m[3]), "&#43;", "+")

	hdrs := http.Header{}
	hdrs.Set("content-type", "application/x-www-form-urlencoded")
	data := url.Values{}
	data.Set(name, value)

	code, body, _ = get(action, hdrs, []byte(data.Encode()))
	if got, want := code, 200; got != want {
		t.Errorf("Code = %v, want %v", got, want)
	}
	if got, want := body, "[https-server] /blah\n"; got != want {
		t.Errorf("Body = %v, want %v", got, want)
	}
	if idp.count == 0 {
		t.Error("IDP Server never called")
	}
}

func newSAMLIDPServer(t *testing.T, cert tls.Certificate) *samlIDPServer {
	idp := &samlIDPServer{
		t:          t,
		samlServer: saml.NewServer(cert),
	}
	mux := http.NewServeMux()
	log := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			t.Logf("[IDP SERVER] %s %s", req.Method, req.RequestURI)
			req.ParseForm()
			for k, v := range req.Form {
				t.Logf("[IDP SERVER]  %s: %v", k, v)
			}
			next.ServeHTTP(w, req)

			idp.mu.Lock()
			defer idp.mu.Unlock()
			idp.count++
		})
	}
	mux.Handle("/", log(idp.samlServer))
	idp.Server = httptest.NewServer(mux)
	return idp
}

type samlIDPServer struct {
	*httptest.Server
	t          *testing.T
	samlServer *saml.ProviderServer

	mu    sync.Mutex
	count int
}
