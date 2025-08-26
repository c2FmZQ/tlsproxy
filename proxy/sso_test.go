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
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/c2FmZQ/storage"
	"github.com/c2FmZQ/storage/crypto"
	jwt "github.com/golang-jwt/jwt/v5"

	"github.com/c2FmZQ/tlsproxy/certmanager"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/cookiemanager"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/oidc"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/passkeys"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/tokenmanager"
)

func TestSSOEnforceOIDC(t *testing.T) {
	for _, tc := range []struct {
		name     string
		hwBacked bool
	}{
		{"Without TPM", false},
		{"With TPM", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
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
					HTTPAddr: newPtr("localhost:0"),
					TLSAddr:  newPtr("localhost:0"),
					CacheDir: newPtr(t.TempDir()),
					MaxOpen:  newPtr(100),
					HWBacked: newPtr(tc.hwBacked),
					OIDCProviders: []*ConfigOIDC{
						{
							Name:          "test-idp",
							AuthEndpoint:  idp.URL + "/authorization",
							TokenEndpoint: idp.URL + "/token",
							RedirectURL:   "https://öauth2.example.com/redirect",
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
							ForwardRootCAs:    []string{ca.RootCAPEM()},
							SSO: &BackendSSO{
								Provider:         "test-idp",
								GenerateIDTokens: true,
							},
							ForwardHTTPHeaders: map[string]string{
								"x-test": "FOO ${SERVER_NAME} ${NETWORK} // ${JWT:email}",
							},
						},
						{
							ServerNames: []string{
								"öauth2.example.com",
								"oauth2.example.com",
							},
							Mode:             "HTTPS",
							ForwardRateLimit: 1000,
							SSO: &BackendSSO{
								Provider: "test-idp",
							},
						},
						{
							ServerNames: []string{
								"dev.example.com",
							},
							Mode:             "LOCAL",
							ForwardRateLimit: 1000,
							SSO: &BackendSSO{
								Provider: "test-idp",
								LocalOIDCServer: &LocalOIDCServer{
									Clients: []*LocalOIDCClient{
										{ID: "clientid", ACL: &Strings{"bob@example.com"}},
									},
								},
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
					Header: hdr,
				}
				if req.Header == nil {
					req.Header = make(http.Header)
				}
				req.Header.Set("x-skip-login-confirmation", "true")
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

			post := func(urlToGet string, hdr http.Header, form url.Values) (int, string) {
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
				client := http.Client{Transport: transport}
				req := &http.Request{
					Method: "POST",
					URL:    u,
					Host:   u.Host,
					Header: hdr,
					Body:   io.NopCloser(strings.NewReader(form.Encode())),
				}
				if req.Header == nil {
					req.Header = make(http.Header)
				}
				req.Header.Set("content-type", "application/x-www-form-urlencoded")
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
				return resp.StatusCode, string(body)
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
			if idp.count == 0 {
				t.Error("IDP Server never called")
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

			hdr.Set("Authorization", "Bearer "+cookies["TLSPROXYIDTOKEN"])
			code, body, cookies = get("https://https.example.com/?header=x-test", hdr)
			if got, want := code, 200; got != want {
				t.Errorf("Code = %v, want %v", got, want)
			}
			if got, want := body, "[https-server] /?header=x-test\nx-test=FOO https.example.com tcp // bob@example.com\n"; got != want {
				t.Errorf("Body = %v, want %v", got, want)
			}

			code, body = post("https://dev.example.com/device/authorization", nil, url.Values{"client_id": {"clientid"}})
			if got, want := code, 200; got != want {
				t.Errorf("Code = %v, want %v", got, want)
			}
			var result map[string]any
			if err := json.Unmarshal([]byte(body), &result); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			t.Logf("RESULT: %#v", result)

			code, _, cookies = get(result["verification_uri_complete"].(string), nil)
			if got, want := code, 200; got != want {
				t.Errorf("Code = %v, want %v", got, want)
			}

			var jar []string
			for k, v := range cookies {
				t.Logf("COOKIE: %s=%s", k, v)
				jar = append(jar, k+"="+v)
			}
			hdr = http.Header{
				"cookie":       {strings.Join(jar, "; ")},
				"x-csrf-check": {"1"},
			}
			code, body = post(result["verification_uri_complete"].(string), hdr, url.Values{
				"user_code": {result["user_code"].(string)},
				"approve":   {"true"},
			})
			if got, want := code, 200; got != want {
				t.Errorf("Code = %v, want %v", got, want)
			}
			if got, want := body, "approved\n"; got != want {
				t.Errorf("Body = %v, want %v", got, want)
			}

			code, body = post("https://dev.example.com/device/token", nil, url.Values{
				"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
				"client_id":   {"clientid"},
				"device_code": {result["device_code"].(string)},
			})
			if got, want := code, 200; got != want {
				t.Errorf("Code = %v, want %v", got, want)
			}
			var token map[string]any
			if err := json.Unmarshal([]byte(body), &token); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			t.Logf("TOKEN: %#v", token)
			if token["access_token"] == nil || token["token_type"] != "Bearer" {
				t.Fatalf("TOKEN: %#v", token)
			}
		})
	}
}

func TestSSOEnforcePasskey(t *testing.T) {
	for _, tc := range []struct {
		name     string
		hwBacked bool
	}{
		{"Without TPM", false},
		{"With TPM", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
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
					HTTPAddr: newPtr("localhost:0"),
					TLSAddr:  newPtr("localhost:0"),
					CacheDir: newPtr(t.TempDir()),
					MaxOpen:  newPtr(100),
					HWBacked: newPtr(tc.hwBacked),
					OIDCProviders: []*ConfigOIDC{
						{
							Name:          "test-idp",
							AuthEndpoint:  idp.URL + "/authorization",
							TokenEndpoint: idp.URL + "/token",
							RedirectURL:   "https://öauth2.example.com/redirect",
							ClientID:      "CLIENTID",
							ClientSecret:  "CLIENTSECRET",
							Domain:        "example.com",
						},
					},
					PasskeyProviders: []*ConfigPasskey{
						{
							Name:             "test-passkey",
							IdentityProvider: "test-idp",
							Endpoint:         "https://login.example.com/passkey",
							Domain:           "example.com",
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
							ForwardRootCAs:    []string{ca.RootCAPEM()},
							SSO: &BackendSSO{
								Provider: "test-passkey",
							},
						},
						{
							ServerNames: []string{
								"öauth2.example.com",
								"oauth2.example.com",
								"login.example.com",
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
				req.Header.Set("x-csrf-check", "1")
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

			// Redirects to login page.
			code, body, host := get("https://https.example.com/blah", nil, nil)
			if got, want := code, 200; got != want {
				t.Errorf("Code = %v, want %v", got, want)
			}
			m := regexp.MustCompile(`href="(/passkey[?]get=RegisterNewID&redirect=([^"]*))"`).FindStringSubmatch(body)
			if len(m) != 3 {
				t.Fatalf("FindStringSubmatch: %v", m)
			}
			token := m[2]
			t.Logf("TOKEN: %s", token)

			// Go to register new key page.
			code, body, _ = get("https://"+host+m[1], nil, nil)
			if got, want := code, 200; got != want {
				t.Errorf("Code = %v, want %v", got, want)
			}
			if haystack, needle := body, "registerPasskey(&#34;"+token+"&#34;"; !strings.Contains(haystack, needle) {
				t.Errorf("Body = %v, want %v", haystack, needle)
			}

			auth, err := passkeys.NewFakeAuthenticator()
			if err != nil {
				t.Fatalf("passkeys.NewFakeAuthenticator: %v", err)
			}
			auth.SetOrigin("https://" + host)

			// Get the attestation options.
			code, body, _ = get("https://"+host+"/passkey?get=AttestationOptions&redirect="+token, nil, []byte{})
			if got, want := code, 200; got != want {
				t.Errorf("Code = %v, want %v", got, want)
			}
			var ao passkeys.AttestationOptions
			if err := json.Unmarshal([]byte(body), &ao); err != nil {
				t.Fatalf("AttestationOptions: %v", err)
			}
			clientDataJSON, attestationObject, err := auth.Create(&ao)
			if err != nil {
				t.Fatalf("auth.Create: %v", err)
			}
			data := struct {
				ClientDataJSON    passkeys.Bytes `json:"clientDataJSON"`
				AttestationObject passkeys.Bytes `json:"attestationObject"`
				Transports        []string       `json:"transports"`
			}{
				ClientDataJSON:    clientDataJSON,
				AttestationObject: attestationObject,
				Transports:        []string{"usb"},
			}
			dataJSON, _ := json.Marshal(data)

			hdr := http.Header{}
			hdr.Set("content-type", "application/x-www-form-urlencoded")
			postBody := "args=" + url.QueryEscape(string(dataJSON))

			// Send the new passkey attestation.
			code, body, _ = get("https://"+host+"/passkey?get=AddKey&redirect="+token, hdr, []byte(postBody))
			if got, want := code, 200; got != want {
				t.Fatalf("Code = %v, want %v", got, want)
			}
			if got, want := strings.TrimSpace(body), `{"redirect":"https://https.example.com/blah","result":"ok"}`; got != want {
				t.Fatalf("Body = %v, want %v", got, want)
			}

			// We should be logged in now.
			code, body, host = get("https://https.example.com/blah", nil, nil)
			if got, want := code, 200; got != want {
				t.Fatalf("Code = %v, want %v", got, want)
			}
			if got, want := body, "[https-server] /blah\n"; got != want {
				t.Fatalf("Body = %v, want %v", got, want)
			}

			if idp.count == 0 {
				t.Error("IDP Server never called")
			}

			// Logout
			code, body, _ = get("https://"+host+"/.sso/logout", nil, nil)
			if got, want := code, 200; got != want {
				t.Errorf("Code = %v, want %v", got, want)
			}

			// Redirects to login page.
			code, body, host = get("https://https.example.com/blah", nil, nil)
			if got, want := code, 200; got != want {
				t.Errorf("Code = %v, want %v", got, want)
			}
			m = regexp.MustCompile(`loginWithPasskey\(&#34;(.*)&#34;,`).FindStringSubmatch(body)
			if len(m) != 2 {
				t.Fatalf("FindStringSubmatch: %v", m)
			}
			token = m[1]
			t.Logf("TOKEN: %s", token)

			// Get the assertion options.
			code, body, _ = get("https://"+host+"/passkey?get=AssertionOptions&redirect="+token, nil, []byte{})
			if got, want := code, 200; got != want {
				t.Errorf("Code = %v, want %v", got, want)
			}
			var aso passkeys.AssertionOptions
			if err := json.Unmarshal([]byte(body), &aso); err != nil {
				t.Fatalf("AssertionOptions: %v", err)
			}
			id, clientDataJSON, authData, signature, userHandle, err := auth.Get(&aso)
			if err != nil {
				t.Fatalf("auth.Get: %v", err)
			}
			data2 := struct {
				ID                string         `json:"id"`
				ClientDataJSON    passkeys.Bytes `json:"clientDataJSON"`
				AuthenticatorData passkeys.Bytes `json:"authenticatorData"`
				Signature         passkeys.Bytes `json:"signature"`
				UserHandle        passkeys.Bytes `json:"userHandle"`
			}{
				ID:                base64.RawURLEncoding.EncodeToString(id),
				ClientDataJSON:    clientDataJSON,
				AuthenticatorData: authData,
				Signature:         signature,
				UserHandle:        userHandle,
			}
			dataJSON, _ = json.Marshal(data2)

			hdr = http.Header{}
			hdr.Set("content-type", "application/x-www-form-urlencoded")
			postBody = "args=" + url.QueryEscape(string(dataJSON))

			// Send the passkey assertion.
			code, body, _ = get("https://"+host+"/passkey?get=Check&redirect="+token, hdr, []byte(postBody))
			if got, want := code, 200; got != want {
				t.Errorf("Code = %v, want %v", got, want)
			}
			if got, want := strings.TrimSpace(body), `{"redirect":"https://https.example.com/blah","result":"ok"}`; got != want {
				t.Errorf("Body = %v, want %v", got, want)
			}

			// We should be logged in again.
			code, body, host = get("https://https.example.com/blah", nil, nil)
			if got, want := code, 200; got != want {
				t.Errorf("Code = %v, want %v", got, want)
			}
			if got, want := body, "[https-server] /blah\n"; got != want {
				t.Errorf("Body = %v, want %v", got, want)
			}
		})
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

	mu    sync.Mutex
	count int
}

func newIDPServer(t *testing.T) *idpServer {
	dir := t.TempDir()
	mk, err := crypto.CreateAESMasterKeyForTest()
	if err != nil {
		t.Fatalf("crypto.CreateMasterKey: %v", err)
	}
	store := storage.New(dir, mk)
	tm, err := tokenmanager.New(store, nil, nil)
	if err != nil {
		t.Fatalf("tokenmanager.New: %v", err)
	}
	cm := cookiemanager.New(tm, "idp", "example.com", "https://idp.example.com")
	opts := oidc.ServerOptions{
		CookieManager: cm,
		ClaimsFromCtx: func(context.Context) jwt.MapClaims {
			return jwt.MapClaims{
				"email": "bob@example.com",
				"sub":   "bob.example.com",
			}
		},
		Clients: []oidc.Client{
			{ID: "CLIENTID", Secret: "CLIENTSECRET", RedirectURI: []string{
				"https://öauth2.example.com/redirect",
				"https://oauth2.example.com/redirect",
			}},
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

			idp.mu.Lock()
			defer idp.mu.Unlock()
			idp.count++
		})
	}
	mux.Handle("/.well-known/openid-configuration", log(idp.oidcServer.ServeConfig))
	mux.Handle("/authorization", log(idp.oidcServer.ServeAuthorization))
	mux.Handle("/token", log(idp.oidcServer.ServeToken))
	mux.Handle("/jwks", log(tm.ServeJWKS))
	idp.Server = httptest.NewServer(mux)
	return idp
}
