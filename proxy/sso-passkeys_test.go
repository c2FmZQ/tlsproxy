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
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/c2FmZQ/tlsproxy/certmanager"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/oidc"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/passkeys"
)

func TestSSOEnforcePasskey(t *testing.T) {
	oidc.AutoApproveForTests = true

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
			code, body, _ = get("https://"+host+"/.sso/logout", nil, []byte{})
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
