// MIT License
//
// Copyright (c) 2026 TTBT Enterprises LLC
// Copyright (c) 2026 Robin Thellend <rthellend@rthellend.com>
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

package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestOAuth2ServerRejectsInvalidJWT(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var userinfoCalled atomic.Bool
	var idpURL string
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"authorization_endpoint": idpURL + "/auth",
				"token_endpoint":         idpURL + "/token",
				"userinfo_endpoint":      idpURL + "/userinfo",
				"jwks_uri":               idpURL + "/jwks",
			})
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			// Return an unsigned/forged JWT with attacker claims.
			forged := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhdHRhY2tlciIsIm5vbmNlIjoidGVzdHN0YXRlIn0."
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": forged,
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		case "/userinfo":
			userinfoCalled.Store(true)
			w.Write([]byte(`{"sub":"attacker"}`))
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"keys":[]}`))
		}
	}))
	defer idp.Close()
	idpURL = idp.URL

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	addr := l.Addr().String()
	l.Close()

	*serverAddr = addr
	srv := &Server{
		Addr:            addr,
		OpenIDConfigURL: idp.URL + "/.well-known/openid-configuration",
		ClientID:        "cid",
		ClientSecret:    "csec",
		Scopes:          []string{"openid"},
	}
	go srv.Run(ctx)

	var resp *http.Response
	for range 50 {
		req, _ := http.NewRequest("GET", "http://"+addr+"/redirect?code=abc&state=teststate", nil)
		req.AddCookie(&http.Cookie{Name: stateCookieName, Value: "teststate"})
		resp, err = http.DefaultClient.Do(req)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("GET /redirect: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if strings.Contains(string(body), "AccessToken claims:") || strings.Contains(string(body), "attacker") {
		t.Errorf("Server accepted unverified JWT claims:\n%s", body)
	}
	if userinfoCalled.Load() {
		t.Errorf("Server called userinfo endpoint after JWT verification failed")
	}
}
