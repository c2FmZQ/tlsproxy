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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

func TestBackendPeerCertificateXSS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	jwksSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				{
					"kty": "EC",
					"crv": "P-256",
					"kid": "k1",
					"alg": "ES256",
					"use": "sig",
					"x":   base64.RawURLEncoding.EncodeToString(priv.X.FillBytes(make([]byte, 32))),
					"y":   base64.RawURLEncoding.EncodeToString(priv.Y.FillBytes(make([]byte, 32))),
				},
			},
		})
	}))
	defer jwksSrv.Close()

	svc := newService(ctx, jwksSrv.URL, true)
	for range 50 {
		if _, err := svc.remote.GetKey("k1"); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss":   "https://login.example.com",
		"aud":   "https://example.com/",
		"email": "alice@example.com",
		"exp":   time.Now().Add(time.Minute).Unix(),
	})
	tok.Header["kid"] = "k1"
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}

	req := httptest.NewRequest("GET", "https://example.com/", nil)
	req.Proto = "HTTP/1.1<script>alert(1)</script>"
	req.Header.Set("Authorization", "Bearer "+signed)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			{
				Subject: pkix.Name{CommonName: "Alice & Bob"},
			},
		},
	}
	w := httptest.NewRecorder()
	svc.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("StatusCode = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "<script>alert(1)</script>") || !strings.Contains(body, "CN=Alice &amp; Bob") {
		t.Errorf("Response contains unescaped HTML:\n%s", body)
	}
}
