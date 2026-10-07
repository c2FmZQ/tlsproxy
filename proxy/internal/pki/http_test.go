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

package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	jwt "github.com/golang-jwt/jwt/v5"

	"github.com/c2FmZQ/tlsproxy/proxy/internal/fromctx"
)

func TestDNSNameMatches(t *testing.T) {
	for _, tc := range []struct {
		pattern, name string
		want          bool
	}{
		{"foo.example.com", "foo.example.com", true},
		{"foo.example.com", "FOO.example.com", true},
		{"foo.example.com", "bar.example.com", false},
		{"foo.example.com", "", false},
		{"*.example.com", "foo.example.com", true},
		{"*.example.com", "*.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", ".example.com", false},
		{"*.example.com", "foo.bar.example.com", false},
		{"*.example.com", "*.bar.example.com", false},
		{"*.example.com", "foo.example.com.evil.com", false},
		{"*.example.com", "fooexample.com", false},
		{"*.bar.example.com", "*.example.com", false},
	} {
		if got := DNSNameMatches(tc.pattern, tc.name); got != tc.want {
			t.Errorf("DNSNameMatches(%q, %q) = %v, want %v", tc.pattern, tc.name, got, tc.want)
		}
	}
}

func TestRequestServerCert(t *testing.T) {
	m := newPKI(t, nil)
	m.opts.AdminMatcher = func(acl []string, email string) bool {
		return slices.Contains(acl, email)
	}

	requestCert := func(email string, dnsNames ...string) (int, *x509.Certificate) {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey: %v", err)
		}
		csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject:  pkix.Name{CommonName: "test"},
			DNSNames: dnsNames,
		}, key)
		if err != nil {
			t.Fatalf("x509.CreateCertificateRequest: %v", err)
		}
		body := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})
		req := httptest.NewRequest(http.MethodPost, "https://pki.example.com/?get=requestCert", bytes.NewReader(body))
		req.Header.Set("content-type", "application/x-pem-file")
		req = req.WithContext(fromctx.WithClaims(req.Context(), jwt.MapClaims{"email": email}))
		w := httptest.NewRecorder()
		m.ServeCertificateManagement(w, req)
		if w.Code != http.StatusOK {
			return w.Code, nil
		}
		var resp struct {
			Cert string `json:"cert"`
		}
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("json.Decode: %v", err)
		}
		block, _ := pem.Decode([]byte(resp.Cert))
		if block == nil {
			t.Fatalf("pem.Decode failed: %q", resp.Cert)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("x509.ParseCertificate: %v", err)
		}
		return w.Code, cert
	}

	// No policy: only client certs.
	if code, cert := requestCert("alice@example.com"); code != http.StatusOK || len(cert.DNSNames) != 0 {
		t.Errorf("client cert: code %d", code)
	}
	if code, _ := requestCert("alice@example.com", "foo.example.com"); code != http.StatusForbidden {
		t.Errorf("server cert without policy: code %d, want %d", code, http.StatusForbidden)
	}

	m.opts.ServerCertificates = []ServerCertificatePolicy{
		{DNSNames: []string{"*.internal.example.com"}},
		{DNSNames: []string{"*.example.com", "example.com"}, ACL: &[]string{"bob@example.com"}},
	}
	for _, tc := range []struct {
		email    string
		dnsNames []string
		want     int
	}{
		{"alice@example.com", []string{"foo.internal.example.com"}, http.StatusOK},
		{"alice@example.com", []string{"FOO.Internal.example.com"}, http.StatusOK},
		{"alice@example.com", []string{"*.internal.example.com"}, http.StatusOK},
		{"alice@example.com", []string{"foo.internal.example.com", "www.example.com"}, http.StatusForbidden},
		{"alice@example.com", []string{"www.example.com"}, http.StatusForbidden},
		{"alice@example.com", []string{"foo.bar.internal.example.com"}, http.StatusForbidden},
		{"bob@example.com", []string{"www.example.com", "example.com", "x.internal.example.com"}, http.StatusOK},
		{"bob@example.com", []string{"www.google.com"}, http.StatusForbidden},
	} {
		code, cert := requestCert(tc.email, tc.dnsNames...)
		if code != tc.want {
			t.Errorf("%s %v: code %d, want %d", tc.email, tc.dnsNames, code, tc.want)
			continue
		}
		if cert == nil {
			continue
		}
		var want []string
		for _, n := range tc.dnsNames {
			want = append(want, strings.ToLower(n))
		}
		if !slices.Equal(cert.DNSNames, want) {
			t.Errorf("%s %v: DNSNames = %v, want %v", tc.email, tc.dnsNames, cert.DNSNames, want)
		}
		if !slices.Equal(cert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) {
			t.Errorf("%s %v: ExtKeyUsage = %v", tc.email, tc.dnsNames, cert.ExtKeyUsage)
		}
	}
}
