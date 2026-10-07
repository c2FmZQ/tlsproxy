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

package ocspcache

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/c2FmZQ/storage"
	storagecrypto "github.com/c2FmZQ/storage/crypto"
	"golang.org/x/crypto/ocsp"
)

type testLogger struct {
	t *testing.T
}

func (l testLogger) Errorf(f string, args ...any) { l.t.Logf(f, args...) }
func (l testLogger) Fatalf(f string, args ...any) { l.t.Fatalf(f, args...) }

type testCert struct {
	cert *x509.Certificate
	key  crypto.Signer
}

func newTestCert(t *testing.T, tmpl *x509.Certificate, parent *testCert) *testCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	sn, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("rand.Int: %v", err)
	}
	tmpl.SerialNumber = sn
	tmpl.NotBefore = time.Now().Add(-time.Hour)
	tmpl.NotAfter = time.Now().Add(time.Hour)
	parentCert, parentKey := tmpl, crypto.Signer(key)
	if parent != nil {
		parentCert, parentKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, key.Public(), parentKey)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate: %v", err)
	}
	return &testCert{cert: cert, key: key}
}

func newOCSPResponse(t *testing.T, cert, issuer, responder *testCert, status int, thisUpdate, nextUpdate time.Time) []byte {
	t.Helper()
	tmpl := ocsp.Response{
		Status:       status,
		SerialNumber: cert.cert.SerialNumber,
		ThisUpdate:   thisUpdate,
		NextUpdate:   nextUpdate,
	}
	if status == ocsp.Revoked {
		tmpl.RevokedAt = thisUpdate
	}
	if responder != issuer {
		tmpl.Certificate = responder.cert
	}
	raw, err := ocsp.CreateResponse(issuer.cert, responder.cert, tmpl, responder.key)
	if err != nil {
		t.Fatalf("ocsp.CreateResponse: %v", err)
	}
	return raw
}

func TestVerifyChains(t *testing.T) {
	now := time.Now()

	var serverResponse []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		io.Copy(io.Discard, req.Body)
		w.Header().Set("content-type", "application/ocsp-response")
		w.Write(serverResponse)
	}))
	defer server.Close()

	ca := newTestCert(t, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test CA"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, nil)
	newLeaf := func() *testCert {
		return newTestCert(t, &x509.Certificate{
			Subject:     pkix.Name{CommonName: "leaf"},
			OCSPServer:  []string{server.URL},
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}, ca)
	}
	other := newLeaf()
	responder := newTestCert(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "OCSP responder"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
	}, ca)

	for _, tc := range []struct {
		name string
		// The stapled response, if any.
		staple func(leaf *testCert) []byte
		// The response returned by the OCSP server.
		fetched func(leaf *testCert) []byte
		wantErr error
	}{
		{
			name: "Fetched good",
			fetched: func(leaf *testCert) []byte {
				return newOCSPResponse(t, leaf, ca, ca, ocsp.Good, now, now.Add(time.Hour))
			},
		},
		{
			name: "Fetched revoked",
			fetched: func(leaf *testCert) []byte {
				return newOCSPResponse(t, leaf, ca, ca, ocsp.Revoked, now, now.Add(time.Hour))
			},
			wantErr: errOCSPRevoked,
		},
		{
			name: "Fetched good from delegated responder",
			fetched: func(leaf *testCert) []byte {
				return newOCSPResponse(t, leaf, ca, responder, ocsp.Good, now, now.Add(time.Hour))
			},
		},
		{
			name: "Fetched good signed by leaf",
			fetched: func(leaf *testCert) []byte {
				return newOCSPResponse(t, leaf, ca, leaf, ocsp.Good, now, now.Add(time.Hour))
			},
			wantErr: errOCSPProtocol,
		},
		{
			name: "Fetched good for other cert",
			fetched: func(leaf *testCert) []byte {
				return newOCSPResponse(t, other, ca, ca, ocsp.Good, now, now.Add(time.Hour))
			},
			wantErr: errOCSPProtocol,
		},
		{
			name: "Fetched expired good",
			fetched: func(leaf *testCert) []byte {
				return newOCSPResponse(t, leaf, ca, ca, ocsp.Good, now.Add(-2*time.Hour), now.Add(-time.Hour))
			},
			wantErr: errOCSPProtocol,
		},
		{
			name: "Fetched future good",
			fetched: func(leaf *testCert) []byte {
				return newOCSPResponse(t, leaf, ca, ca, ocsp.Good, now.Add(time.Hour), now.Add(2*time.Hour))
			},
			wantErr: errOCSPProtocol,
		},
		{
			name: "Stapled good, fetched revoked",
			staple: func(leaf *testCert) []byte {
				return newOCSPResponse(t, leaf, ca, ca, ocsp.Good, now, now.Add(time.Hour))
			},
			fetched: func(leaf *testCert) []byte {
				return newOCSPResponse(t, leaf, ca, ca, ocsp.Revoked, now, now.Add(time.Hour))
			},
		},
		{
			name: "Stapled good signed by leaf, fetched revoked",
			staple: func(leaf *testCert) []byte {
				return newOCSPResponse(t, leaf, ca, leaf, ocsp.Good, now, now.Add(365*24*time.Hour))
			},
			fetched: func(leaf *testCert) []byte {
				return newOCSPResponse(t, leaf, ca, ca, ocsp.Revoked, now, now.Add(time.Hour))
			},
			wantErr: errOCSPRevoked,
		},
		{
			name: "Stapled good for other cert, fetched revoked",
			staple: func(leaf *testCert) []byte {
				return newOCSPResponse(t, other, ca, ca, ocsp.Good, now, now.Add(time.Hour))
			},
			fetched: func(leaf *testCert) []byte {
				return newOCSPResponse(t, leaf, ca, ca, ocsp.Revoked, now, now.Add(time.Hour))
			},
			wantErr: errOCSPRevoked,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mk, err := storagecrypto.CreateAESMasterKeyForTest()
			if err != nil {
				t.Fatalf("CreateAESMasterKeyForTest: %v", err)
			}
			c := New(storage.New(t.TempDir(), mk), testLogger{t})

			leaf := newLeaf()
			var staple []byte
			if tc.staple != nil {
				staple = tc.staple(leaf)
			}
			serverResponse = tc.fetched(leaf)
			chains := [][]*x509.Certificate{{leaf.cert, ca.cert}}
			if err := c.VerifyChains(context.Background(), chains, staple); err != tc.wantErr {
				t.Errorf("VerifyChains() = %v, want %v", err, tc.wantErr)
			}
		})
	}
}
