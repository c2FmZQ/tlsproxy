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

package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/c2FmZQ/storage"
	"github.com/c2FmZQ/storage/crypto"
	"github.com/c2FmZQ/tpm"
	"github.com/google/go-tpm-tools/simulator"
	"golang.org/x/crypto/ocsp"
)

func newPKI(t *testing.T, tpm *tpm.TPM) *PKIManager {
	dir := t.TempDir()
	mk, err := crypto.CreateAESMasterKeyForTest()
	if err != nil {
		t.Fatalf("crypto.CreateMasterKey: %v", err)
	}
	opts := Options{
		Name:     "pki-test",
		Endpoint: "https://pki.example.com",
		Store:    storage.New(dir, mk),
		TPM:      tpm,
	}
	m, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

func TestNewPKIManager(t *testing.T) {
	m := newPKI(t, nil)
	if m.db == nil {
		t.Fatal("pki.example.com doesn't exist")
	}
	if m.db.CACert == nil {
		t.Fatal("ca cert is not set")
	}
	if _, err := x509.ParseCertificate(m.db.CACert.Raw); err != nil {
		t.Errorf("x509.ParseCertificate: %v", err)
	}
	t.Logf("CERT: %s", m.db.CACert.pem())
}

func TestIssueRevoke(t *testing.T) {
	rwc, err := simulator.Get()
	if err != nil {
		t.Fatalf("simulator.Get: %v", err)
	}
	tpmSim, err := tpm.New(tpm.WithTPM(rwc))
	if err != nil {
		t.Fatalf("tpm.New: %v", err)
	}
	for _, tc := range []struct {
		name string
		tpm  *tpm.TPM
	}{
		{"Without TPM", nil},
		{"With TPM", tpmSim},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newPKI(t, tc.tpm)

			caCert, err := m.CACert()
			if err != nil {
				t.Fatalf("CACert: %v", err)
			}

			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("ecdsa.GenerateKey: %v", err)
			}
			templ := &x509.CertificateRequest{
				PublicKeyAlgorithm: x509.ECDSA,
				Subject:            pkix.Name{CommonName: "hello-world"},
			}
			raw, err := x509.CreateCertificateRequest(rand.Reader, templ, key)
			if err != nil {
				t.Fatalf("x509.CreateCertificateRequest: %v", err)
			}

			cr, err := m.ValidateCertificateRequest(raw)
			if err != nil {
				t.Fatalf("m.ValidateCertificateRequest: %v", err)
			}
			certBytes, err := m.IssueCertificate(cr)
			if err != nil {
				t.Fatalf("m.IssueCertificate: %v", err)
			}
			cert, err := x509.ParseCertificate(certBytes)
			if err != nil {
				t.Fatalf("x509.ParseCertificate: %v", err)
			}
			if got, want := cert.Subject.String(), "CN=hello-world"; got != want {
				t.Errorf("Subject) = %v, want %v", got, want)
			}

			if raw, err = ocsp.CreateRequest(cert, caCert, nil); err != nil {
				t.Fatalf("ocsp.CreateRequest: %v", err)
			}
			ocspReq, err := ocsp.ParseRequest(raw)
			if err != nil {
				t.Fatalf("ocsp.ParseRequest: %v", err)
			}
			if got, want := m.IsRevoked(cert.SerialNumber), false; got != want {
				t.Errorf("m.IsRevoked() = %v, want %v", got, want)
			}
			if raw, err := m.OCSPResponse(ocspReq); err != nil {
				t.Errorf("m.OCSPResponse: %v", err)
			} else if resp, err := ocsp.ParseResponse(raw, caCert); err != nil {
				t.Errorf("ocsp.ParseResponse: %v", err)
			} else {
				t.Logf("OCSP Response: %#v", resp)
				if got, want := resp.Status, ocsp.Good; got != want {
					t.Errorf("Response Status = %v, want %v", got, want)
				}
			}

			if err := m.RevokeCertificate(cert.SerialNumber, RevokeReasonKeyCompromise); err != nil {
				t.Fatalf("m.Revoke: %v", err)
			}
			if got, want := m.IsRevoked(cert.SerialNumber), true; got != want {
				t.Errorf("m.IsRevoked() = %v, want %v", got, want)
			}
			if raw, err := m.OCSPResponse(ocspReq); err != nil {
				t.Errorf("m.OCSPResponse: %v", err)
			} else if resp, err := ocsp.ParseResponse(raw, caCert); err != nil {
				t.Errorf("ocsp.ParseResponse: %v", err)
			} else {
				t.Logf("OCSP Response: %#v", resp)
				if got, want := resp.Status, ocsp.Revoked; got != want {
					t.Errorf("Response Status = %v, want %v", got, want)
				}
			}

			_, crl, err := m.RevocationList()
			if err != nil {
				t.Fatalf("m.RevocationList: %v", err)
			}
			_, crl2, err := m.RevocationList()
			if err != nil {
				t.Fatalf("m.RevocationList: %v", err)
			}
			if !bytes.Equal(crl, crl2) {
				t.Error("crl not cached")
			}
			rl, err := x509.ParseRevocationList(crl)
			if err != nil {
				t.Fatalf("x509.ParseRevocationList: %v", err)
			}
			if got, want := len(rl.RevokedCertificateEntries), 1; got != want {
				t.Fatalf("len(RevokedCertificateEntries) = %d, want %d", got, want)
			}
			if got, want := rl.RevokedCertificateEntries[0].SerialNumber, cert.SerialNumber; got.Cmp(want) != 0 {
				t.Errorf("SerialNumber = %s, want %s", got, want)
			}
			if got, want := rl.RevokedCertificateEntries[0].ReasonCode, RevokeReasonKeyCompromise; got != want {
				t.Errorf("ReasonCode = %d, want %d", got, want)
			}
		})
	}
}
