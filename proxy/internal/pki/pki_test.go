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
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"slices"
	"sync"
	"testing"
	"time"

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

			// Revoke another cert right away, i.e. within the same
			// second. The new CRL must include it.
			certBytes2, err := m.IssueCertificate(cr)
			if err != nil {
				t.Fatalf("m.IssueCertificate: %v", err)
			}
			cert2, err := x509.ParseCertificate(certBytes2)
			if err != nil {
				t.Fatalf("x509.ParseCertificate: %v", err)
			}
			if err := m.RevokeCertificate(cert2.SerialNumber, RevokeReasonKeyCompromise); err != nil {
				t.Fatalf("m.Revoke: %v", err)
			}
			_, crl3, err := m.RevocationList()
			if err != nil {
				t.Fatalf("m.RevocationList: %v", err)
			}
			if rl, err = x509.ParseRevocationList(crl3); err != nil {
				t.Fatalf("x509.ParseRevocationList: %v", err)
			}
			if got, want := len(rl.RevokedCertificateEntries), 2; got != want {
				t.Fatalf("len(RevokedCertificateEntries) = %d, want %d", got, want)
			}
		})
	}
}

func TestConcurrentRevocationList(t *testing.T) {
	m := newPKI(t, nil)
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			if _, _, err := m.RevocationList(); err != nil {
				t.Errorf("m.RevocationList: %v", err)
			}
		})
		wg.Go(func() {
			if _, err := m.CACert(); err != nil {
				t.Errorf("m.CACert: %v", err)
			}
		})
	}
	wg.Wait()
	m.mu.Lock()
	defer m.mu.Unlock()
	if got, want := len(m.db.DelegateCerts), 1; got != want {
		t.Errorf("len(DelegateCerts) = %d, want %d", got, want)
	}
}

func TestPKIDelegateAndCRLVerification(t *testing.T) {
	m := newPKI(t, nil)
	caCert, err := m.CACert()
	if err != nil {
		t.Fatalf("CACert: %v", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	csrRaw, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "leaf"},
	}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	cr, err := m.ValidateCertificateRequest(csrRaw)
	if err != nil {
		t.Fatalf("ValidateCertificateRequest: %v", err)
	}
	certBytes, err := m.IssueCertificate(cr)
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	ocspReqRaw, err := ocsp.CreateRequest(leaf, caCert, nil)
	if err != nil {
		t.Fatalf("ocsp.CreateRequest: %v", err)
	}
	ocspReq, err := ocsp.ParseRequest(ocspReqRaw)
	if err != nil {
		t.Fatalf("ocsp.ParseRequest: %v", err)
	}
	ocspRespRaw, err := m.OCSPResponse(ocspReq)
	if err != nil {
		t.Fatalf("m.OCSPResponse: %v", err)
	}
	ocspResp, err := ocsp.ParseResponse(ocspRespRaw, caCert)
	if err != nil {
		t.Fatalf("ocsp.ParseResponse: %v", err)
	}

	// 1. Delegate cert must not be a CA and must pass x509.Verify against caCert.
	if ocspResp.Certificate.IsCA {
		t.Errorf("Delegate certificate has IsCA = true, want false")
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := ocspResp.Certificate.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
	}); err != nil {
		t.Errorf("Delegate certificate failed x509.Verify against CA: %v", err)
	}

	// 2. id-pkix-ocsp-nocheck extension must have ASN.1 NULL (0x05, 0x00) value.
	var foundNoCheck bool
	for _, ext := range ocspResp.Certificate.Extensions {
		if ext.Id.Equal([]int{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}) {
			foundNoCheck = true
			if !bytes.Equal(ext.Value, []byte{0x05, 0x00}) {
				t.Errorf("id-pkix-ocsp-nocheck Value = %x, want 0500", ext.Value)
			}
		}
	}
	if !foundNoCheck {
		t.Errorf("id-pkix-ocsp-nocheck extension not found on delegate cert")
	}

	// 3. CRL must be directly verifiable against caCert via CheckSignatureFrom.
	_, crlBytes, err := m.RevocationList()
	if err != nil {
		t.Fatalf("m.RevocationList: %v", err)
	}
	rl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		t.Fatalf("x509.ParseRevocationList: %v", err)
	}
	if err := rl.CheckSignatureFrom(caCert); err != nil {
		t.Errorf("rl.CheckSignatureFrom(caCert) failed: %v", err)
	}

	// 4. OCSP response IssuerHash must match ocspReq.HashAlgorithm.
	if ocspResp.IssuerHash != ocspReq.HashAlgorithm {
		t.Errorf("ocspResp.IssuerHash = %v, want %v", ocspResp.IssuerHash, ocspReq.HashAlgorithm)
	}

	// 5. RevokeCertificate must reject revoking the Root CA or OCSP delegate cert.
	if err := m.RevokeCertificate(caCert.SerialNumber, RevokeReasonKeyCompromise); err == nil {
		t.Errorf("RevokeCertificate(caCert) succeeded, want error")
	}
	if err := m.RevokeCertificate(ocspResp.Certificate.SerialNumber, RevokeReasonKeyCompromise); err == nil {
		t.Errorf("RevokeCertificate(delegateCert) succeeded, want error")
	}
}

func TestValidateCertificateRequestWeakKey(t *testing.T) {
	m := newPKI(t, nil)

	weakRSA, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(1024): %v", err)
	}
	csrRaw, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "weak-rsa"},
	}, weakRSA)
	if err != nil {
		t.Fatalf("CreateCertificateRequest(weakRSA): %v", err)
	}
	if _, err := m.ValidateCertificateRequest(csrRaw); err == nil {
		t.Errorf("ValidateCertificateRequest(1024-bit RSA) succeeded, want error")
	}

	weakECDSA, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey(P224): %v", err)
	}
	csrECDSA, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "weak-ecdsa"},
	}, weakECDSA)
	if err != nil {
		t.Fatalf("CreateCertificateRequest(weakECDSA): %v", err)
	}
	if _, err := m.ValidateCertificateRequest(csrECDSA); err == nil {
		t.Errorf("ValidateCertificateRequest(P-224 ECDSA) succeeded, want error")
	}
}

func TestValidateCertificateRequestRSAExponent3(t *testing.T) {
	m := newPKI(t, nil)
	key := newRSAKeyWithExponent3(t)
	csrRaw, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "rsa-e3"},
	}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	if _, err := m.ValidateCertificateRequest(csrRaw); err != nil {
		t.Errorf("ValidateCertificateRequest(2048-bit RSA, e=3) = %v, want nil", err)
	}
}

// newRSAKeyWithExponent3 returns a 2048-bit RSA key with public exponent 3.
func newRSAKeyWithExponent3(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	one := big.NewInt(1)
	for {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa.GenerateKey: %v", err)
		}
		p, q := k.Primes[0], k.Primes[1]
		phi := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
		d := new(big.Int).ModInverse(big.NewInt(3), phi)
		if d == nil {
			continue
		}
		key := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{N: k.N, E: 3},
			D:         d,
			Primes:    []*big.Int{p, q},
		}
		key.Precompute()
		if err := key.Validate(); err != nil {
			continue
		}
		return key
	}
}

// newCACertForTest creates a self-signed CA certificate for m's key with
// the given key usage and SubjectKeyId, and installs it as m's CA cert.
func newCACertForTest(t *testing.T, m *PKIManager, ku x509.KeyUsage, skid []byte, serial int64) *x509.Certificate {
	t.Helper()
	var err error
	commit, err := m.open()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	pk, err := m.parseKeyBytes(m.db.PrivateKey)
	if err != nil {
		t.Fatalf("parseKeyBytes: %v", err)
	}
	signer := pk.(stdcrypto.Signer)
	now := time.Now()
	templ := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: m.opts.Name},
		NotBefore:             now,
		NotAfter:              now.Add(caCertLifetime),
		KeyUsage:              ku,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
		SubjectKeyId:          skid,
	}
	raw, err := x509.CreateCertificate(rand.Reader, templ, templ, signer.Public(), signer)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	h := sha256.Sum256(raw)
	c := &certificate{SHA256: bytesToHex(h[:]), SerialNumber: bytesToHex(big.NewInt(serial).Bytes()), Raw: raw}
	m.db.CACert = c
	m.db.IssuedCerts = append(m.db.IssuedCerts, c)
	if err := commit(true, &err); err != nil {
		t.Fatalf("commit: %v", err)
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

func TestCAReissuePreservesSubjectKeyId(t *testing.T) {
	m := newPKI(t, nil)
	caCert, err := m.CACert()
	if err != nil {
		t.Fatalf("CACert: %v", err)
	}

	// Replace the CA certificate with one created the way older versions
	// did: same key, no CRLSign key usage, and a SHA-1 SubjectKeyId as
	// generated by go < 1.25.
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(caCert.RawSubjectPublicKeyInfo, &spki); err != nil {
		t.Fatalf("asn1.Unmarshal: %v", err)
	}
	sha1SKID := sha1.Sum(spki.PublicKey.Bytes)
	commit, err := m.open()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	m.db.IssuedCerts = nil
	if err := commit(true, &err); err != nil {
		t.Fatalf("commit: %v", err)
	}
	oldCA := newCACertForTest(t, m, x509.KeyUsageCertSign, sha1SKID[:], 1234)

	// Issue a leaf certificate with the old CA.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	csrRaw, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "leaf"},
	}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	cr, err := m.ValidateCertificateRequest(csrRaw)
	if err != nil {
		t.Fatalf("ValidateCertificateRequest: %v", err)
	}
	certBytes, err := m.IssueCertificate(cr)
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if !bytes.Equal(leaf.AuthorityKeyId, oldCA.SubjectKeyId) {
		t.Fatalf("leaf.AuthorityKeyId = %x, want %x", leaf.AuthorityKeyId, oldCA.SubjectKeyId)
	}

	// Re-issue the CA certificate (adds CRLSign).
	if err := m.initCA(); err != nil {
		t.Fatalf("initCA: %v", err)
	}
	newCA, err := m.CACert()
	if err != nil {
		t.Fatalf("CACert: %v", err)
	}
	if newCA.SerialNumber.Cmp(oldCA.SerialNumber) == 0 {
		t.Errorf("CA certificate was not re-issued")
	}
	if newCA.KeyUsage&x509.KeyUsageCRLSign == 0 {
		t.Errorf("re-issued CA certificate doesn't have CRLSign")
	}
	if !bytes.Equal(newCA.SubjectKeyId, oldCA.SubjectKeyId) {
		t.Errorf("re-issued CA SubjectKeyId = %x, want %x", newCA.SubjectKeyId, oldCA.SubjectKeyId)
	}
	if !bytes.Equal(leaf.AuthorityKeyId, newCA.SubjectKeyId) {
		t.Errorf("leaf.AuthorityKeyId = %x, re-issued CA SubjectKeyId = %x", leaf.AuthorityKeyId, newCA.SubjectKeyId)
	}
	ids, err := m.KeyIDs()
	if err != nil {
		t.Fatalf("KeyIDs: %v", err)
	}
	if want := []string{hex.EncodeToString(newCA.SubjectKeyId)}; !slices.Equal(ids, want) {
		t.Errorf("KeyIDs() = %v, want %v", ids, want)
	}
	// The old CA certificate must have been replaced in the issued list.
	var caCount int
	for _, c := range m.db.IssuedCerts {
		if cert, _ := c.parse(); cert != nil && cert.IsCA && cert.Subject.CommonName == m.opts.Name {
			caCount++
		}
	}
	if caCount != 1 {
		t.Errorf("found %d CA certificates in IssuedCerts, want 1", caCount)
	}

	// Simulate a CA certificate that was already re-issued with a
	// different (go default) SubjectKeyId. KeyIDs must still return the
	// AuthorityKeyId used by the issued certificates.
	otherCA := newCACertForTest(t, m, x509.KeyUsageCertSign|x509.KeyUsageCRLSign, nil, 5678)
	if bytes.Equal(otherCA.SubjectKeyId, leaf.AuthorityKeyId) {
		t.Fatalf("test setup: expected a different SubjectKeyId")
	}
	ids, err = m.KeyIDs()
	if err != nil {
		t.Fatalf("KeyIDs: %v", err)
	}
	for _, want := range []string{hex.EncodeToString(otherCA.SubjectKeyId), hex.EncodeToString(leaf.AuthorityKeyId)} {
		if !slices.Contains(ids, want) {
			t.Errorf("KeyIDs() = %v, missing %s", ids, want)
		}
	}
}
