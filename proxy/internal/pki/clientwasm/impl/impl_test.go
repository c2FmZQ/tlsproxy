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

package impl

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestKeyTypeFormat(t *testing.T) {
	count := 0
	for _, tc := range []struct {
		keyType     string
		format      string
		label       string
		dnsName     string
		contentType string
		ext         string
	}{
		{keyType: "ed25519", format: "gpg", contentType: "application/octet-stream", ext: ".pem.gpg"},
		{keyType: "ecdsa-p521", format: "gpg", contentType: "application/octet-stream", ext: ".pem.gpg"},
		{keyType: "ecdsa-p256", format: "p12", contentType: "application/x-pkcs12", ext: ".p12"},
		{keyType: "rsa-2048", format: "p12", contentType: "application/x-pkcs12", ext: ".p12"},
		{keyType: "ed25519", format: "gpg", dnsName: "example.com", contentType: "application/octet-stream", ext: ".pem.gpg"},
	} {
		count++
		csrPEM, err := MakeCSR(count, tc.keyType, tc.format, tc.label, tc.dnsName, "foo")
		if err != nil {
			t.Fatalf("MakeCSR: %v", err)
		}
		block, _ := pem.Decode(csrPEM)
		if block == nil {
			t.Fatal("Error decoding PEM CSR")
		}
		if got, want := block.Type, "CERTIFICATE REQUEST"; got != want {
			t.Errorf("PEM type = %s, want %s", got, want)
		}

		cr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			t.Fatalf("x509.ParseCertificateRequest: %v", err)
		}

		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ed25519.GenerateKey: %v", err)
		}
		now := time.Now().UTC()
		sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 160))
		if err != nil {
			t.Fatalf("rand.Int: %v", err)
		}
		templ := &x509.Certificate{
			SerialNumber:          sn,
			PublicKeyAlgorithm:    cr.PublicKeyAlgorithm,
			Subject:               cr.Subject,
			NotBefore:             now,
			NotAfter:              now.Add(10 * time.Minute),
			KeyUsage:              x509.KeyUsageDataEncipherment | x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
		}
		raw, err := x509.CreateCertificate(rand.Reader, templ, templ, cr.PublicKey, privKey)
		if err != nil {
			t.Fatalf("x509.CreateCertificate: %v", err)
		}
		cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})

		_, contentType, fileName, err := MakeResponse(count, string(cert))
		if err != nil {
			t.Fatalf("MakeResponse: %v", err)
		}
		if got, want := contentType, tc.contentType; got != want {
			t.Errorf("content-type = %s, want %s", got, want)
		}
		if got, want := fileName, hex.EncodeToString(sn.Bytes())+tc.ext; got != want {
			t.Errorf("fileName = %s, want %s", got, want)
		}
	}
}
