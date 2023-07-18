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

package certmanager_test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/c2FmZQ/tlsproxy/certmanager"
)

func TestCertsAreValid(t *testing.T) {
	cm, err := certmanager.New("test", t.Logf)
	if err != nil {
		t.Fatalf("certmanager.New: %v", err)
	}
	block, _ := pem.Decode([]byte(cm.RootCAPEM()))
	rootCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("x509.ParseCertificate: %v", err)
	}
	if got, want := rootCert.Subject.String(), "CN=test"; got != want {
		t.Errorf("Subject = %q, want %q", got, want)
	}
	if _, err := rootCert.Verify(x509.VerifyOptions{
		Roots:     cm.RootCACertPool(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Errorf("Verify: %v", err)
	}

	cert, err := cm.GetCert("hello.example.com")
	if err != nil {
		t.Fatalf("cm.GetCert: %v", err)
	}
	if got, want := cert.Leaf.Subject.String(), "CN=hello.example.com"; got != want {
		t.Errorf("Subject = %q, want %q", got, want)
	}
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{
		DNSName:   "hello.example.com",
		Roots:     cm.RootCACertPool(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Errorf("Verify: %v", err)
	}
	if !cert.PrivateKey.(*rsa.PrivateKey).PublicKey.Equal(cert.Leaf.PublicKey) {
		t.Error("Cert public key doesn't match the private key")
	}
}
