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

// Package certmanager implements an X509 certificate manager that can replace
// https://pkg.go.dev/golang.org/x/crypto/acme/autocert#Manager for testing
// purposes.
// This certificate manager is a self-signed certificate authority that is not
// and should not be trusted for securing any real life communication.
package certmanager

import (
	"fmt"
	"testing"
)

func TestGetCertCache(t *testing.T) {
	cm, err := New("test", t.Logf)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c1, err := cm.GetCert("foo.example.com")
	if err != nil {
		t.Fatalf("GetCert: %v", err)
	}
	c2, err := cm.GetCert("bar.example.com")
	if err != nil {
		t.Fatalf("GetCert: %v", err)
	}
	if c1.PrivateKey != c2.PrivateKey {
		t.Error("certs don't share the same key")
	}
	if c3, err := cm.GetCert("foo.example.com"); err != nil || c3 != c1 {
		t.Errorf("GetCert didn't return cached cert: %v", err)
	}
	for i := range maxCachedCerts + 1 {
		if _, err := cm.GetCert(fmt.Sprintf("n%d.example.com", i)); err != nil {
			t.Fatalf("GetCert: %v", err)
		}
	}
	if n := len(cm.certs); n > maxCachedCerts {
		t.Errorf("len(certs) = %d", n)
	}
}
