// MIT License
//
// Copyright (c) 2024 TTBT Enterprises LLC
// Copyright (c) 2024 Robin Thellend <rthellend@rthellend.com>
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

package jwks

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRemote(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	ks := New([]crypto.PublicKey{&ecKey.PublicKey})
	b, err := json.Marshal(ks)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	}))
	defer ts.Close()

	r := NewRemote(nil, nil)
	r.SetIssuers([]Issuer{{
		Issuer:  "https://example.com",
		JWKSURI: ts.URL,
	}})
	r.Ready(t.Context())

	pk, err := r.GetKey(ks.Keys[0].ID)
	if err != nil {
		t.Fatalf("r.GetKey: %v", err)
	}
	if pk.(*ecdsa.PublicKey).X.Cmp(ecKey.X) != 0 {
		t.Error("PublicKey mismatch")
	}

	if issuer, ok := r.IssuerForKey(ks.Keys[0].ID); !ok || issuer != "https://example.com" {
		t.Errorf("IssuerForKey = %q, want https://example.com", issuer)
	}
}

func TestRemoteKidCollision(t *testing.T) {
	ecKeyA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	ecKeyB, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	ksA := New([]crypto.PublicKey{&ecKeyA.PublicKey})
	ksA.Keys[0].ID = "shared-kid"
	bA, _ := json.Marshal(ksA)

	ksB := New([]crypto.PublicKey{&ecKeyB.PublicKey})
	ksB.Keys[0].ID = "shared-kid"
	bB, _ := json.Marshal(ksB)

	tsA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(bA)
	}))
	defer tsA.Close()

	tsB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(bB)
	}))
	defer tsB.Close()

	// Callers use one Remote per trusted issuer so that keys with the same
	// kid from different issuers are never confused.
	rA := NewRemote(nil, nil)
	rA.SetIssuers([]Issuer{{Issuer: "https://issuer-a.example.com", JWKSURI: tsA.URL}})
	rA.Ready(t.Context())
	rB := NewRemote(nil, nil)
	rB.SetIssuers([]Issuer{{Issuer: "https://issuer-b.example.com", JWKSURI: tsB.URL}})
	rB.Ready(t.Context())

	for i := range 50 {
		pkA, err := rA.GetKey("shared-kid")
		if err != nil {
			t.Fatalf("iteration %d: rA.GetKey: %v", i, err)
		}
		if pkA.(*ecdsa.PublicKey).X.Cmp(ecKeyA.X) != 0 {
			t.Fatalf("iteration %d: rA.GetKey returned wrong key", i)
		}
		pkB, err := rB.GetKey("shared-kid")
		if err != nil {
			t.Fatalf("iteration %d: rB.GetKey: %v", i, err)
		}
		if pkB.(*ecdsa.PublicKey).X.Cmp(ecKeyB.X) != 0 {
			t.Fatalf("iteration %d: rB.GetKey returned wrong key", i)
		}
	}
}
