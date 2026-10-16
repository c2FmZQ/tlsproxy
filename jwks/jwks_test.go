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
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
)

func TestJWKS(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	ecKey384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey(P384): %v", err)
	}
	ecKey521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey(P521): %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}

	ks := New([]crypto.PublicKey{
		&ecKey.PublicKey,
		&ecKey384.PublicKey,
		&ecKey521.PublicKey,
		&rsaKey.PublicKey,
		edPub,
	})
	if len(ks.Keys) != 5 {
		t.Errorf("len(ks.Keys) = %d, want 5", len(ks.Keys))
	}
	if ks.Keys[0].Type != "EC" || ks.Keys[0].Curve != "P-256" {
		t.Errorf("ks.Keys[0] = %v, want EC/P-256", ks.Keys[0])
	}
	if ks.Keys[1].Type != "EC" || ks.Keys[1].Curve != "P-384" {
		t.Errorf("ks.Keys[1] = %v, want EC/P-384", ks.Keys[1])
	}
	if ks.Keys[2].Type != "EC" || ks.Keys[2].Curve != "P-521" {
		t.Errorf("ks.Keys[2] = %v, want EC/P-521", ks.Keys[2])
	}
	if ks.Keys[3].Type != "RSA" {
		t.Errorf("ks.Keys[3].Type = %q, want RSA", ks.Keys[3].Type)
	}
	if ks.Keys[4].Type != "OKP" {
		t.Errorf("ks.Keys[4].Type = %q, want OKP", ks.Keys[4].Type)
	}

	b, err := json.Marshal(ks)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var got JWKS
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if len(got.Keys) != 5 {
		t.Errorf("len(got.Keys) = %d, want 5", len(got.Keys))
	}
}

func TestJWKSValidation(t *testing.T) {
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	validEdJWK := PublicKeyToJWK(edPub)

	invalidKeys := []struct {
		name string
		jwk  JWK
	}{
		{
			name: "OKP short X",
			jwk:  JWK{Type: "OKP", Curve: "Ed25519", X: "AAAA"},
		},
		{
			name: "OKP wrong curve",
			jwk:  JWK{Type: "OKP", Curve: "X25519", X: validEdJWK.X},
		},
		{
			name: "RSA empty modulus",
			jwk:  JWK{Type: "RSA", N: "", E: "AQAB"},
		},
		{
			name: "RSA small modulus",
			jwk:  JWK{Type: "RSA", N: "AQAB", E: "AQAB"},
		},
		{
			name: "RSA even exponent",
			jwk:  JWK{Type: "RSA", N: validEdJWK.X, E: "Ag"},
		},
		{
			name: "EC off-curve point",
			jwk:  JWK{Type: "EC", Curve: "P-256", X: "AQ", Y: "AQ"},
		},
		{
			name: "Use enc instead of sig",
			jwk:  JWK{Type: "OKP", Use: "enc", Curve: "Ed25519", X: validEdJWK.X},
		},
	}

	for _, tc := range invalidKeys {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.jwk.PublicKey(); err == nil {
				t.Errorf("PublicKey() succeeded for invalid JWK %s, want error", tc.name)
			}
		})
	}
}
