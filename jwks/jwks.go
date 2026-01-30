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

// Package jwks implements a JSON Web Key Set (JWKS) management system.
package jwks

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
)

// JWKS is a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK is a JSON Web Key.
type JWK struct {
	Type string `json:"kty"`
	Use  string `json:"use"`
	ID   string `json:"kid"`
	Alg  string `json:"alg"`
	// EC
	Curve string `json:"crv,omitempty"`
	X     string `json:"x,omitempty"`
	Y     string `json:"y,omitempty"`
	// RSA
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`
}

// PublicKey returns the crypto.PublicKey from the JWK.
func (k JWK) PublicKey() (crypto.PublicKey, error) {
	switch k.Type {
	case "EC":
		var curve elliptic.Curve
		switch k.Curve {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported EC curve %q", k.Curve)
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, err
		}
		y, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, err
		}
		return &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}, nil
	case "RSA":
		n, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, err
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, err
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(eBytes).Int64())}, nil
	case "OKP": // EdDSA
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, err
		}
		return ed25519.PublicKey(x), nil
	default:
		return nil, fmt.Errorf("unknown key type %q", k.Type)
	}
}

// PublicKeyToJWK converts a crypto.PublicKey to a JWK.
func PublicKeyToJWK(pub crypto.PublicKey) *JWK {
	var jwk JWK
	switch pub := pub.(type) {
	case *ecdsa.PublicKey:
		var alg, crv string
		switch pub.Curve {
		case elliptic.P256():
			alg = "ES256"
			crv = "P-256"
		case elliptic.P384():
			alg = "ES384"
			crv = "P-384"
		case elliptic.P521():
			alg = "ES512"
			crv = "P-521"
		default:
			return nil
		}
		size := (pub.Curve.Params().BitSize + 7) / 8
		xBytes := make([]byte, size)
		yBytes := make([]byte, size)
		pub.X.FillBytes(xBytes)
		pub.Y.FillBytes(yBytes)
		jwk = JWK{
			Type:  "EC",
			Use:   "sig",
			Alg:   alg,
			Curve: crv,
			X:     base64.RawURLEncoding.EncodeToString(xBytes),
			Y:     base64.RawURLEncoding.EncodeToString(yBytes),
		}
	case ed25519.PublicKey:
		jwk = JWK{
			Type:  "OKP",
			Use:   "sig",
			Alg:   "EdDSA",
			Curve: "Ed25519",
			X:     base64.RawURLEncoding.EncodeToString(pub),
		}
	case *rsa.PublicKey:
		jwk = JWK{
			Type: "RSA",
			Use:  "sig",
			Alg:  "RS256",
			N:    base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E:    base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}
	default:
		return nil
	}
	// Calculate Key ID (kid)
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err == nil {
		sum := sha256.Sum256(b)
		jwk.ID = hex.EncodeToString(sum[:])[:16]
	}
	return &jwk
}

// New returns a new JWKS from the provided public keys.
// Note: RSA keys default to alg:"RS256", which may not be correct, and might need to be updated.
func New(keys []crypto.PublicKey) *JWKS {
	var out JWKS
	for _, pub := range keys {
		if k := PublicKeyToJWK(pub); k != nil {
			out.Keys = append(out.Keys, *k)
		}
	}
	return &out
}
