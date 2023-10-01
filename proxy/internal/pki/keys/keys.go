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

package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"strings"
)

// GenerateKey generates a cryptographic key of the given type.
func GenerateKey(keyType string) (crypto.PrivateKey, error) {
	switch kt := strings.ToLower(keyType); kt {
	case "ed25519":
		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		return privKey, err

	case "ecdsa-p224", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521":
		var crv elliptic.Curve
		switch kt {
		case "ecdsa-p224":
			crv = elliptic.P224()
		case "ecdsa-p256":
			crv = elliptic.P256()
		case "ecdsa-p384":
			crv = elliptic.P384()
		case "ecdsa-p521":
			crv = elliptic.P521()
		}
		return ecdsa.GenerateKey(crv, rand.Reader)

	case "rsa-2048", "rsa-3072", "rsa-4096", "rsa-8192":
		var bits int
		switch kt {
		case "rsa-2048":
			bits = 2048
		case "rsa-3072":
			bits = 3072
		case "rsa-4096":
			bits = 4096
		case "rsa-8192":
			bits = 8192
		}
		return rsa.GenerateKey(rand.Reader, bits)

	default:
		return nil, fmt.Errorf("unexpected key type: %q", keyType)
	}
}
