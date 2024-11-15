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

package passkeys

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"

	cbor "github.com/fxamacker/cbor/v2"
)

// FakeAuthenticator mimics the behavior of a WebAuthn authenticator for testing.
type FakeAuthenticator struct {
	keys     map[string]fakeAuthKey
	rpIDHash []byte
	origin   string
}

type fakeAuthKey struct {
	id         []byte
	uid        []byte
	rk         bool
	privateKey crypto.Signer
	signCount  uint32
}

// NewFakeAuthenticator returns a new FakeAuthenticator for testing.
func NewFakeAuthenticator() (*FakeAuthenticator, error) {
	return &FakeAuthenticator{
		keys:   make(map[string]fakeAuthKey),
		origin: "https://example.com/",
	}, nil
}

func (a *FakeAuthenticator) SetOrigin(orig string) {
	a.origin = orig
}

// Create mimics the behavior of the WebAuthn create call.
func (a *FakeAuthenticator) Create(options *AttestationOptions) (clientDataJSON, attestationObject []byte, err error) {
	var authKey fakeAuthKey
	var coseKey []byte
	switch options.PubKeyCredParams[0].Alg {
	case algES256:
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		if coseKey, err = es256CoseKey(privKey.PublicKey); err != nil {
			return nil, nil, err
		}
		authKey.privateKey = privKey
	case algRS256:
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, err
		}
		if coseKey, err = rs256CoseKey(privKey.PublicKey); err != nil {
			return nil, nil, err
		}
		authKey.privateKey = privKey
	default:
		return nil, nil, errors.New("unexpected options.PubKeyCredParams alg")
	}
	cd := clientData{
		Type:      "webauthn.create",
		Challenge: base64.RawURLEncoding.EncodeToString(options.Challenge),
		Origin:    a.origin,
	}
	if clientDataJSON, err = json.Marshal(cd); err != nil {
		return nil, nil, err
	}

	authKey.uid = options.User.ID
	authKey.rk = options.AuthenticatorSelection.ResidentKey == "preferred" || options.AuthenticatorSelection.ResidentKey == "required"

	authKey.id = make([]byte, 32)
	if _, err := rand.Read(authKey.id); err != nil {
		return nil, nil, err
	}
	rpIDHash := sha256.Sum256([]byte(options.RelyingParty.ID))
	a.rpIDHash = rpIDHash[:]

	authData, err := authKey.makeAuthData(a.rpIDHash, coseKey)
	if err != nil {
		return nil, nil, err
	}
	att := attestation{
		Format:      "none",
		RawAuthData: authData,
	}
	if attestationObject, err = cbor.Marshal(att); err != nil {
		return nil, nil, err
	}
	a.keys[base64.RawURLEncoding.EncodeToString(authKey.id)] = authKey
	return
}

// Get mimics the behavior of the WebAuthn create call.
func (a *FakeAuthenticator) Get(options *AssertionOptions) (id []byte, clientDataJSON, authData, signature, userHandle []byte, err error) {
	var authKey fakeAuthKey
	if len(options.AllowCredentials) > 0 {
		for _, k := range options.AllowCredentials {
			if ak, ok := a.keys[base64.RawURLEncoding.EncodeToString(k.ID)]; ok {
				id = k.ID
				authKey = ak
				break
			}
		}
	} else {
		for kid, key := range a.keys {
			if key.rk {
				id, _ = base64.RawURLEncoding.DecodeString(kid)
				authKey = key
				userHandle = key.uid
				break
			}
		}
	}
	if len(id) == 0 {
		err = errors.New("key not found")
		return
	}
	cd := clientData{
		Type:      "webauthn.get",
		Challenge: base64.RawURLEncoding.EncodeToString(options.Challenge),
		Origin:    "https://example.com/",
	}
	if clientDataJSON, err = json.Marshal(cd); err != nil {
		return
	}
	authKey.signCount++
	if authData, err = authKey.makeAuthData(a.rpIDHash, nil); err != nil {
		return
	}
	signature, err = sign(authKey, authData, clientDataJSON)
	return
}

func (a *FakeAuthenticator) RotateKeys() error {
	for k, v := range a.keys {
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		v.privateKey = privKey
		a.keys[k] = v
	}
	return nil
}

func (k *fakeAuthKey) makeAuthData(rpIDHash, coseKey []byte) ([]byte, error) {
	var buf bytes.Buffer
	buf.Write(rpIDHash)

	var bits uint8
	bits |= 1      // UP
	bits |= 1 << 2 // UV
	if coseKey != nil {
		bits |= 1 << 6 // AT
	}
	buf.Write([]byte{bits})
	binary.Write(&buf, binary.BigEndian, k.signCount)

	if coseKey != nil {
		var aaguid [16]byte
		buf.Write(aaguid[:])
		binary.Write(&buf, binary.BigEndian, uint16(len(k.id)))
		buf.Write(k.id)
		buf.Write(coseKey)
	}
	return buf.Bytes(), nil
}

// es256CoseKey converts a ECDSA public key to COSE.
func es256CoseKey(publicKey ecdsa.PublicKey) ([]byte, error) {
	if publicKey.Curve != elliptic.P256() {
		return nil, errors.New("unexpected EC curve")
	}
	ecKey := struct {
		KTY   int    `cbor:"1,keyasint"`
		ALG   int    `cbor:"3,keyasint"`
		Curve int    `cbor:"-1,keyasint"`
		X     []byte `cbor:"-2,keyasint"`
		Y     []byte `cbor:"-3,keyasint"`
	}{
		KTY:   2,
		ALG:   algES256,
		Curve: 1, // P-256
		X:     publicKey.X.Bytes(),
		Y:     publicKey.Y.Bytes(),
	}
	return cbor.Marshal(ecKey)
}

// rs256CoseKey converts a RSA public key to COSE.
func rs256CoseKey(publicKey rsa.PublicKey) ([]byte, error) {
	rsaKey := struct {
		KTY int    `cbor:"1,keyasint"`
		ALG int    `cbor:"3,keyasint"`
		N   []byte `cbor:"-1,keyasint"`
		E   int    `cbor:"-2,keyasint"`
	}{
		KTY: 3,
		ALG: algRS256,
		N:   publicKey.N.Bytes(),
		E:   publicKey.E,
	}
	return cbor.Marshal(rsaKey)
}

func sign(authKey fakeAuthKey, authData, clientDataJSON []byte) ([]byte, error) {
	signedBytes := signedBytes(authData, clientDataJSON)
	hashed := sha256.Sum256(signedBytes)
	return authKey.privateKey.Sign(rand.Reader, hashed[:], crypto.SHA256)
}
