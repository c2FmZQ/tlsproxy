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

// Package passkeys implements the server side of WebAuthn.
package passkeys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	cbor "github.com/fxamacker/cbor/v2"
)

const (
	// https://w3c.github.io/webauthn/#sctn-alg-identifier
	algES256 = -7
	algRS256 = -257
)

// errTooShort indicates that the message is too short and can't be decoded.
var errTooShort = errors.New("too short")

type Bytes []byte

func (b Bytes) MarshalJSON() ([]byte, error) {
	if b == nil {
		return []byte("null"), nil
	}
	return []byte(strings.Join(strings.Fields(fmt.Sprintf("%d", b)), ",")), nil
}

// AttestationOptions encapsulates the options to navigator.credentials.create().
type AttestationOptions struct {
	// The cryptographic challenge is 32 random bytes.
	Challenge Bytes `json:"challenge"`
	// The name of the relying party. The ID is optional.
	RelyingParty struct {
		Name string `json:"name"`
		ID   string `json:"id,omitempty"`
	} `json:"rp"`
	// The user information.
	User struct {
		ID          Bytes  `json:"id"`
		Name        string `json:"name"`
		DisplayName string `json:"displayName"`
	} `json:"user"`
	// The acceptable public key params.
	PubKeyCredParams []PubKeyCredParam `json:"pubKeyCredParams,omitempty"`
	// Timeout in milliseconds.
	Timeout int `json:"timeout,omitempty"`
	// A list of credentials already registered for this user.
	ExcludeCredentials []CredentialID `json:"excludeCredentials,omitempty"`
	// The type of attestation
	Attestation string `json:"attestation,omitempty"`
	// Authticator selection parameters.
	AuthenticatorSelection struct {
		// required, preferred, or discouraged
		UserVerification string `json:"userVerification"`
		// required, preferred, or discouraged
		ResidentKey string `json:"residentKey"`
	} `json:"authenticatorSelection"`
	// Extensions.
	Extensions map[string]interface{} `json:"extensions,omitempty"`
}

// newAttestationOptions returns a new AttestationOptions with Challenge,
// PubKeyCredParams, and Timeout already populated.
func newAttestationOptions() (*AttestationOptions, error) {
	ao := &AttestationOptions{
		PubKeyCredParams: []PubKeyCredParam{
			{
				Type: "public-key",
				Alg:  algES256,
			},
			{
				Type: "public-key",
				Alg:  algRS256,
			},
		},
		Timeout: 120000, // 120 sec
		// No needed with passkeys.
		Attestation: "none",
	}
	ao.AuthenticatorSelection.UserVerification = "required"
	ao.AuthenticatorSelection.ResidentKey = "preferred"

	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, err
	}
	ao.Challenge = challenge
	return ao, nil
}

// AssertionOptions encapsulates the options to navigator.credentials.get().
type AssertionOptions struct {
	// The cryptographic challenge is 32 random bytes.
	Challenge Bytes `json:"challenge"`
	// Timeout in milliseconds.
	Timeout int `json:"timeout,omitempty"`
	// A list of credentials already registered for this user.
	AllowCredentials []CredentialID `json:"allowCredentials"`
	// UserVerification: required, preferred, discouraged
	UserVerification string `json:"userVerification"`
}

// newAssertionOptions returns a new AssertionOptions with Challenge,
// and Timeout already populated.
func newAssertionOptions() (*AssertionOptions, error) {
	ao := &AssertionOptions{
		Timeout:          120000, // 120 sec
		UserVerification: "required",
		AllowCredentials: make([]CredentialID, 0),
	}
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, err
	}
	ao.Challenge = challenge
	return ao, nil
}

// PubKeyCredParam: Public key credential parameters.
type PubKeyCredParam struct {
	// The type of credentials. Always "public-key"
	Type string `json:"type"`
	// The encryption algorythm: -7 for ES256, -257 for RS256.
	Alg int `json:"alg"`
}

// CredentialID is a credential ID from an anthenticator.
type CredentialID struct {
	// The type of credentials. Always "public-key"
	Type string `json:"type"`
	// The credential ID.
	ID Bytes `json:"id"`
	// The available transports for this credential.
	Transports []string `json:"transports,omitempty"`
}

// clientData is a decoded ClientDataJSON object.
type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

// attestation. https://w3c.github.io/webauthn/#sctn-attestation
type attestation struct {
	Format      string          `cbor:"fmt"`
	AttStmt     cbor.RawMessage `cbor:"attStmt"`
	RawAuthData []byte          `cbor:"authData"`

	AuthData authenticatorData `cbor:"-"`
}

// authenticatorData is the authenticator data provided during attestation and
// assertion. https://w3c.github.io/webauthn/#sctn-authenticator-data
type authenticatorData struct {
	RPIDHash               Bytes                `json:"rpIdHash"`
	UserPresence           bool                 `json:"up"`
	BackupEligible         bool                 `json:"be"`
	BackupState            bool                 `json:"bs"`
	UserVerification       bool                 `json:"uv"`
	AttestedCredentialData bool                 `json:"at"`
	ExtensionData          bool                 `json:"ed"`
	SignCount              uint32               `json:"signCount"`
	AttestedCredentials    *attestedCredentials `json:"attestedCredentialData"`
}

// attestedCredentials. https://w3c.github.io/webauthn/#sctn-attested-credential-data
type attestedCredentials struct {
	AAGUID  Bytes `json:"AAGUID"`
	ID      Bytes `json:"credentialId"`
	COSEKey Bytes `json:"credentialPublicKey"`
}

// parseAttestationObject parses an attestationObject. Passkeys don't typically
// provide attestation statements.
func parseAttestationObject(attestationObject []byte) (*attestation, error) {
	var att attestation
	if err := cbor.Unmarshal(attestationObject, &att); err != nil {
		return nil, fmt.Errorf("cbor.Unmarshal: %w", err)
	}
	if err := parseAuthenticatorData(att.RawAuthData, &att.AuthData); err != nil {
		return nil, fmt.Errorf("parseAuthenticatorData: %w", err)
	}
	return &att, nil
}

func parseAuthenticatorData(raw []byte, ad *authenticatorData) error {
	// https://w3c.github.io/webauthn/#sctn-authenticator-data
	if len(raw) < 37 {
		return errTooShort
	}
	ad.RPIDHash = raw[:32]
	raw = raw[32:]
	ad.UserPresence = raw[0]&1 != 0
	ad.UserVerification = (raw[0]>>2)&1 != 0
	ad.BackupEligible = (raw[0]>>3)&1 != 0
	ad.BackupState = (raw[0]>>4)&1 != 0
	ad.AttestedCredentialData = (raw[0]>>6)&1 != 0
	ad.ExtensionData = (raw[0]>>7)&1 != 0
	raw = raw[1:]
	ad.SignCount = binary.BigEndian.Uint32(raw[:4])
	raw = raw[4:]

	if ad.AttestedCredentialData {
		// https://w3c.github.io/webauthn/#sctn-attested-credential-data
		if len(raw) < 18 {
			return errTooShort
		}
		ad.AttestedCredentials = &attestedCredentials{}
		ad.AttestedCredentials.AAGUID = raw[:16]
		raw = raw[16:]

		sz := binary.BigEndian.Uint16(raw[:2])
		raw = raw[2:]
		if sz > 1023 {
			return errors.New("invalid credentialId length")
		}
		if len(raw) < int(sz) {
			return errTooShort
		}
		ad.AttestedCredentials.ID = raw[:int(sz)]
		raw = raw[int(sz):]

		var coseKey cbor.RawMessage
		var err error
		if raw, err = cbor.UnmarshalFirst(raw, &coseKey); err != nil {
			return err
		}
		ad.AttestedCredentials.COSEKey = Bytes(coseKey)
	}
	if ad.ExtensionData {
		// Parse extensions
	}
	return nil
}

func parseClientData(js []byte) (*clientData, error) {
	var out clientData
	err := json.Unmarshal(js, &out)
	return &out, err
}

func signedBytes(authData, clientDataJSON []byte) []byte {
	clientDataHash := sha256.Sum256(clientDataJSON)
	signedBytes := make([]byte, len(authData)+len(clientDataHash))
	copy(signedBytes, authData)
	copy(signedBytes[len(authData):], clientDataHash[:])
	return signedBytes
}

// verifySignature verifies the webauthn signature.
func verifySignature(coseKey, authData, clientDataJSON, signature Bytes) error {
	signedBytes := signedBytes(authData, clientDataJSON)
	hashed := sha256.Sum256(signedBytes)

	var kty struct {
		KTY int `cbor:"1,keyasint"`
	}
	if err := cbor.Unmarshal(coseKey, &kty); err != nil {
		return fmt.Errorf("cbor.Unmarshal(%v): %w", coseKey, err)
	}
	switch kty.KTY {
	case 2: // ECDSA public key
		var ecKey struct {
			KTY   int    `cbor:"1,keyasint"`
			ALG   int    `cbor:"3,keyasint"`
			Curve int    `cbor:"-1,keyasint"`
			X     []byte `cbor:"-2,keyasint"`
			Y     []byte `cbor:"-3,keyasint"`
		}
		if err := cbor.Unmarshal(coseKey, &ecKey); err != nil {
			return err
		}
		if ecKey.ALG != algES256 {
			return errors.New("unexpected EC key alg")
		}
		if ecKey.Curve != 1 { // P-256
			return errors.New("unexpected EC key curve")
		}
		publicKey := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(ecKey.X),
			Y:     new(big.Int).SetBytes(ecKey.Y),
		}
		if !publicKey.Curve.IsOnCurve(publicKey.X, publicKey.Y) {
			return errors.New("invalid public key")
		}
		if !ecdsa.VerifyASN1(publicKey, hashed[:], signature) {
			return errors.New("invalid signature")
		}
		return nil
	case 3: // RSA public key, RSASSA-PKCS1-v1_5
		var rsaKey struct {
			KTY int    `cbor:"1,keyasint"`
			ALG int    `cbor:"3,keyasint"`
			N   []byte `cbor:"-1,keyasint"`
			E   int    `cbor:"-2,keyasint"`
		}
		if err := cbor.Unmarshal(coseKey, &rsaKey); err != nil {
			return err
		}
		if rsaKey.ALG != algRS256 {
			return errors.New("unexpected RSA key alg")
		}
		publicKey := &rsa.PublicKey{
			N: new(big.Int).SetBytes(rsaKey.N),
			E: rsaKey.E,
		}
		if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature); err != nil {
			return err
		}
		return nil
	default:
		return errors.New("unsupported key type")
	}
}
