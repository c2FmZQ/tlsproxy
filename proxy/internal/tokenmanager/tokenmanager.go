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

// Package tokenmanager implements a simple JSON Web Token (JWT) and JSON Web
// Key (JWK) management system. It manages key rotation, token creation, and
// token validation.
package tokenmanager

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/c2FmZQ/storage"
	jwt "github.com/golang-jwt/jwt/v5"
)

const (
	tokenKeyFile = "token-keys"
)

type tokenKeys struct {
	Keys []*tokenKey
}

type tokenKey struct {
	ID           string
	Type         string
	Key          []byte
	privKey      crypto.PrivateKey
	CreationTime time.Time
}

// TokenManager implements a simple JSON Web Token (JWT) and JSON Web Key (JWK)
// management system. It manages key rotation, token creation, and token
// validation.
type TokenManager struct {
	store *storage.Storage

	mu   sync.Mutex
	keys tokenKeys
}

// New returns a new TokenManager.
func New(store *storage.Storage) (*TokenManager, error) {
	tm := TokenManager{
		store: store,
	}
	store.CreateEmptyFile(tokenKeyFile, &tm.keys)
	if err := tm.rotateKeys(); err != nil {
		return nil, err
	}
	return &tm, nil
}

// KeyRotationLoop takes care of key rotation. It runs until ctx is canceled.
func (tm *TokenManager) KeyRotationLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Hour):
			if err := tm.rotateKeys(); err != nil && err != storage.ErrRolledBack {
				log.Printf("ERR tokenManager.rotateKeys(): %v", err)
			}
		}
	}
}

func (tm *TokenManager) rotateKeys() (retErr error) {
	var keys tokenKeys
	commit, err := tm.store.OpenForUpdate(tokenKeyFile, &keys)
	if err != nil {
		return err
	}
	defer commit(false, &retErr)
	var changed bool

	if len(keys.Keys) == 0 {
		tk, err := createNewTokenKeys()
		if err != nil {
			return err
		}
		keys.Keys = append(keys.Keys, tk...)
		changed = true
	}

	newest := keys.Keys[len(keys.Keys)-1]
	now := time.Now().UTC()

	if newest.CreationTime.Add(24 * time.Hour).Before(now) {
		tk, err := createNewTokenKeys()
		if err != nil {
			return err
		}
		keys.Keys = append(keys.Keys, tk...)
		changed = true
	}
	if keys.Keys[0].CreationTime.Add(7 * 24 * time.Hour).Before(now) {
		keys.Keys = keys.Keys[1:]
		changed = true
	}
	if !changed && len(tm.keys.Keys) > 0 {
		return nil
	}

	for _, k := range keys.Keys {
		if k.Type == "rsa" {
			privKey, err := x509.ParsePKCS1PrivateKey(k.Key)
			if err != nil {
				return err
			}
			k.privKey = privKey
		} else {
			k.Type = "ecdsa"
			privKey, err := x509.ParseECPrivateKey(k.Key)
			if err != nil {
				return err
			}
			k.privKey = privKey
		}
	}
	tm.mu.Lock()
	tm.keys = keys
	tm.mu.Unlock()
	return commit(true, nil)
}

func createNewTokenKeys() ([]*tokenKey, error) {
	ecKey, err := createNewECDSATokenKey()
	if err != nil {
		return nil, err
	}
	rsaKey, err := createNewRSATokenKey()
	if err != nil {
		return nil, err
	}
	return []*tokenKey{ecKey, rsaKey}, nil
}

func createNewECDSATokenKey() (*tokenKey, error) {
	var id [16]byte
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		return nil, err
	}
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	b, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, err
	}
	tk := &tokenKey{
		ID:           hex.EncodeToString(id[:]),
		Type:         "ecdsa",
		Key:          b,
		privKey:      privKey,
		CreationTime: time.Now(),
	}
	return tk, nil
}

func createNewRSATokenKey() (*tokenKey, error) {
	var id [16]byte
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		return nil, err
	}
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	tk := &tokenKey{
		ID:           hex.EncodeToString(id[:]),
		Type:         "rsa",
		Key:          x509.MarshalPKCS1PrivateKey(privKey),
		privKey:      privKey,
		CreationTime: time.Now(),
	}
	return tk, nil
}

// CreateToken creates a new JSON Web Token (JWT) with the provided claims.
func (tm *TokenManager) CreateToken(claims jwt.Claims, alg string) (string, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	method := jwt.GetSigningMethod(alg)
	if method == nil {
		return "", errors.New("unknown signing method")
	}
	var keyType string
	switch method.(type) {
	case *jwt.SigningMethodECDSA:
		keyType = "ecdsa"
	case *jwt.SigningMethodRSA:
		keyType = "rsa"
	}
	var tk *tokenKey
	for _, k := range tm.keys.Keys {
		// Pick the most recent key that's at least 2 hours old.
		if k.Type == keyType && (tk == nil || k.CreationTime.Add(2*time.Hour).Before(time.Now())) {
			tk = k
		}
	}
	tok := jwt.NewWithClaims(method, claims)
	tok.Header["kid"] = tk.ID
	return tok.SignedString(tk.privKey)
}

func (tm *TokenManager) getKey(tok *jwt.Token) (interface{}, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	for _, tk := range tm.keys.Keys {
		if tk.ID == tok.Header["kid"] {
			switch key := tk.privKey.(type) {
			case *ecdsa.PrivateKey:
				return key.Public(), nil
			case *rsa.PrivateKey:
				return key.Public(), nil
			}
		}
	}
	return nil, errors.New("not found")
}

// ValidateToken validates a JSON Web Token (JWT).
func (tm *TokenManager) ValidateToken(t string, opts ...jwt.ParserOption) (*jwt.Token, error) {
	opts = append(opts, jwt.WithValidMethods([]string{"ES256"}))
	return jwt.ParseWithClaims(t, jwt.MapClaims{}, tm.getKey, opts...)
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
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

// ServeJWKS returns the current public keys as a JSON Web Key Set (JWKS).
func (tm *TokenManager) ServeJWKS(w http.ResponseWriter, req *http.Request) {
	tm.mu.Lock()
	var out jwks
	for _, key := range tm.keys.Keys {
		switch pk := key.privKey.(type) {
		case *ecdsa.PrivateKey:
			pub := pk.PublicKey
			out.Keys = append(out.Keys, jwk{
				Type:  "EC",
				Use:   "sig",
				ID:    key.ID,
				Alg:   "ES256",
				Curve: "P-256",
				X:     base64.RawURLEncoding.EncodeToString(pub.X.Bytes()),
				Y:     base64.RawURLEncoding.EncodeToString(pub.Y.Bytes()),
			})
		case *rsa.PrivateKey:
			pub := pk.PublicKey
			out.Keys = append(out.Keys, jwk{
				Type: "RSA",
				Use:  "sig",
				ID:   key.ID,
				Alg:  "RS256",
				N:    base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				E:    base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			})
		}
	}
	tm.mu.Unlock()

	content, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	sum := sha256.Sum256(content)
	etag := `"` + hex.EncodeToString(sum[:]) + `"`

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("Etag", etag)

	if e := req.Header.Get("If-None-Match"); e == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(content)
}
