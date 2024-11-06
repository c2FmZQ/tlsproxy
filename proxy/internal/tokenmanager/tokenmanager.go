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
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math/big"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/c2FmZQ/storage"
	"github.com/c2FmZQ/tpm"
	jwt "github.com/golang-jwt/jwt/v5"
)

const (
	tokenKeyFile = "token-keys"
)

type tokenKeys struct {
	Keys []*tokenKey
}

type privateKey interface {
	Public() crypto.PublicKey
}

type tokenKey struct {
	ID           string
	Type         string
	Key          []byte
	privKey      privateKey
	CreationTime time.Time
}

type logger interface {
	Errorf(format string, args ...any)
}

type defaultLogger struct{}

func (defaultLogger) Errorf(format string, args ...any) {
	log.Printf(format, args...)
}

// TokenManager implements a simple JSON Web Token (JWT) and JSON Web Key (JWK)
// management system. It manages key rotation, token creation, and token
// validation.
type TokenManager struct {
	store  *storage.Storage
	tpm    *tpm.TPM
	logger logger

	mu   sync.Mutex
	keys tokenKeys
}

// New returns a new TokenManager.
func New(store *storage.Storage, tpm *tpm.TPM, logger logger) (*TokenManager, error) {
	if logger == nil {
		logger = defaultLogger{}
	}
	tm := TokenManager{
		store:  store,
		tpm:    tpm,
		logger: logger,
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
				tm.logger.Errorf("ERR tokenManager.rotateKeys(): %v", err)
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
		tk, err := tm.createNewTokenKeys()
		if err != nil {
			return err
		}
		keys.Keys = append(keys.Keys, tk...)
		changed = true
	}

	newest := keys.Keys[len(keys.Keys)-1]
	now := time.Now().UTC()

	if newest.CreationTime.Add(24 * time.Hour).Before(now) {
		tk, err := tm.createNewTokenKeys()
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
		if tm.tpm != nil {
			privKey, err := tm.tpm.UnmarshalKey(k.Key)
			if err != nil {
				tm.logger.Errorf("ERR tpm.UnmarshalKey: %v", err)
				continue
			}
			k.privKey = privKey
			continue
		}
		privKey, err := x509.ParsePKCS8PrivateKey(k.Key)
		if err != nil {
			tm.logger.Errorf("ERR x509.ParsePKCS8PrivateKey: %v", err)
			continue
		}
		k.privKey = privKey.(privateKey)
	}
	keys.Keys = slices.DeleteFunc(keys.Keys, func(k *tokenKey) bool {
		return k.privKey == nil
	})
	tm.mu.Lock()
	tm.keys = keys
	tm.mu.Unlock()
	return commit(true, nil)
}

func (tm *TokenManager) createNewTokenKeys() ([]*tokenKey, error) {
	if tm.tpm != nil {
		ecKey, err := tm.createNewTPMECDSATokenKey()
		if err != nil {
			return nil, err
		}
		rsaKey, err := tm.createNewTPMRSATokenKey()
		if err != nil {
			return nil, err
		}
		return []*tokenKey{ecKey, rsaKey}, nil
	}
	ecKey, err := createNewECDSATokenKey()
	if err != nil {
		return nil, err
	}
	rsaKey, err := createNewRSATokenKey()
	if err != nil {
		return nil, err
	}
	edKey, err := createNewED25519TokenKey()
	if err != nil {
		return nil, err
	}
	return []*tokenKey{ecKey, rsaKey, edKey}, nil
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
	b, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, err
	}
	tk := &tokenKey{
		ID:           hex.EncodeToString(id[:]),
		Key:          b,
		privKey:      privKey,
		CreationTime: time.Now(),
	}
	return tk, nil
}

func (tm *TokenManager) createNewTPMECDSATokenKey() (*tokenKey, error) {
	var id [16]byte
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		return nil, err
	}
	privKey, err := tm.tpm.CreateKey(tpm.WithECC(elliptic.P256()))
	if err != nil {
		return nil, err
	}
	b, err := privKey.Marshal()
	if err != nil {
		return nil, err
	}
	tk := &tokenKey{
		ID:           hex.EncodeToString(id[:]),
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
	b, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, err
	}
	tk := &tokenKey{
		ID:           hex.EncodeToString(id[:]),
		Key:          b,
		privKey:      privKey,
		CreationTime: time.Now(),
	}
	return tk, nil
}

func (tm *TokenManager) createNewTPMRSATokenKey() (*tokenKey, error) {
	var id [16]byte
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		return nil, err
	}
	privKey, err := tm.tpm.CreateKey(tpm.WithRSA(2048))
	if err != nil {
		return nil, err
	}
	b, err := privKey.Marshal()
	if err != nil {
		return nil, err
	}
	tk := &tokenKey{
		ID:           hex.EncodeToString(id[:]),
		Key:          b,
		privKey:      privKey,
		CreationTime: time.Now(),
	}
	return tk, nil
}

func createNewED25519TokenKey() (*tokenKey, error) {
	var id [16]byte
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		return nil, err
	}
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	mPrivKey, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, err
	}
	tk := &tokenKey{
		ID:           hex.EncodeToString(id[:]),
		Key:          mPrivKey,
		privKey:      privKey,
		CreationTime: time.Now(),
	}
	return tk, nil
}

// CreateToken creates a new JSON Web Token (JWT) with the provided claims.
func (tm *TokenManager) CreateToken(claims jwt.Claims, alg string) (string, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	if alg == "" {
		if tm.tpm != nil {
			alg = "ES256"
		} else {
			alg = "EdDSA"
		}
	}

	method := jwt.GetSigningMethod(alg)
	if method == nil {
		return "", errors.New("unknown signing method")
	}
	var tk *tokenKey
	for _, k := range tm.keys.Keys {
		switch method.(type) {
		case *jwt.SigningMethodECDSA:
			if _, ok := k.privKey.Public().(*ecdsa.PublicKey); !ok {
				continue
			}
		case *jwt.SigningMethodEd25519:
			if _, ok := k.privKey.Public().(ed25519.PublicKey); !ok {
				continue
			}
		case *jwt.SigningMethodRSA:
			if _, ok := k.privKey.Public().(*rsa.PublicKey); !ok {
				continue
			}
		default:
			continue
		}
		// Pick the most recent key that's at least 2 hours old.
		if tk == nil || k.CreationTime.Add(2*time.Hour).Before(time.Now()) {
			tk = k
		}
	}
	tok := jwt.NewWithClaims(&tpmSigningMethod{method}, claims)
	tok.Header["kid"] = tk.ID
	return tok.SignedString(tk.privKey)
}

type tpmSigningMethod struct {
	jwt.SigningMethod
}

func (m *tpmSigningMethod) Sign(signingString string, key interface{}) ([]byte, error) {
	k, ok := key.(*tpm.Key)
	if !ok {
		return m.SigningMethod.Sign(signingString, key)
	}
	switch sm := m.SigningMethod.(type) {
	case *jwt.SigningMethodECDSA:
		if sm.CurveBits != k.Curve().Params().BitSize {
			return nil, jwt.ErrInvalidKey
		}
		hasher := sm.Hash.New()
		hasher.Write([]byte(signingString))
		sig, err := k.Sign(nil, hasher.Sum(nil), sm.Hash)
		if err != nil {
			return nil, err
		}
		var ss []*big.Int
		if _, err := asn1.Unmarshal(sig, &ss); err != nil {
			return nil, err
		}
		if len(ss) != 2 {
			return nil, errors.New("invalid ecdsa signature")
		}
		sz := sm.CurveBits / 8
		out := make([]byte, 2*sz)
		ss[0].FillBytes(out[:sz])
		ss[1].FillBytes(out[sz:])
		return out, nil

	case *jwt.SigningMethodRSA:
		hasher := sm.Hash.New()
		hasher.Write([]byte(signingString))
		return k.Sign(nil, hasher.Sum(nil), sm.Hash)

	default:
		return m.SigningMethod.Sign(signingString, key)
	}
}

func (tm *TokenManager) getKey(tok *jwt.Token) (interface{}, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	for _, tk := range tm.keys.Keys {
		if tk.ID == tok.Header["kid"] {
			return tk.privKey.Public(), nil
		}
	}
	return nil, errors.New("not found")
}

// ValidateToken validates a JSON Web Token (JWT).
func (tm *TokenManager) ValidateToken(t string, opts ...jwt.ParserOption) (*jwt.Token, error) {
	opts = append(opts, jwt.WithValidMethods([]string{"ES256", "RS256", "EdDSA"}))
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
		switch pub := key.privKey.Public().(type) {
		case *ecdsa.PublicKey:
			out.Keys = append(out.Keys, jwk{
				Type:  "EC",
				Use:   "sig",
				ID:    key.ID,
				Alg:   "ES256",
				Curve: "P-256",
				X:     base64.RawURLEncoding.EncodeToString(pub.X.Bytes()),
				Y:     base64.RawURLEncoding.EncodeToString(pub.Y.Bytes()),
			})
		case ed25519.PublicKey:
			out.Keys = append(out.Keys, jwk{
				Type:  "OKP",
				Use:   "sig",
				ID:    key.ID,
				Alg:   "EdDSA",
				Curve: "Ed25519",
				X:     base64.RawURLEncoding.EncodeToString(pub),
			})
		case *rsa.PublicKey:
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
