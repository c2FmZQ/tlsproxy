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

package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/c2FmZQ/storage"
	jwt "github.com/golang-jwt/jwt/v5"
)

const (
	tlsProxyAuthCookie = "TLSPROXYAUTH"
	tokenKeyFile       = "token-keys"
)

type identityProvider interface {
	validateToken(token string) (string, error)
	domain() string
	callbackHostAndPath() (string, string, error)

	requestLogin(w http.ResponseWriter, req *http.Request, origURL string)
	handleCallback(w http.ResponseWriter, req *http.Request)
}

type tokenKeys struct {
	Keys []*tokenKey
}

type tokenKey struct {
	ctx          context.Context
	ID           string
	Key          []byte
	privKey      *ecdsa.PrivateKey
	CreationTime time.Time
}

type tokenManager struct {
	store *storage.Storage

	mu   sync.Mutex
	keys tokenKeys
}

func newTokenManager(store *storage.Storage) (*tokenManager, error) {
	tm := tokenManager{
		store: store,
	}
	store.CreateEmptyFile(tokenKeyFile, &tm.keys)
	if err := tm.refresh(); err != nil {
		return nil, err
	}
	return &tm, nil
}

func (tm *tokenManager) refreshLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Hour):
			if err := tm.refresh(); err != nil {
				log.Printf("ERR tokenManager.refresh(): %v", err)
			}
		}
	}
}

func (tm *tokenManager) refresh() (retErr error) {
	var keys tokenKeys
	commit, err := tm.store.OpenForUpdate(tokenKeyFile, &keys)
	if err != nil {
		return err
	}
	defer commit(false, &retErr)
	var changed bool

	if len(keys.Keys) == 0 {
		tk, err := createNewTokenKey()
		if err != nil {
			return err
		}
		keys.Keys = append(keys.Keys, tk)
		changed = true
	}

	newest := keys.Keys[len(keys.Keys)-1]
	now := time.Now().UTC()

	if newest.CreationTime.Add(24 * time.Hour).Before(now) {
		tk, err := createNewTokenKey()
		if err != nil {
			return err
		}
		keys.Keys = append(keys.Keys, tk)
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
		privKey, err := x509.ParseECPrivateKey(k.Key)
		if err != nil {
			return err
		}
		k.privKey = privKey
	}
	tm.mu.Lock()
	tm.keys = keys
	tm.mu.Unlock()
	return commit(true, nil)
}

func createNewTokenKey() (*tokenKey, error) {
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
		Key:          b,
		privKey:      privKey,
		CreationTime: time.Now(),
	}
	return tk, nil
}

func (tm *tokenManager) createToken(claims jwt.Claims) (string, error) {
	tk := tm.keys.Keys[0]
	for _, k := range tm.keys.Keys {
		// Pick the most recent key that's at least 2 hours old.
		if k.CreationTime.Add(2 * time.Hour).Before(time.Now()) {
			tk = k
		}
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = tk.ID
	return tok.SignedString(tk.privKey)
}

func (tm *tokenManager) validateToken(t string, opts ...jwt.ParserOption) (*jwt.Token, error) {
	opts = append(opts, jwt.WithValidMethods([]string{"ES256"}))
	getKey := func(tok *jwt.Token) (interface{}, error) {
		for _, tk := range tm.keys.Keys {
			if tk.ID == tok.Header["kid"] {
				return tk.privKey.Public(), nil
			}
		}
		return nil, errors.New("not found")
	}
	return jwt.ParseWithClaims(t, jwt.MapClaims{}, getKey, opts...)
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Type  string `json:"kty"`
	Use   string `json:"use"`
	ID    string `json:"kid"`
	Alg   string `json:"alg"`
	Curve string `json:"crv"`
	X     string `json:"x"`
	Y     string `json:"y"`
}

func (tm *tokenManager) serveJWKS(w http.ResponseWriter, req *http.Request) {
	logRequest(req)
	tm.mu.Lock()
	var out jwks
	for _, key := range tm.keys.Keys {
		pub := key.privKey.PublicKey
		out.Keys = append(out.Keys, jwk{
			Type:  "EC",
			Use:   "sig",
			ID:    key.ID,
			Alg:   "ES256",
			Curve: "P-256",
			X:     base64.RawURLEncoding.EncodeToString(pub.X.Bytes()),
			Y:     base64.RawURLEncoding.EncodeToString(pub.Y.Bytes()),
		})
	}
	tm.mu.Unlock()

	w.Header().Set("content-type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(out)
}
