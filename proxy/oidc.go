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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"

	"github.com/c2FmZQ/tlsproxy/proxy/internal/netw"
)

const (
	tlsProxyAuthCookie = "TLSPROXYAUTH"
)

// oidcProvider handles the OIDC manual flow based on information from
// https://developers.google.com/identity/openid-connect/openid-connect and
// https://developers.facebook.com/docs/facebook-login/guides/advanced/oidc-token/
type oidcProvider struct {
	AuthEndpoint  string `json:"authorization_endpoint"`
	TokenEndpoint string `json:"token_endpoint"`

	cfg         ConfigOIDC
	recordEvent func(string)

	mu     sync.Mutex
	states map[string]*oauthState
}

type oauthState struct {
	Created      time.Time
	OriginalURL  string
	CodeVerifier string
	Seen         bool
}

func newOIDCProvider(cfg ConfigOIDC, recordEvent func(string)) (*oidcProvider, error) {
	var p oidcProvider
	if cfg.DiscoveryURL != "" {
		resp, err := http.Get(cfg.DiscoveryURL)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("http get(%s): %s", cfg.DiscoveryURL, resp.Status)
		}
		if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
			return nil, fmt.Errorf("discovery document: %v", err)
		}
	} else {
		p.AuthEndpoint = cfg.AuthEndpoint
		p.TokenEndpoint = cfg.TokenEndpoint
	}
	if _, err := url.Parse(p.AuthEndpoint); err != nil {
		return nil, fmt.Errorf("AuthEndpoint: %v", err)
	}
	if _, err := url.Parse(p.TokenEndpoint); err != nil {
		return nil, fmt.Errorf("TokenEndpoint: %v", err)
	}
	p.cfg = cfg
	p.recordEvent = recordEvent
	p.states = make(map[string]*oauthState)
	return &p, nil
}

func (p *oidcProvider) redirectHostAndPath() (string, string, error) {
	url, err := url.Parse(p.cfg.RedirectURL)
	if err != nil {
		return "", "", err
	}
	host := url.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return host, url.Path, nil
}

func (p *oidcProvider) requestLogin(w http.ResponseWriter, req *http.Request, origURL string) {
	var nonce [12]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	nonceStr := hex.EncodeToString(nonce[:])
	var codeVerifier [32]byte
	if _, err := io.ReadFull(rand.Reader, codeVerifier[:]); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	codeVerifierStr := base64.RawURLEncoding.EncodeToString(codeVerifier[:])
	cvh := sha256.Sum256([]byte(codeVerifierStr))
	p.mu.Lock()
	p.states[nonceStr] = &oauthState{
		Created:      time.Now(),
		OriginalURL:  origURL,
		CodeVerifier: codeVerifierStr,
	}
	p.mu.Unlock()
	url := p.AuthEndpoint + "?" +
		"response_type=code" +
		"&client_id=" + url.QueryEscape(p.cfg.ClientID) +
		"&scope=" + url.QueryEscape("openid email") +
		"&redirect_uri=" + url.QueryEscape(p.cfg.RedirectURL) +
		"&state=" + nonceStr +
		"&nonce=" + nonceStr +
		"&code_challenge=" + base64.RawURLEncoding.EncodeToString(cvh[:]) +
		"&code_challenge_method=S256"
	http.Redirect(w, req, url, http.StatusFound)
	p.recordEvent("oidc auth request")
}

func (p *oidcProvider) handleRedirect(w http.ResponseWriter, req *http.Request) {
	p.recordEvent("oidc auth redirect")
	tlsConn := req.Context().Value(connCtxKey).(*tls.Conn)
	desc := formatConnDesc(tlsConn.NetConn().(*netw.Conn))
	log.Printf("REQ %s ➔ %s %s?...", desc, req.Method, req.URL.Path)
	req.ParseForm()
	if req.Form.Get("logout") != "" {
		cookie := &http.Cookie{
			Name:     tlsProxyAuthCookie,
			Value:    "",
			Domain:   p.cfg.Domain,
			MaxAge:   -1,
			Secure:   true,
			HttpOnly: true,
		}
		http.SetCookie(w, cookie)
		w.Write([]byte("logout successful"))
		return
	}

	p.mu.Lock()
	for k, v := range p.states {
		if time.Since(v.Created) > 5*time.Minute {
			delete(p.states, k)
		}
	}
	state, ok := p.states[req.Form.Get("state")]
	invalid := !ok || state.Seen
	if ok {
		state.Seen = true
	}
	p.mu.Unlock()

	if invalid {
		p.recordEvent("invalid state")
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	code := req.Form.Get("code")

	form := url.Values{}
	form.Add("code", code)
	form.Add("client_id", p.cfg.ClientID)
	form.Add("client_secret", p.cfg.ClientSecret)
	form.Add("redirect_uri", p.cfg.RedirectURL)
	form.Add("grant_type", "authorization_code")
	form.Add("code_verifier", state.CodeVerifier)

	resp, err := http.PostForm(p.TokenEndpoint, form)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	var data struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var claims struct {
		Email         string `json:"email"`
		EmailVerified *bool  `json:"email_verified"`
		Nonce         string `json:"nonce"`
		jwt.RegisteredClaims
	}
	// We received the JWT directly from the identity provider. So, we
	// don't need to validate it.
	if _, _, err := (&jwt.Parser{}).ParseUnverified(data.IDToken, &claims); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	p.mu.Lock()
	state, ok = p.states[claims.Nonce]
	delete(p.states, claims.Nonce)
	p.mu.Unlock()
	if !ok {
		p.recordEvent("invalid nonce")
		http.Error(w, "invalid nonce", http.StatusBadRequest)
		return
	}
	if claims.EmailVerified != nil && !*claims.EmailVerified {
		p.recordEvent("email not verified")
		http.Error(w, "email not verified", http.StatusForbidden)
		return
	}
	token, err := p.makeToken(claims.Email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cookie := &http.Cookie{
		Name:     tlsProxyAuthCookie,
		Value:    token,
		Domain:   p.cfg.Domain,
		Secure:   true,
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, req, state.OriginalURL, http.StatusFound)
}

type tokenData struct {
	Exp      time.Time `json:"exp"`
	Email    string    `json:"email"`
	Provider string    `json:"provider"`
}

func (p *oidcProvider) tokenKey() []byte {
	buf := make([]byte, len(p.cfg.ClientSecret)+len(p.cfg.ClientID))
	copy(buf, []byte(p.cfg.ClientSecret))
	copy(buf[len(p.cfg.ClientSecret):], []byte(p.cfg.ClientID))
	key := sha256.Sum256(buf)
	return key[:]
}

func (p *oidcProvider) makeToken(email string) (string, error) {
	payload, err := json.Marshal(tokenData{
		Exp:      time.Now().UTC().Add(12 * time.Hour),
		Email:    email,
		Provider: p.cfg.Name,
	})
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(p.tokenKey())
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	out := gcm.Seal(nonce, nonce, payload, nil)
	return base64.RawURLEncoding.EncodeToString(out), nil
}

func (p *oidcProvider) validateToken(token string) (string, error) {
	enc, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(p.tokenKey())
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(enc) < gcm.NonceSize() {
		return "", fmt.Errorf("invalid token len=%d", len(enc))
	}
	nonce, enc := enc[:gcm.NonceSize()], enc[gcm.NonceSize():]
	b, err := gcm.Open(nil, nonce, enc, nil)
	if err != nil {
		return "", err
	}
	var tok tokenData
	if err := json.Unmarshal(b, &tok); err != nil {
		return "", err
	}
	if tok.Provider != p.cfg.Name {
		return "", errors.New("provider mismatch")
	}
	if tok.Exp.Before(time.Now()) {
		return "", errors.New("token is expired")
	}
	return tok.Email, nil
}
