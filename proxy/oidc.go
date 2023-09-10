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
	"github.com/c2FmZQ/tlsproxy/proxy/internal/tokenmanager"
)

// oidcProvider handles the OIDC manual flow based on information from
// https://developers.google.com/identity/openid-connect/openid-connect and
// https://developers.facebook.com/docs/facebook-login/guides/advanced/oidc-token/
type oidcProvider struct {
	AuthEndpoint  string `json:"authorization_endpoint"`
	TokenEndpoint string `json:"token_endpoint"`

	cfg         ConfigOIDC
	recordEvent func(string)
	tm          *tokenmanager.TokenManager
	self        string

	mu     sync.Mutex
	states map[string]*oauthState
}

type oauthState struct {
	Created      time.Time
	OriginalURL  string
	CodeVerifier string
	Seen         bool
}

func newOIDCProvider(cfg ConfigOIDC, recordEvent func(string), tm *tokenmanager.TokenManager) (*oidcProvider, error) {
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
	if u, err := url.Parse(cfg.RedirectURL); err != nil {
		return nil, fmt.Errorf("RedirectURL: %v", err)
	} else {
		p.self = "https://" + u.Host + "/"
	}
	p.cfg = cfg
	p.recordEvent = recordEvent
	p.tm = tm
	p.states = make(map[string]*oauthState)
	return &p, nil
}

func (p *oidcProvider) domain() string {
	return p.cfg.Domain
}

func (p *oidcProvider) callbackHostAndPath() (string, string, error) {
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

func (p *oidcProvider) tokenManager() *tokenmanager.TokenManager {
	return p.tm
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

func (p *oidcProvider) handleCallback(w http.ResponseWriter, req *http.Request) {
	p.recordEvent("oidc auth callback")
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
		http.Error(w, "timeout", http.StatusForbidden)
		return
	}
	if claims.EmailVerified != nil && !*claims.EmailVerified {
		p.recordEvent("email not verified")
		http.Error(w, "email not verified", http.StatusForbidden)
		return
	}
	now := time.Now().UTC()
	token, err := p.tm.CreateToken(jwt.MapClaims{
		"iat":   now.Unix(),
		"exp":   now.Add(20 * time.Hour).Unix(),
		"iss":   p.self,
		"aud":   p.self,
		"sub":   claims.Email,
		"scope": "proxy",
		"sid":   claims.Nonce,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cookie := &http.Cookie{
		Name:     tlsProxyAuthCookie,
		Value:    token,
		Domain:   p.cfg.Domain,
		Path:     "/",
		Expires:  now.Add(24 * time.Hour),
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, req, state.OriginalURL, http.StatusFound)
}

func (p *oidcProvider) validateToken(token string) (*jwt.Token, error) {
	tok, err := p.tm.ValidateToken(token, jwt.WithIssuer(p.self), jwt.WithAudience(p.self))
	if err != nil {
		return nil, err
	}
	if c, ok := tok.Claims.(jwt.MapClaims); !ok || c["scope"] != "proxy" {
		return nil, errors.New("wrong scope")
	}
	return tok, nil
}
