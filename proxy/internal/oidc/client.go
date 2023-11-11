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

package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

// Config contains the parameters of an OIDC provider.
type Config struct {
	// DiscoveryURL is the discovery URL of the OIDC provider. If set, it
	// is used to discover the values of AuthEndpoint and TokenEndpoint.
	DiscoveryURL string
	// AuthEndpoint is the authorization endpoint. It must be set only if
	// DiscoveryURL is not set.
	AuthEndpoint string
	// Scopes is the list of scopes to request. The default list is:
	// openid, email.
	Scopes []string
	// TokenEndpoint is the token endpoint. It must be set only if
	// DiscoveryURL is not set.
	TokenEndpoint string
	// UserinfoEndpoint is the userinfo endpoint. It must be set only if
	// DiscoveryURL is not set and the token endpoint doesn't return an
	// ID token.
	UserinfoEndpoint string
	// RedirectURL is the OAUTH2 redirect URL. It must be managed by the
	// proxy.
	RedirectURL string
	// ClientID is the Client ID.
	ClientID string
	// ClientSecret is the Client Secret.
	ClientSecret string
}

// CookieManager is the interface to set and clear the auth token.
type CookieManager interface {
	SetAuthTokenCookie(w http.ResponseWriter, userID, sessionID, host string, extraClaims map[string]any) error
	ClearCookies(w http.ResponseWriter) error
}

// EventRecorder is used to record events.
type EventRecorder interface {
	Record(string)
}

// ProviderClient handles the OIDC authentication code flow based on information
// from https://developers.google.com/identity/openid-connect/openid-connect and
// https://developers.facebook.com/docs/facebook-login/guides/advanced/oidc-token/
type ProviderClient struct {
	cfg Config
	cm  CookieManager
	er  EventRecorder

	mu     sync.Mutex
	states map[string]*oauthState
}

type oauthState struct {
	Created      time.Time
	OriginalURL  string
	Host         string
	CodeVerifier string
	Seen         bool
}

// New returns a new ProviderClient.
func New(cfg Config, er EventRecorder, cm CookieManager) (*ProviderClient, error) {
	p := &ProviderClient{
		cfg:    cfg,
		cm:     cm,
		er:     er,
		states: make(map[string]*oauthState),
	}
	if p.cfg.DiscoveryURL != "" {
		resp, err := http.Get(p.cfg.DiscoveryURL)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("http get(%s): %s", cfg.DiscoveryURL, resp.Status)
		}
		var disc struct {
			AuthEndpoint     string `json:"authorization_endpoint"`
			TokenEndpoint    string `json:"token_endpoint"`
			UserinfoEndpoint string `json:"userinfo_endpoint"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
			return nil, fmt.Errorf("discovery document: %v", err)
		}
		p.cfg.AuthEndpoint = disc.AuthEndpoint
		p.cfg.TokenEndpoint = disc.TokenEndpoint
		p.cfg.UserinfoEndpoint = disc.UserinfoEndpoint
	}
	if _, err := url.Parse(p.cfg.AuthEndpoint); err != nil {
		return nil, fmt.Errorf("AuthEndpoint: %v", err)
	}
	if _, err := url.Parse(p.cfg.TokenEndpoint); err != nil {
		return nil, fmt.Errorf("TokenEndpoint: %v", err)
	}
	if _, err := url.Parse(p.cfg.RedirectURL); err != nil {
		return nil, fmt.Errorf("RedirectURL: %v", err)
	}
	return p, nil
}

func (p *ProviderClient) RequestLogin(w http.ResponseWriter, req *http.Request, originalURL string) {
	ou, err := url.Parse(originalURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
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
		OriginalURL:  originalURL,
		Host:         ou.Host,
		CodeVerifier: codeVerifierStr,
	}
	p.mu.Unlock()
	scopes := p.cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email"}
	}
	url := p.cfg.AuthEndpoint + "?" +
		"response_type=code" +
		"&client_id=" + url.QueryEscape(p.cfg.ClientID) +
		"&scope=" + url.QueryEscape(strings.Join(scopes, " ")) +
		"&redirect_uri=" + url.QueryEscape(p.cfg.RedirectURL) +
		"&state=" + nonceStr +
		"&nonce=" + nonceStr +
		"&code_challenge=" + base64.RawURLEncoding.EncodeToString(cvh[:]) +
		"&code_challenge_method=S256"
	http.Redirect(w, req, url, http.StatusFound)
	p.er.Record("oidc auth request")
}

func (p *ProviderClient) HandleCallback(w http.ResponseWriter, req *http.Request) {
	p.er.Record("oidc auth callback")
	req.ParseForm()

	p.mu.Lock()
	for k, v := range p.states {
		if time.Since(v.Created) > 5*time.Minute {
			delete(p.states, k)
		}
	}
	nonce := req.Form.Get("state")
	state, ok := p.states[nonce]
	invalid := !ok || state.Seen
	if ok {
		state.Seen = true
	}
	p.mu.Unlock()

	if invalid {
		p.er.Record("invalid state")
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

	req, err := http.NewRequest(http.MethodPost, p.cfg.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	req.Header.Set("accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	var data struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var claims struct {
		Email         string `json:"email"`
		EmailVerified *bool  `json:"email_verified"`
		Nonce         string `json:"nonce"`
		Name          string `json:"name"`
		GivenName     string `json:"given_name"`
		MiddleName    string `json:"middle_name"`
		FamilyName    string `json:"family_name"`
		Picture       string `json:"picture"`
		AvatarURL     string `json:"avatar_url"` // github
		Login         string `json:"login"`      // github
		jwt.RegisteredClaims
	}
	if data.IDToken != "" {
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
			p.er.Record("invalid nonce")
			http.Error(w, "timeout", http.StatusForbidden)
			return
		}
	} else if p.cfg.UserinfoEndpoint != "" && (data.TokenType == "" || strings.ToLower(data.TokenType) == "bearer") {
		p.mu.Lock()
		delete(p.states, nonce)
		p.mu.Unlock()
		req, err := http.NewRequest(http.MethodGet, p.cfg.UserinfoEndpoint, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		req.Header.Set("authorization", "Bearer "+data.AccessToken)
		req.Header.Set("accept", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()
		claims.Issuer = p.cfg.UserinfoEndpoint
		claims.Nonce = nonce
		if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		http.Error(w, "no user info", http.StatusInternalServerError)
		return
	}
	if claims.Email == "" {
		http.Error(w, "no email", http.StatusInternalServerError)
		return
	}
	if claims.EmailVerified != nil && !*claims.EmailVerified {
		p.er.Record("email not verified")
		http.Error(w, "email not verified", http.StatusForbidden)
		return
	}
	extraClaims := map[string]any{
		"source": claims.Issuer,
	}
	if claims.Name != "" {
		extraClaims["name"] = claims.Name
	}
	if claims.GivenName != "" {
		extraClaims["given_name"] = claims.GivenName
	}
	if claims.MiddleName != "" {
		extraClaims["middle_name"] = claims.MiddleName
	}
	if claims.FamilyName != "" {
		extraClaims["family_name"] = claims.FamilyName
	}
	if claims.Picture != "" {
		extraClaims["picture"] = claims.Picture
	} else if claims.AvatarURL != "" {
		extraClaims["picture"] = claims.AvatarURL
	}
	if err := p.cm.SetAuthTokenCookie(w, claims.Email, claims.Nonce, state.Host, extraClaims); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, req, state.OriginalURL, http.StatusFound)
}
