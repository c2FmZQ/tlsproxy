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
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"

	"github.com/c2FmZQ/tlsproxy/proxy/internal/tokenmanager"
)

const (
	wellKnownOpenIDConfigurationPath = "/.well-known/openid-configuration"
	authorizationPath                = "/authorization"
	tokenPath                        = "/token"
	userInfoPath                     = "/userinfo"
	jwksPath                         = "/jwks"

	defaultTokenLifetime = time.Hour
	codeExpiration       = 10 * time.Minute
	pollInterval         = 5 * time.Second
)

type openIDConfiguration struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserInfoEndpoint                 string   `json:"userinfo_endpoint"`
	JWKSURI                          string   `json:"jwks_uri"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                  []string `json:"scopes_supported"`
	ClaimsSupported                  []string `json:"claims_supported"`
}

type codeData struct {
	created  time.Time
	clientID string
	token    string
	scope    []string
}

// ServerOptions contains the parameters needed to configure a ProviderServer.
type ServerOptions struct {
	TokenManager  *tokenmanager.TokenManager
	Issuer        string
	PathPrefix    string
	TokenLifetime time.Duration
	ClaimsFromCtx func(context.Context) jwt.MapClaims
	ACLMatcher    func(acl []string, email string) bool
	Clients       []Client
	RewriteRules  []RewriteRule

	EventRecorder EventRecorder
	Logger        interface {
		Errorf(string, ...any)
	}
}

// RewriteRule is used to apply a regular expression on an existing JWT claim
// to create or overwrite another claim, or possibly the same claim.
type RewriteRule struct {
	InputClaim  string
	OutputClaim string
	Regex       string
	Value       string
}

type defaultLogger struct{}

func (defaultLogger) Errorf(format string, args ...any) {
	log.Printf(format, args...)
}

// NewServer returns a new ProviderServer.
func NewServer(opts ServerOptions) *ProviderServer {
	if opts.Logger == nil {
		opts.Logger = defaultLogger{}
	}
	return &ProviderServer{
		opts:           opts,
		codes:          make(map[string]*codeData),
		deviceCodes:    make(map[string]*deviceCodeData),
		deviceIDTokens: make(map[string]*deviceAccessData),
	}
}

// ProviderServer is a OpenID Connect server implementation.
// https://openid.net/specs/openid-connect-discovery-1_0.html
// https://openid.net/specs/openid-connect-basic-1_0.html
type ProviderServer struct {
	opts ServerOptions

	mu             sync.Mutex
	codes          map[string]*codeData
	deviceCodes    map[string]*deviceCodeData
	deviceIDTokens map[string]*deviceAccessData
}

type Client struct {
	ID          string
	Secret      string
	RedirectURI []string
	ACL         *[]string
}

func (s *ProviderServer) vacuum() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	for k, v := range s.codes {
		if v.created.Add(2 * time.Minute).Before(now) {
			delete(s.codes, k)
		}
	}
	for k, v := range s.deviceCodes {
		if v.created.Add(codeExpiration).Before(now) {
			delete(s.deviceCodes, k)
		}
	}
	for k, v := range s.deviceIDTokens {
		if v.created.Add(codeExpiration).Before(now) {
			delete(s.deviceIDTokens, k)
		}
	}
}

func (s *ProviderServer) ServeConfig(w http.ResponseWriter, req *http.Request) {
	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	cfg := openIDConfiguration{
		Issuer:                s.opts.Issuer,
		AuthorizationEndpoint: fmt.Sprintf("https://%s%s%s", host, s.opts.PathPrefix, authorizationPath),
		TokenEndpoint:         fmt.Sprintf("https://%s%s%s", host, s.opts.PathPrefix, tokenPath),
		UserInfoEndpoint:      fmt.Sprintf("https://%s%s%s", host, s.opts.PathPrefix, userInfoPath),
		JWKSURI:               fmt.Sprintf("https://%s%s%s", host, s.opts.PathPrefix, jwksPath),
		ResponseTypesSupported: []string{
			"code",
		},
		SubjectTypesSupported: []string{
			"public",
		},
		IDTokenSigningAlgValuesSupported: []string{
			"RS256",
			"ES256",
		},
		ScopesSupported: []string{
			"openid",
			"email",
			"profile",
		},
		ClaimsSupported: []string{
			"aud",
			"email",
			"exp",
			"family_name",
			"middle_name",
			"given_name",
			"iat",
			"iss",
			"locale",
			"name",
			"picture",
			"sub",
		},
	}

	s.opts.EventRecorder.Record("allow openid config request")
	content, err := json.MarshalIndent(cfg, "", "  ")
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

func (s *ProviderServer) ServeAuthorization(w http.ResponseWriter, req *http.Request) {
	s.vacuum()
	userClaims := s.opts.ClaimsFromCtx(req.Context())
	if userClaims == nil {
		http.Error(w, "not logged in", http.StatusUnauthorized)
		return
	}
	email, ok := userClaims["email"].(string)
	if !ok || email == "" {
		http.Error(w, "no email", http.StatusInternalServerError)
		return
	}
	req.ParseForm()
	if rt := req.Form.Get("response_type"); rt != "code" {
		s.opts.Logger.Errorf("ERR ServeAuthorization: invalid response_type %q", rt)
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	clientID := req.Form.Get("client_id")
	redirectURI := req.Form.Get("redirect_uri")
	var found bool
	for _, client := range s.opts.Clients {
		if client.ID == clientID && redirectURI != "" && slices.Contains(client.RedirectURI, redirectURI) {
			found = true
			break
		}
	}
	if !found {
		s.opts.Logger.Errorf("ERR ServeAuthorization: invalid client_id %q or redirect_uri %q", clientID, redirectURI)
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if !s.AuthorizeClient(clientID, email) {
		s.opts.EventRecorder.Record("oidc authorization denied by ACL for " + clientID)
		http.Error(w, "operation not permitted", http.StatusForbidden)
		return
	}

	ru, err := url.Parse(redirectURI)
	if err != nil {
		s.opts.Logger.Errorf("ERR ServeAuthorization: invalid redirect_uri %q", redirectURI)
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	b := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	code := base64.StdEncoding.EncodeToString(b)

	sub, _ := userClaims.GetSubject()

	now := time.Now().UTC()
	ttl := s.opts.TokenLifetime
	if ttl == 0 {
		ttl = defaultTokenLifetime
	}
	claims := jwt.MapClaims{
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
		"iss": s.opts.Issuer,
		"aud": clientID,
		"sub": sub,
	}
	if nonce := req.Form.Get("nonce"); nonce != "" {
		claims["nonce"] = nonce
	}

	scopes := slices.DeleteFunc(strings.Split(req.Form.Get("scope"), " "), func(s string) bool { return s == "" })

	// Remove any scopes that the user doesn't have.
	if userClaims["scope"] != nil {
		userScopes, ok := userClaims["scope"].([]any)
		if !ok {
			http.Error(w, "invalid user scopes", http.StatusBadRequest)
			return
		}
		scopes = slices.DeleteFunc(scopes, func(s string) bool {
			return !slices.Contains(userScopes, any(s))
		})
	}
	if len(scopes) == 0 {
		scopes = []string{"openid"}
	}
	claims["scope"] = scopes

	claims["email"] = userClaims["email"]
	claims["email_verified"] = true

	if slices.Contains(scopes, "profile") {
		for _, v := range []string{"name", "family_name", "given_name", "middle_name", "nickname", "preferred_username", "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale"} {
			if vv := userClaims[v]; vv != nil {
				claims[v] = vv
			}
		}
	}

	s.applyRewriteRules(s.opts.RewriteRules, userClaims, claims)

	token, err := s.opts.TokenManager.CreateToken(claims, "RS256")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.mu.Lock()
	s.codes[code] = &codeData{
		created:  now,
		clientID: clientID,
		token:    token,
		scope:    scopes,
	}
	s.mu.Unlock()

	qs := ru.Query()
	qs.Set("state", req.Form.Get("state"))
	qs.Set("code", code)
	qs.Set("scope", strings.Join(scopes, " "))
	ru.RawQuery = qs.Encode()

	s.opts.EventRecorder.Record("allow openid auth request for " + clientID)
	http.Redirect(w, req, ru.String(), http.StatusFound)
}

func (s *ProviderServer) ServeToken(w http.ResponseWriter, req *http.Request) {
	s.vacuum()
	if req.Method != http.MethodPost {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	req.ParseForm()
	if gt := req.Form.Get("grant_type"); gt != "authorization_code" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	code := req.Form.Get("code")
	clientID := req.Form.Get("client_id")
	clientSecret := req.Form.Get("client_secret")
	redirectURI := req.Form.Get("redirect_uri")

	var found bool
	for _, client := range s.opts.Clients {
		if client.ID == clientID && client.Secret != "" && client.Secret == clientSecret && redirectURI != "" && slices.Contains(client.RedirectURI, redirectURI) {
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	data, ok := s.codes[code]
	delete(s.codes, code)
	s.mu.Unlock()

	if !ok || data.clientID != clientID {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	resp := struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		IDToken     string `json:"id_token"`
		Scope       string `json:"scope"`
		TokenType   string `json:"token_type"`
	}{
		AccessToken: data.token,
		ExpiresIn:   90,
		IDToken:     data.token,
		Scope:       strings.Join(data.scope, " "),
		TokenType:   "Bearer",
	}

	s.opts.EventRecorder.Record("allow openid token request for " + clientID)
	content, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.WriteHeader(http.StatusOK)
	w.Write(content)
}

func (s *ProviderServer) ServeUserInfo(w http.ResponseWriter, req *http.Request) {
	s.vacuum()
	if req.Method != http.MethodGet && req.Method != http.MethodPost {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	userClaims := s.opts.ClaimsFromCtx(req.Context())
	if userClaims == nil {
		http.Error(w, "not logged in", http.StatusUnauthorized)
		return
	}

	filter := map[string]bool{
		"iss":   true,
		"aud":   true,
		"iat":   true,
		"exp":   true,
		"nbf":   true,
		"scope": true,
		"sid":   true,
		"nonce": true,
	}
	out := make(map[string]interface{})
	for k, v := range userClaims {
		if !filter[k] {
			out[k] = v
		}
	}

	content, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.WriteHeader(http.StatusOK)
	w.Write(content)
}

func (s *ProviderServer) applyRewriteRules(rules []RewriteRule, in, out jwt.MapClaims) {
	buf := maps.Clone(in)
	getClaim := func(n string) string {
		if v, exists := buf[n]; exists {
			return fmt.Sprint(v)
		}
		if v, exists := buf[strings.TrimSuffix(n, ":lower")]; exists {
			return strings.ToLower(fmt.Sprint(v))
		}
		if v, exists := buf[strings.TrimSuffix(n, ":upper")]; exists {
			return strings.ToUpper(fmt.Sprint(v))
		}
		return ""
	}
	for _, rr := range rules {
		var input string
		if strings.Contains(rr.InputClaim, "$") {
			input = os.Expand(rr.InputClaim, getClaim)
		} else {
			input = getClaim(rr.InputClaim)
		}
		re, err := regexp.Compile(rr.Regex)
		if err != nil {
			s.opts.Logger.Errorf("ERR REGEX %q: %v", rr.Regex, err)
			continue
		}
		if !re.MatchString(input) {
			continue
		}
		v := re.ReplaceAllString(input, rr.Value)
		buf[rr.OutputClaim] = v
		out[rr.OutputClaim] = v
		s.opts.Logger.Errorf("DBG REGEX %s: %q -> %q", rr.OutputClaim, input, v)
	}
}
