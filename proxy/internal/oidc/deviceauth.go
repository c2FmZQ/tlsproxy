// MIT License
//
// Copyright (c) 2025 TTBT Enterprises LLC
// Copyright (c) 2025 Robin Thellend <rthellend@rthellend.com>
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
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"

	"github.com/c2FmZQ/tlsproxy/proxy/internal/cookiemanager"
)

//go:embed verify-template.html
var verifyEmbed string
var verifyTemplate *template.Template

func init() {
	verifyTemplate = template.Must(template.New("verify-template").Parse(verifyEmbed))
}

type deviceCodeData struct {
	created    time.Time
	clientID   string
	deviceCode string
}

type deviceToken struct {
	created     time.Time
	clientID    string
	scope       []string
	accessToken string
	denied      bool
	ready       chan struct{}
}

func (s *ProviderServer) ServeDeviceAuthorization(w http.ResponseWriter, req *http.Request) {
	s.vacuum()
	if req.Method != http.MethodPost {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	req.ParseForm()
	clientID := req.Form.Get("client_id")
	if !slices.ContainsFunc(s.opts.Clients, func(c Client) bool { return c.ID == clientID }) {
		s.opts.Logger.Errorf("ERR ServeAuthorization: invalid client_id %q", clientID)
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	deviceCode := hex.EncodeToString(b)
	b = make([]byte, 6)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	userCode := fmt.Sprintf("%02X%02X-%02X%02X-%02X%02X", b[0], b[1], b[2], b[3], b[4], b[5])

	scopes := slices.DeleteFunc(strings.Split(req.Form.Get("scope"), " "), func(scope string) bool {
		return !slices.Contains(s.opts.Scopes, scope)
	})

	now := time.Now().UTC()
	s.mu.Lock()
	s.deviceCodes[userCode] = &deviceCodeData{
		created:    now,
		clientID:   clientID,
		deviceCode: deviceCode,
	}
	s.deviceTokens[deviceCode] = &deviceToken{
		created:  now,
		clientID: clientID,
		scope:    scopes,
		ready:    make(chan struct{}),
	}
	s.mu.Unlock()

	s.opts.EventRecorder.Record("device authorization request for " + clientID)

	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	out := struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
	}{
		DeviceCode:              deviceCode,
		UserCode:                userCode,
		VerificationURI:         fmt.Sprintf("https://%s%s/device/verification", host, s.opts.PathPrefix),
		VerificationURIComplete: fmt.Sprintf("https://%s%s/device/verification?user_code=%s", host, s.opts.PathPrefix, userCode),
		ExpiresIn:               int(codeExpiration / time.Second),
		Interval:                int(pollInterval / time.Second),
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

func (s *ProviderServer) AuthorizeClient(clientID, email string) bool {
	return slices.ContainsFunc(s.opts.Clients, func(c Client) bool {
		return c.ID == clientID && (c.ACL == nil || s.opts.ACLMatcher(*c.ACL, email))
	})
}

func (s *ProviderServer) ServeDeviceVerification(w http.ResponseWriter, req *http.Request) {
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

	if req.Method == http.MethodGet {
		data := struct {
			Email    string
			UserCode string
		}{
			Email:    email,
			UserCode: req.Form.Get("user_code"),
		}
		w.Header().Set("content-type", "text/html; charset=utf-8")
		verifyTemplate.Execute(w, data)
		return
	}
	if req.Method != http.MethodPost {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if v := req.Header.Get("x-csrf-check"); v != "1" {
		s.opts.Logger.Errorf("ERR x-csrf-check: %v", v)
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	userCode := strings.ToUpper(req.Form.Get("user_code"))

	s.mu.Lock()
	defer s.mu.Unlock()

	data, ok := s.deviceCodes[userCode]
	delete(s.deviceCodes, userCode)
	var devToken *deviceToken
	if ok {
		devToken, ok = s.deviceTokens[data.deviceCode]
	}
	if !ok {
		http.Error(w, "request expired", http.StatusBadRequest)
		return
	}
	defer close(devToken.ready)

	if !s.AuthorizeClient(data.clientID, email) {
		devToken.denied = true
		s.opts.EventRecorder.Record("device authorization denied by ACL for " + data.clientID)
		http.Error(w, "operation not permitted", http.StatusForbidden)
		return
	}

	if approve := req.Form.Get("approve"); approve != "true" {
		devToken.denied = true
		s.opts.EventRecorder.Record("device authorization denied for " + data.clientID)
		w.Write([]byte("denied\n"))
		return
	}

	claims := jwt.MapClaims{}
	for k, v := range userClaims {
		if slices.Contains([]string{
			"proxyauth",
			"source",
			"hhash",
		}, k) {
			continue
		}
		claims[k] = v
	}
	ttl := defaultTokenLifetime
	if s.opts.TokenLifetime > 0 {
		ttl = s.opts.TokenLifetime
	}
	claims["client_id"] = data.clientID

	// Remove any scopes that the user doesn't have.
	if userClaims["scope"] != nil {
		userScopes, ok := userClaims["scope"].([]any)
		if !ok {
			http.Error(w, "invalid user scopes", http.StatusBadRequest)
			return
		}
		devToken.scope = slices.DeleteFunc(devToken.scope, func(s string) bool {
			return !slices.Contains(userScopes, any(s))
		})
	}
	if len(devToken.scope) == 0 {
		devToken.scope = []string{"openid"}
	}
	claims["scope"] = devToken.scope

	tok, err := s.opts.CookieManager.MintToken(claims, ttl, cookiemanager.AudienceForToken(req), "ES256")
	if err != nil {
		s.opts.Logger.Errorf("ERR MintToken: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	devToken.accessToken = tok

	s.opts.EventRecorder.Record("device authorization granted for " + data.clientID)
	w.Write([]byte("approved\n"))
}
