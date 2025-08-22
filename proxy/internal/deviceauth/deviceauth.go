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

package deviceauth

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"

	"github.com/c2FmZQ/tlsproxy/proxy/internal/cookiemanager"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/tokenmanager"
)

const (
	codeExpiration       = 10 * time.Minute
	pollInterval         = 5 * time.Second
	defaultTokenLifetime = 1 * time.Hour
)

//go:embed verify-template.html
var verifyEmbed string
var verifyTemplate *template.Template

func init() {
	verifyTemplate = template.Must(template.New("verify-template").Parse(verifyEmbed))
}

type codeData struct {
	created    time.Time
	clientID   string
	deviceCode string
}

type accessData struct {
	created  time.Time
	clientID string
	token    string
	denied   bool
}

// EventRecorder is used to record events.
type EventRecorder interface {
	Record(string)
}

// Options contains the parameters needed to configure a Server.
type Options struct {
	TokenManager  *tokenmanager.TokenManager
	ClaimsFromCtx func(context.Context) jwt.MapClaims
	ACLMatcher    func(acl []string, email string) bool
	PathPrefix    string
	Clients       []Client
	TokenLifetime time.Duration

	EventRecorder EventRecorder
	Logger        interface {
		Errorf(string, ...any)
	}
}

type defaultLogger struct{}

func (defaultLogger) Errorf(format string, args ...any) {
	log.Printf(format, args...)
}

// NewServer returns a new Server.
func NewServer(opts Options) *Server {
	if opts.Logger == nil {
		opts.Logger = defaultLogger{}
	}
	return &Server{
		opts:     opts,
		codes:    make(map[string]*codeData),
		idTokens: make(map[string]*accessData),
	}
}

// Server is a device authorization implementation. RFC 8628
type Server struct {
	opts Options

	mu       sync.Mutex
	codes    map[string]*codeData
	idTokens map[string]*accessData
}

type Client struct {
	ID  string
	ACL *[]string
}

func (s *Server) vacuum() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	for k, v := range s.codes {
		if v.created.Add(codeExpiration).Before(now) {
			delete(s.codes, k)
		}
	}
	for k, v := range s.idTokens {
		if v.created.Add(codeExpiration).Before(now) {
			delete(s.idTokens, k)
		}
	}
}

func (s *Server) ServeAuthorization(w http.ResponseWriter, req *http.Request) {
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

	b := make([]byte, 12)
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

	now := time.Now().UTC()
	s.mu.Lock()
	s.codes[userCode] = &codeData{
		created:    now,
		clientID:   clientID,
		deviceCode: deviceCode,
	}
	s.idTokens[deviceCode] = &accessData{
		created:  now,
		clientID: clientID,
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

func (s *Server) AuthorizeClient(clientID, email string) bool {
	return slices.ContainsFunc(s.opts.Clients, func(c Client) bool {
		return c.ID == clientID && (c.ACL == nil || s.opts.ACLMatcher(*c.ACL, email))
	})
}

func (s *Server) ServeVerification(w http.ResponseWriter, req *http.Request) {
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
	if userClaims["proxyauth"] == nil {
		http.Error(w, "invalid authentication method", http.StatusUnauthorized)
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

	var idToken *accessData
	s.mu.Lock()
	data, ok := s.codes[userCode]
	delete(s.codes, userCode)
	if ok {
		idToken, ok = s.idTokens[data.deviceCode]
	}
	s.mu.Unlock()

	if !ok {
		http.Error(w, "request expired", http.StatusBadRequest)
		return
	}

	if !s.AuthorizeClient(data.clientID, email) {
		s.mu.Lock()
		idToken.denied = true
		s.mu.Unlock()
		s.opts.EventRecorder.Record("device authorization denied by ACL for " + data.clientID)
		http.Error(w, "operation not permitted", http.StatusForbidden)
		return
	}

	if approve := req.Form.Get("approve"); approve != "true" {
		s.mu.Lock()
		idToken.denied = true
		s.mu.Unlock()
		s.opts.EventRecorder.Record("device authorization denied for " + data.clientID)
		w.Write([]byte("denied\n"))
		return
	}

	claims := jwt.MapClaims{}
	for k, v := range userClaims {
		if slices.Contains([]string{
			"scope",
			"proxyauth",
			"source",
			"hhash",
		}, k) {
			continue
		}
		claims[k] = v
	}
	now := time.Now().UTC()
	ttl := defaultTokenLifetime
	if s.opts.TokenLifetime > 0 {
		ttl = s.opts.TokenLifetime
	}
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(ttl).Unix()
	claims["aud"] = cookiemanager.AudienceForToken(req)
	claims["device_client_id"] = data.clientID
	tok, err := s.opts.TokenManager.CreateToken(claims, "ES256")
	if err != nil {
		s.opts.Logger.Errorf("ERR CreateToken: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	s.mu.Lock()
	idToken.token = tok
	s.mu.Unlock()
	s.opts.EventRecorder.Record("device authorization granted for " + data.clientID)
	w.Write([]byte("approved\n"))
}

func (s *Server) ServeToken(w http.ResponseWriter, req *http.Request) {
	s.vacuum()
	if req.Method != http.MethodPost {
		http.Error(w, "method not allowed ", http.StatusMethodNotAllowed)
		return
	}
	req.ParseForm()
	if gt := req.Form.Get("grant_type"); gt != "urn:ietf:params:oauth:grant-type:device_code" {
		http.Error(w, "invalid grant type", http.StatusBadRequest)
		return
	}
	deviceCode := req.Form.Get("device_code")
	clientID := req.Form.Get("client_id")

	s.mu.Lock()
	data, ok := s.idTokens[deviceCode]
	s.mu.Unlock()

	var resp struct {
		Error       string `json:"error,omitempty"`
		AccessToken string `json:"access_token,omitempty"`
		Scope       string `json:"scope,omitempty"`
		TokenType   string `json:"token_type,omitempty"`
	}

	status := http.StatusOK
	switch {
	case !ok:
		resp.Error = "invalid_request"
		status = http.StatusBadRequest
	case data.clientID != clientID:
		resp.Error = "invalid_client"
		status = http.StatusBadRequest
	case data.token != "":
		resp.AccessToken = data.token
		resp.Scope = "email"
		resp.TokenType = "Bearer"
		s.mu.Lock()
		delete(s.idTokens, deviceCode)
		s.mu.Unlock()
	case data.denied:
		resp.Error = "access_denied"
	default:
		resp.Error = "authorization_pending"
	}

	content, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.WriteHeader(status)
	w.Write(content)
}
