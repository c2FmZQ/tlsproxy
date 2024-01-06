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

package passkeys

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/c2FmZQ/storage"
	jwt "github.com/golang-jwt/jwt/v5"

	"github.com/c2FmZQ/tlsproxy/proxy/internal/cookiemanager"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/tokenmanager"
)

const passkeyFile = "passkeys"

var (
	//go:embed auth-template.html
	authEmbed    string
	authTemplate *template.Template
	//go:embed manage-template.html
	manageEmbed    string
	manageTemplate *template.Template
	//go:embed webauthn.js
	webauthnJSEmbed []byte
)

func init() {
	authTemplate = template.Must(template.New("passkey-auth").Parse(authEmbed))
	manageTemplate = template.Must(template.New("passkey-manage").Parse(manageEmbed))
}

type user struct {
	Handle Bytes
	Keys   []*userKey
	Claims map[string]any
}

type userKey struct {
	Name       string
	ID         Bytes
	PublicKey  Bytes
	RPIDHash   Bytes
	Transports []string
	CreatedAt  time.Time
	LastSeen   time.Time
}

// EventRecorder is used to record events.
type EventRecorder interface {
	Record(string)
}

type Config struct {
	Store *storage.Storage
	Other interface {
		RequestLogin(w http.ResponseWriter, req *http.Request, origURL string)
	}
	RefreshInterval    time.Duration
	Endpoint           string
	EventRecorder      EventRecorder
	CookieManager      *cookiemanager.CookieManager
	OtherCookieManager *cookiemanager.CookieManager
	TokenManager       *tokenmanager.TokenManager
	ClaimsFromCtx      func(context.Context) jwt.MapClaims
}

func NewManager(cfg Config) (*Manager, error) {
	m := &Manager{
		cfg:        cfg,
		challenges: make(map[string]*challenge),
		nonces:     make(map[string]*nonceData),
	}
	m.db.Handles = make(map[string]*user)
	m.db.Subjects = make(map[string]string)
	m.cfg.Store.CreateEmptyFile(passkeyFile, &m.db)
	if err := m.cfg.Store.ReadDataFile(passkeyFile, &m.db); err != nil {
		return nil, err
	}
	return m, nil
}

type Manager struct {
	cfg Config
	db  struct {
		Handles  map[string]*user
		Subjects map[string]string
	}
	acl *[]string

	mu         sync.Mutex
	challenges map[string]*challenge

	noncesMu sync.Mutex
	nonces   map[string]*nonceData
}

type challenge struct {
	created time.Time
	claims  map[string]any
	uid     []byte
}

type nonceData struct {
	created time.Time
	origURL *url.URL
}

func (m *Manager) SetACL(acl *[]string) {
	m.acl = acl
}

func (m *Manager) vacuum() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	for k, v := range m.challenges {
		if v.created.Add(5 * time.Minute).Before(now) {
			delete(m.challenges, k)
		}
	}
}

// ServeWellKnown serves a list of passkey endpoints.
// https://github.com/ms-id-standards/MSIdentityStandardsExplainers/blob/main/PasskeyEndpointsWellKnownUrl/explainer.md#proposed-solution
func (m *Manager) ServeWellKnown(w http.ResponseWriter, req *http.Request) {
	cfg := struct {
		Enroll string `json:"enroll,omitempty"`
		Manage string `json:"manage,omitempty"`
	}{
		Manage: fmt.Sprintf("https://%s/.sso/passkeys", req.Host),
	}
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

func (m *Manager) RequestLogin(w http.ResponseWriter, req *http.Request, origURL string) {
	m.cfg.EventRecorder.Record("passkey auth request")

	m.noncesMu.Lock()
	defer m.noncesMu.Unlock()

	n := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, n); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	nonce := hex.EncodeToString(n)
	ou, err := url.Parse(origURL)
	if err != nil {
		log.Printf("ERR %q: %v", origURL, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	m.nonces[nonce] = &nonceData{
		created: time.Now().UTC(),
		origURL: ou,
	}

	u, err := url.Parse(m.cfg.Endpoint)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	ephost := u.Host
	if h, _, err := net.SplitHostPort(ephost); err == nil {
		ephost = h
	}
	port := ""
	if _, p, err := net.SplitHostPort(req.Host); err == nil {
		port = p
	}
	if port != "" {
		ephost = net.JoinHostPort(ephost, port)
	}
	args := u.Query()
	args.Set("get", "Login")
	args.Set("nonce", nonce)
	u.Host = ephost
	u.RawQuery = args.Encode()
	http.Redirect(w, req, u.String(), http.StatusFound)
}

func (m *Manager) HandleCallback(w http.ResponseWriter, req *http.Request) {
	m.noncesMu.Lock()
	defer m.noncesMu.Unlock()
	now := time.Now().UTC()
	for k, v := range m.nonces {
		if v.created.Add(5 * time.Minute).Before(now) {
			delete(m.nonces, k)
		}
	}
	req.ParseForm()

	nonce := req.Form.Get("nonce")
	if nData, ok := m.nonces[nonce]; ok {
		delete(m.nonces, nonce)
		token, _, err := m.cfg.TokenManager.URLToken(w, req, nData.origURL)
		if err != nil {
			log.Printf("ERR %q: %v", nData.origURL, err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		args := req.URL.Query()
		args.Del("nonce")
		args.Set("redirect", token)
		req.URL.RawQuery = args.Encode()
		http.Redirect(w, req, req.URL.String(), http.StatusFound)
		return
	}

	mode := req.Form.Get("get")
	if mode == "JS" {
		serveWebauthnJS(w, req)
		return
	}

	redirectToken := req.Form.Get("redirect")
	if redirectToken == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	origURL, err := m.cfg.TokenManager.ValidateURLToken(w, req, redirectToken)
	if err != nil {
		http.Error(w, "invalid or expired request", http.StatusBadRequest)
		return
	}
	originalURL, err := url.Parse(origURL)
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	token, err := m.cfg.OtherCookieManager.ValidateAuthTokenCookie(req)
	if err != nil {
		switch mode {
		case "RegisterNewID", "RefreshID":
			req.URL.Scheme = "https"
			req.URL.Host = req.Host
			m.cfg.Other.RequestLogin(w, req, req.URL.String())
			return
		case "AttestationOptions", "AddKey":
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}

	switch mode {
	case "Login", "RegisterNewID", "RefreshID":
		data := struct {
			Self         string
			Token        string
			Mode         string
			Email        string
			URL          string
			DisplayURL   string
			IsAllowed    bool
			IsRegistered bool
		}{
			Self:       req.URL.Path,
			Token:      redirectToken,
			Mode:       mode,
			URL:        originalURL.String(),
			DisplayURL: originalURL.String(),
		}
		if len(data.DisplayURL) > 100 {
			data.DisplayURL = data.DisplayURL[:97] + "..."
		}
		if mode == "RegisterNewID" || mode == "RefreshID" {
			data.Email, _ = token.Claims.(jwt.MapClaims)["email"].(string)
			data.IsAllowed = m.subjectIsAllowed(data.Email)
			data.IsRegistered = m.subjectIsRegistered(data.Email)
		}
		w.Header().Set("X-Frame-Options", "DENY")
		authTemplate.Execute(w, data)

	case "AssertionOptions":
		if req.Method != "POST" {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if v := req.Header.Get("x-csrf-check"); v != "1" {
			log.Printf("ERR x-csrf-check: %v", v)
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		opts, err := m.assertionOptions()
		if err != nil {
			log.Printf("ERR assertionOptions: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("content-type", "application/json")
		json.NewEncoder(w).Encode(opts)

	case "AttestationOptions":
		if req.Method != "POST" {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if v := req.Header.Get("x-csrf-check"); v != "1" {
			log.Printf("ERR x-csrf-check: %v", v)
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		opts, err := m.attestationOptions(claims)
		if err != nil {
			log.Printf("ERR attestationOptions: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("content-type", "application/json")
		json.NewEncoder(w).Encode(opts)

	case "Check":
		if req.Method != "POST" {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if v := req.Header.Get("x-csrf-check"); v != "1" {
			log.Printf("ERR x-csrf-check: %v", v)
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		claims, err := m.processAssertion(req.Form.Get("args"), token)
		if err != nil {
			log.Printf("ERR processAssertion: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if m.cfg.RefreshInterval > 0 {
			iat, err := jwt.MapClaims(claims).GetIssuedAt()
			if err != nil || iat == nil || time.Since(iat.Time) > m.cfg.RefreshInterval {
				m.cfg.EventRecorder.Record("passkey refreshID required")
				u := req.URL
				args := u.Query()
				args.Set("get", "RefreshID")
				u.Scheme = "https"
				u.Host = req.Host
				u.RawQuery = args.Encode()
				w.Header().Set("content-type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{
					"result": "refresh",
					"email":  claims["email"],
					"url":    u.String(),
				})
				return
			}
		}
		m.cfg.EventRecorder.Record("passkey check request")
		m.setAuthToken(w, originalURL, claims)

	case "AddKey":
		if req.Method != "POST" {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if v := req.Header.Get("x-csrf-check"); v != "1" {
			log.Printf("ERR x-csrf-check: %v", v)
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		email, _ := token.Claims.(jwt.MapClaims)["email"].(string)
		if !m.subjectIsAllowed(email) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		claims, err = m.processAttestation(claims, req.Host, req.Form.Get("args"), false)
		if err != nil {
			log.Printf("ERR processAttestation: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		m.cfg.EventRecorder.Record("passkey addkey request")
		m.setAuthToken(w, originalURL, claims)

	case "Switch":
		if req.Method != "POST" {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if v := req.Header.Get("x-csrf-check"); v != "1" {
			log.Printf("ERR x-csrf-check: %v", v)
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		m.cfg.OtherCookieManager.ClearCookies(w)
		w.Header().Set("content-type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"result":   "ok",
			"redirect": originalURL.String(),
		})

	default:
		http.Error(w, "invalid request", http.StatusBadRequest)
	}
}

func serveWebauthnJS(w http.ResponseWriter, req *http.Request) {
	sum := sha256.Sum256(webauthnJSEmbed)
	etag := `"` + hex.EncodeToString(sum[:]) + `"`

	w.Header().Set("Content-Type", "text/javascript")
	w.Header().Set("Cache-Control", "public")
	w.Header().Set("Etag", etag)

	if e := req.Header.Get("If-None-Match"); e == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(webauthnJSEmbed)
}

func (m *Manager) ManageKeys(w http.ResponseWriter, req *http.Request) {
	u, err := url.Parse(m.cfg.Endpoint)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	ephost := u.Host
	if h, _, err := net.SplitHostPort(ephost); err == nil {
		ephost = h
	}
	port := ""
	if _, p, err := net.SplitHostPort(req.Host); err == nil {
		port = p
	}
	if port != "" {
		ephost = net.JoinHostPort(ephost, port)
	}
	if ephost != req.Host {
		req.URL.Scheme = "https"
		req.URL.Host = ephost
		http.Redirect(w, req, req.URL.String(), http.StatusFound)
		return
	}

	req.ParseForm()
	req.URL.Scheme = "https"
	req.URL.Host = req.Host
	here := req.URL.String()

	claims := m.cfg.ClaimsFromCtx(req.Context())
	var iat time.Time
	if claims != nil {
		if p, _ := claims.GetIssuedAt(); p != nil {
			iat = p.Time
		}
	}
	hh := sha256.Sum256([]byte(req.Host))
	if claims == nil || claims["hhash"] != hex.EncodeToString(hh[:]) || time.Since(iat) > 10*time.Minute {
		m.RequestLogin(w, req, here)
		return
	}
	mode := req.Form.Get("get")
	email, _ := claims["email"].(string)
	passkeyHash, ok := claims["passkey_hash"].(string)
	if !ok {
		log.Print("ERR passkey_hash is missing")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	switch mode {
	case "AttestationOptions":
		if req.Method != "POST" {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if v := req.Header.Get("x-csrf-check"); v != "1" {
			log.Printf("ERR x-csrf-check: %v", v)
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		opts, err := m.attestationOptions(claims)
		if err != nil {
			log.Printf("ERR attestationOptions: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("content-type", "application/json")
		json.NewEncoder(w).Encode(opts)

	case "AddKey":
		if req.Method != "POST" {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if v := req.Header.Get("x-csrf-check"); v != "1" {
			log.Printf("ERR x-csrf-check: %v", v)
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if _, err := m.processAttestation(claims, req.Host, req.Form.Get("args"), true); err != nil {
			log.Printf("ERR processAttestation: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("content-type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"result": "ok",
		})
		m.cfg.EventRecorder.Record("passkey addkey request")

	case "DeleteKey":
		if req.Method != "POST" {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if v := req.Header.Get("x-csrf-check"); v != "1" {
			log.Printf("ERR x-csrf-check: %v", v)
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		id, err := hex.DecodeString(req.Form.Get("id"))
		if err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		h := sha256.Sum256(id)
		if passkeyHash == hex.EncodeToString(h[:]) {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if err := m.deleteKey(email, id); err != nil {
			log.Printf("ERR deleteKey(%q, %v): %v", email, id, err)
		}
		w.Header().Set("content-type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"result": "ok",
		})
		m.cfg.EventRecorder.Record("passkey deletekey request")

	case "JS":
		serveWebauthnJS(w, req)

	case "":
		data := struct {
			Self       string
			Mode       string
			Email      string
			Keys       []keyItem
			CurrentKey string
		}{
			Self:       req.URL.Path,
			Mode:       mode,
			Email:      email,
			Keys:       m.keys(email),
			CurrentKey: passkeyHash,
		}
		w.Header().Set("X-Frame-Options", "DENY")
		manageTemplate.Execute(w, data)

	default:
		http.Error(w, "invalid request", http.StatusBadRequest)
	}
}

type keyItem struct {
	ID       string
	ShortID  string
	Hash     string
	Created  string
	LastSeen string
}

func (m *Manager) keys(email string) []keyItem {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.db.Subjects[email]
	if !ok {
		return nil
	}
	u, ok := m.db.Handles[h]
	if !ok {
		return nil
	}
	keys := make([]keyItem, len(u.Keys))
	for i, k := range u.Keys {
		h := sha256.Sum256(k.ID)
		ki := keyItem{
			ID:       hex.EncodeToString(k.ID),
			ShortID:  hex.EncodeToString(k.ID),
			Hash:     hex.EncodeToString(h[:]),
			Created:  k.CreatedAt.Format("2006-01-02 15:04:05"),
			LastSeen: k.LastSeen.Format("2006-01-02 15:04:05"),
		}
		if len(ki.ShortID) > 8 {
			ki.ShortID = ki.ShortID[:8]
		}
		keys[i] = ki
	}
	return keys
}

func (m *Manager) subjectIsAllowed(email string) bool {
	if m.acl == nil {
		return true
	}
	_, subDomain, _ := strings.Cut(email, "@")
	return slices.Contains(*m.acl, email) || slices.Contains(*m.acl, "@"+subDomain)
}

func (m *Manager) subjectIsRegistered(email string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.db.Subjects[email]
	if !ok {
		return false
	}
	u, ok := m.db.Handles[h]
	return ok && len(u.Keys) > 0
}

func (m *Manager) deleteKey(email string, id Bytes) (retErr error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	commit, err := m.cfg.Store.OpenForUpdate(passkeyFile, &m.db)
	if err != nil {
		return err
	}
	defer commit(false, &retErr)

	h, ok := m.db.Subjects[email]
	if !ok {
		return errors.New("not found")
	}
	u, ok := m.db.Handles[h]
	if !ok {
		return errors.New("not found")
	}
	var keys []*userKey
	for _, k := range u.Keys {
		if !bytes.Equal(k.ID, id) {
			keys = append(keys, k)
		}
	}
	u.Keys = keys
	return commit(true, nil)
}

func (m *Manager) setAuthToken(w http.ResponseWriter, u *url.URL, claims map[string]any) {
	if u == nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	subject, ok := claims["sub"].(string)
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	email, ok := claims["email"].(string)
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	sid, ok := claims["sid"].(string)
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := m.cfg.CookieManager.SetAuthTokenCookie(w, subject, email, sid, u.Hostname(), claims); err != nil {
		log.Printf("ERR SetAuthTokenCookie: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"result":   "ok",
		"redirect": u.String(),
	})
}

func (m *Manager) attestationOptions(claims map[string]any) (*AttestationOptions, error) {
	m.vacuum()
	opts, err := newAttestationOptions()
	if err != nil {
		return nil, err
	}
	email, ok := claims["email"].(string)
	if !ok {
		return nil, errors.New("invalid email")
	}
	ep, err := url.Parse(m.cfg.Endpoint)
	if err != nil {
		return nil, errors.New("internal error")
	}
	opts.User.Name = email
	opts.User.DisplayName = email
	opts.RelyingParty.Name = ep.Host
	opts.RelyingParty.ID = ep.Host

	m.mu.Lock()
	defer m.mu.Unlock()
	if h, ok := m.db.Subjects[email]; ok {
		u, ok := m.db.Handles[h]
		if !ok {
			return nil, errors.New("internal error")
		}
		opts.User.ID = u.Handle
		for _, key := range u.Keys {
			opts.ExcludeCredentials = append(opts.ExcludeCredentials, CredentialID{
				Type:       "public-key",
				ID:         key.ID,
				Transports: key.Transports,
			})
		}
	} else {
		uid := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, uid); err != nil {
			return nil, err
		}
		opts.User.ID = uid
	}

	m.challenges[base64.RawURLEncoding.EncodeToString(opts.Challenge)] = &challenge{
		created: time.Now().UTC(),
		claims:  claims,
		uid:     opts.User.ID,
	}
	return opts, nil
}

func (m *Manager) processAttestation(claims map[string]any, host, jsargs string, allowNewKey bool) (newClaims map[string]any, retErr error) {
	m.vacuum()
	email, ok := claims["email"].(string)
	if !ok {
		return nil, errors.New("invalid email")
	}
	var args struct {
		ClientDataJSON    Bytes    `json:"clientDataJSON"`
		AttestationObject Bytes    `json:"attestationObject"`
		Transports        []string `json:"transports"`
	}
	if err := json.Unmarshal([]byte(jsargs), &args); err != nil {
		return nil, err
	}
	cd, err := parseClientData(args.ClientDataJSON)
	if err != nil {
		return nil, err
	}
	if cd.Type != "webauthn.create" {
		return nil, errors.New("expected clientData.type")
	}
	origin := "https://" + host
	if cd.Origin != origin {
		log.Printf("ERR cd.Origin: %q != %q", cd.Origin, origin)
		return nil, errors.New("expected clientData.origin")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	challenge, ok := m.challenges[cd.Challenge]
	delete(m.challenges, cd.Challenge)

	if !ok || !reflect.DeepEqual(challenge.claims, claims) {
		return nil, errors.New("invalid challenge")
	}

	ao, err := parseAttestationObject(args.AttestationObject)
	if err != nil {
		return nil, err
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if hash := sha256.Sum256([]byte(host)); subtle.ConstantTimeCompare(ao.AuthData.RPIDHash, hash[:]) != 1 {
		log.Printf("ERR rpidHash: %v != %v", ao.AuthData.RPIDHash, hash[:])
		return nil, errors.New("invalid rpIdHash")
	}
	if !ao.AuthData.UserPresence {
		return nil, errors.New("user presence is false")
	}
	if !ao.AuthData.UserVerification {
		return nil, errors.New("user verification is false")
	}
	creds := ao.AuthData.AttestedCredentials
	if creds == nil {
		return nil, errors.New("no attested credentials")
	}

	commit, err := m.cfg.Store.OpenForUpdate(passkeyFile, &m.db)
	if err != nil {
		return nil, err
	}
	defer commit(false, &retErr)

	var u *user
	if h, ok := m.db.Subjects[email]; ok {
		u = m.db.Handles[h]
	}
	if u == nil {
		u = &user{
			Handle: challenge.uid,
			Claims: challenge.claims,
		}
		uids := base64.RawURLEncoding.EncodeToString(challenge.uid)
		m.db.Handles[uids] = u
		m.db.Subjects[email] = uids
	}
	if !allowNewKey && len(u.Keys) > 0 {
		return nil, errors.New("email is already registered")
	}
	now := time.Now().UTC()
	u.Keys = append(u.Keys, &userKey{
		ID:         creds.ID,
		PublicKey:  creds.COSEKey,
		RPIDHash:   ao.AuthData.RPIDHash,
		Transports: args.Transports,
		CreatedAt:  now,
		LastSeen:   now,
	})

	c := maps.Clone(claims)
	h := sha256.Sum256(creds.ID)
	c["passkey_hash"] = hex.EncodeToString(h[:])
	return c, commit(true, nil)
}

func (m *Manager) assertionOptions() (*AssertionOptions, error) {
	m.vacuum()
	opts, err := newAssertionOptions()
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.challenges[base64.RawURLEncoding.EncodeToString(opts.Challenge)] = &challenge{
		created: time.Now().UTC(),
	}
	return opts, nil
}

func (m *Manager) processAssertion(jsargs string, token *jwt.Token) (claims map[string]any, retErr error) {
	m.vacuum()
	var args struct {
		ID                string `json:"id"`
		ClientDataJSON    Bytes  `json:"clientDataJSON"`
		AuthenticatorData Bytes  `json:"authenticatorData"`
		Signature         Bytes  `json:"signature"`
		UserHandle        Bytes  `json:"userHandle"`
	}
	if err := json.Unmarshal([]byte(jsargs), &args); err != nil {
		return nil, err
	}
	cd, err := parseClientData(args.ClientDataJSON)
	if err != nil {
		return nil, err
	}
	if cd.Type != "webauthn.get" {
		return nil, errors.New("unexpected clientData.type")
	}
	var authData authenticatorData
	if err := parseAuthenticatorData(args.AuthenticatorData, &authData); err != nil {
		return nil, err
	}
	if !authData.UserPresence {
		return nil, errors.New("UserPresence is false")
	}
	if !authData.UserVerification {
		return nil, errors.New("UserVerification is false")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.challenges[cd.Challenge]; !ok {
		return nil, errors.New("invalid challenge")
	}
	delete(m.challenges, cd.Challenge)

	commit, err := m.cfg.Store.OpenForUpdate(passkeyFile, &m.db)
	if err != nil {
		return nil, err
	}
	defer commit(false, &retErr)

	u, ok := m.db.Handles[base64.RawURLEncoding.EncodeToString(args.UserHandle)]
	if !ok {
		return nil, errors.New("invalid userHandle")
	}
	kid, err := base64.RawURLEncoding.DecodeString(args.ID)
	if err != nil {
		return nil, err
	}

	var key *userKey
	for _, k := range u.Keys {
		if subtle.ConstantTimeCompare(k.ID, kid) == 1 {
			key = k
			break
		}
	}
	if key == nil {
		return nil, fmt.Errorf("unknown key %v", kid)
	}
	if subtle.ConstantTimeCompare(authData.RPIDHash, key.RPIDHash) != 1 {
		return nil, errors.New("rpIdHash mismatch")
	}
	if err := verifySignature(key.PublicKey, args.AuthenticatorData, args.ClientDataJSON, args.Signature); err != nil {
		return nil, err
	}
	key.LastSeen = time.Now().UTC()

	if token != nil {
		// Refresh claims if ID matches.
		if nc, ok := token.Claims.(jwt.MapClaims); ok && nc["sub"] == u.Claims["sub"] && nc["email"] == u.Claims["email"] {
			u.Claims = nc
		}
	}

	c := maps.Clone(u.Claims)
	h := sha256.Sum256(key.ID)
	c["passkey_hash"] = hex.EncodeToString(h[:])
	return c, commit(true, nil)
}
