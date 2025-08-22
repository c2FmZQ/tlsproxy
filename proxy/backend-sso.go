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
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"

	"github.com/c2FmZQ/tlsproxy/proxy/internal/cookiemanager"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/idp"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/passkeys"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/tokenmanager"
)

type ctxAuthKey struct{}

const (
	xTLSProxyUserIDHeader = "X-tlsproxy-user-id"
)

var (
	authCtxKey ctxAuthKey

	//go:embed permission-denied-template.html
	permissionDeniedEmbed    string
	permissionDeniedTemplate *template.Template
	//go:embed login-template.html
	loginEmbed    string
	loginTemplate *template.Template
	//go:embed logout-template.html
	logoutEmbed    string
	logoutTemplate *template.Template
	//go:embed sso-status-template.html
	ssoStatusEmbed    string
	ssoStatusTemplate *template.Template
	//go:embed style.css
	styleEmbed []byte
)

func init() {
	permissionDeniedTemplate = template.Must(template.New("permission-denied").Parse(permissionDeniedEmbed))
	loginTemplate = template.Must(template.New("login").Parse(loginEmbed))
	logoutTemplate = template.Must(template.New("logout").Parse(logoutEmbed))
	ssoStatusTemplate = template.Must(template.New("sso-status").Parse(ssoStatusEmbed))
}

func claimsFromCtx(ctx context.Context) jwt.MapClaims {
	if v := ctx.Value(authCtxKey); v != nil {
		return v.(jwt.MapClaims)
	}
	return nil
}

// authenticateUser inspects the request headers to get the user's identity, if
// available. It modifies the request headers and context.
// It returns true if processing of the request should continue.
func (be *Backend) authenticateUser(w http.ResponseWriter, req **http.Request) bool {
	(*req).Header.Del(xTLSProxyUserIDHeader)
	if be.SSO != nil {
		claims, cont := be.checkCookies(w, *req)
		if !cont {
			return false
		}
		if claims != nil {
			if email, ok := claims["email"].(string); ok && email != "" {
				if be.SSO.SetUserIDHeader {
					(*req).Header.Set(xTLSProxyUserIDHeader, email)
				}
				*req = (*req).WithContext(context.WithValue((*req).Context(), authCtxKey, claims))
			}
		}
	}
	return true
}

func (be *Backend) checkCookies(w http.ResponseWriter, req *http.Request) (jwt.MapClaims, bool) {
	// If a valid ID Token is in the authorization header, use it and
	// ignore the cookies.
	if tok, err := be.SSO.cm.ValidateAuthorizationHeader(req); err == nil {
		c := tok.Claims.(jwt.MapClaims)
		// Check that device tokens are still valid.
		if clientID, ok := c["device_client_id"].(string); ok {
			if email, ok := c["email"].(string); !ok || !be.SSO.da.AuthorizeClient(clientID, email) {
				w.WriteHeader(http.StatusForbidden)
				return nil, false
			}
		}
		return c, true
	}

	authToken, err := be.SSO.cm.ValidateAuthTokenCookie(req)
	if err != nil {
		return nil, true
	}
	authClaims, ok := authToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, true
	}
	email, ok := authClaims["email"].(string)
	if !ok || email == "" {
		return nil, true
	}

	if !be.SSO.GenerateIDTokens {
		return authClaims, true
	}

	if !slices.Contains(be.ServerNames, hostFromReq(req)) {
		return authClaims, true
	}

	if err := be.SSO.cm.ValidateIDTokenCookie(req, authToken); err == nil {
		// Token is already set, and is valid.
		return authClaims, true
	}
	if err := be.SSO.cm.SetIDTokenCookie(w, req, authToken, be.aclMatcher.groupsForEmail(email)); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return nil, false
	}
	http.Redirect(w, req, req.URL.String(), http.StatusFound)
	return nil, false
}

func (be *Backend) serveSSOStyle(w http.ResponseWriter, req *http.Request) {
	sum := sha256.Sum256(styleEmbed)
	etag := `"` + hex.EncodeToString(sum[:]) + `"`

	w.Header().Set("Content-Type", "text/css")
	w.Header().Set("Cache-Control", "public")
	w.Header().Set("Etag", etag)

	if e := req.Header.Get("If-None-Match"); e == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(styleEmbed)
}

func (be *Backend) serveSSOStatus(w http.ResponseWriter, req *http.Request) {
	claims := claimsFromCtx(req.Context())
	var keys []string
	for k := range claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	type kv struct {
		Key, Value string
	}
	var data struct {
		Token    string
		Claims   []kv
		Passkeys bool
	}
	email, _ := claims["email"].(string)
	if groups := be.aclMatcher.groupsForEmail(email); len(groups) > 0 {
		data.Claims = append(data.Claims, kv{"groups", strings.Join(be.aclMatcher.groupsForEmail(email), ", ")})
	}
	for _, k := range keys {
		if k == "iat" {
			v, _ := claims.GetIssuedAt()
			data.Claims = append(data.Claims, kv{k, v.String()})
			continue
		}
		if k == "exp" {
			v, _ := claims.GetExpirationTime()
			data.Claims = append(data.Claims, kv{k, v.String()})
			continue
		}
		data.Claims = append(data.Claims, kv{k, fmt.Sprint(claims[k])})
	}
	req.URL.Scheme = "https"
	req.URL.Host = req.Host
	token, _, err := be.tm.URLToken(w, req, req.URL, nil)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	data.Token = token
	_, data.Passkeys = be.SSO.p.(*passkeys.Manager)
	ssoStatusTemplate.Execute(w, data)
}

func (be *Backend) serveLogin(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	tok := req.Form.Get("redirect")
	if tok == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	url, claims, err := be.tm.ValidateURLToken(w, req, tok)
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	var email string
	if e, ok := claims["email"].(string); ok {
		email = e
	}
	be.SSO.p.RequestLogin(w, req, url.String(), idp.WithLoginHint(email))
}

func (be *Backend) serveLogout(w http.ResponseWriter, req *http.Request) {
	if be.SSO != nil {
		be.SSO.cm.ClearCookies(w)
	}
	req.ParseForm()
	if tokenStr := req.Form.Get("u"); tokenStr != "" {
		url, _, err := be.tm.ValidateURLToken(w, req, tokenStr)
		if err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		be.SSO.p.RequestLogin(w, req, url.String(), idp.WithSelectAccount(true))
		return
	}
	logoutTemplate.Execute(w, nil)
}

func (be *Backend) servePermissionDenied(w http.ResponseWriter, req *http.Request) {
	var email string
	if claims := claimsFromCtx(req.Context()); claims != nil {
		email, _ = claims["email"].(string)
	}
	req.URL.Scheme = "https"
	req.URL.Host = req.Host
	token, url, err := be.tm.URLToken(w, req, req.URL, nil)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	data := struct {
		Email      string
		URL        string
		DisplayURL string
		Token      string
		Message    template.HTML
	}{
		Email:      email,
		URL:        url,
		DisplayURL: url,
		Token:      token,
		Message:    template.HTML(be.SSO.HTMLMessage),
	}
	if len(data.DisplayURL) > 100 {
		data.DisplayURL = data.DisplayURL[:97] + "..."
	}
	w.WriteHeader(http.StatusForbidden)
	if err := permissionDeniedTemplate.Execute(w, data); err != nil {
		be.logErrorF("ERR permission-denied-template: %v", err)
	}
}

func (be *Backend) enforceSSOPolicy(w http.ResponseWriter, req *http.Request) bool {
	if be.SSO == nil {
		return true
	}
	var rule *SSORule
	for _, r := range be.SSO.Rules {
		if pathMatches(r.Paths, req.URL.Path) && (len(r.Exceptions) == 0 || !pathMatches(r.Exceptions, req.URL.Path)) {
			rule = r
			break
		}
	}
	if rule == nil {
		return true
	}
	claims := claimsFromCtx(req.Context())
	var iat time.Time
	if claims != nil {
		if p, _ := claims.GetIssuedAt(); p != nil {
			iat = p.Time
		}
	}
	hh := sha256.Sum256([]byte(req.Host))
	// Request authentication when:
	// * the user isn't logged in, or
	// * the backend has ForceReAuth set, and the last authentication
	//   either on a different host, or too long ago.
	if claims == nil || (rule.ForceReAuth != 0 && (claims["hhash"] != hex.EncodeToString(hh[:]) || time.Since(iat) > rule.ForceReAuth)) {
		if req.Method != http.MethodGet {
			be.logRequestF("REQ %s ➔ %s %s ➔ status:%d (SSO) (%q)", formatReqDesc(req), req.Method, req.RequestURI, http.StatusForbidden, userAgent(req))
			http.Error(w, "authentication required", http.StatusForbidden)
			return false
		}
		req.URL.Scheme = "https"
		req.URL.Host = req.Host
		var extra map[string]any
		if claims != nil {
			if email, ok := claims["email"].(string); ok {
				extra = map[string]any{
					"email": email,
				}
			}
		}
		token, url, err := be.tm.URLToken(w, req, req.URL, extra)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return false
		}
		if _, ok := be.SSO.p.(*passkeys.Manager); ok || req.Header.Get("x-skip-login-confirmation") != "" {
			be.logRequestF("REQ %s ➔ %s %s ➔ status:%d (SSO) (%q)", formatReqDesc(req), req.Method, req.RequestURI, http.StatusFound, userAgent(req))
			http.Redirect(w, req, "/.sso/login?redirect="+token, http.StatusFound)
			return false
		}
		be.logRequestF("REQ %s ➔ %s %s ➔ status:%d (SSO) (%q)", formatReqDesc(req), req.Method, req.RequestURI, http.StatusForbidden, userAgent(req))
		data := struct {
			URL        string
			DisplayURL string
			Token      string
			IDP        string
		}{
			URL:        url,
			DisplayURL: url,
			Token:      token,
			IDP:        be.SSO.actualIDP,
		}
		if len(data.DisplayURL) > 100 {
			data.DisplayURL = data.DisplayURL[:97] + "..."
		}
		w.WriteHeader(http.StatusForbidden)
		if err := loginTemplate.Execute(w, data); err != nil {
			be.logErrorF("ERR login-template: %v", err)
		}
		return false
	}
	userID, _ := claims["email"].(string)
	host := connServerName(req.Context().Value(connCtxKey).(anyConn))
	if rule.ACL != nil && !be.aclMatcher.emailMatches(*rule.ACL, userID) {
		be.recordEvent(fmt.Sprintf("deny SSO %s to %s", userID, idnaToUnicode(host)))
		be.logRequestF("REQ %s ➔ %s %s ➔ status:%d (SSO) (%q)", formatReqDesc(req), req.Method, req.RequestURI, http.StatusForbidden, userAgent(req))
		be.servePermissionDenied(w, req)
		return false
	}
	be.recordEvent(fmt.Sprintf("allow SSO %s to %s", userID, idnaToUnicode(host)))

	// Filter out the tlsproxy auth cookie.
	cookiemanager.FilterOutAuthTokenCookie(req, tokenmanager.SessionIDCookieName)
	return true
}

func pathMatches(prefixes []string, path string) bool {
	if len(prefixes) == 0 {
		return true
	}
	cleanPath := pathClean(path)
	for _, p := range prefixes {
		if strings.HasPrefix(path, p) || strings.HasPrefix(cleanPath, p) {
			return true
		}
	}
	return false
}
