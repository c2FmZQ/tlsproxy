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
	_ "embed"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"

	"github.com/c2FmZQ/tlsproxy/proxy/internal/cookiemanager"
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
	//go:embed logout-template.html
	logoutEmbed    string
	logoutTemplate *template.Template
	//go:embed sso-status-template.html
	ssoStatusEmbed    string
	ssoStatusTemplate *template.Template
)

func init() {
	permissionDeniedTemplate = template.Must(template.New("permission-denied").Parse(permissionDeniedEmbed))
	logoutTemplate = template.Must(template.New("logout").Parse(logoutEmbed))
	ssoStatusTemplate = template.Must(template.New("sso-status").Parse(ssoStatusEmbed))
}

func claimsFromCtx(ctx context.Context) jwt.Claims {
	if v := ctx.Value(authCtxKey); v != nil {
		return v.(jwt.Claims)
	}
	return nil
}

func (be *Backend) userAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		req.Header.Del(xTLSProxyUserIDHeader)
		if be.SSO != nil {
			claims, cont := be.checkCookies(w, req)
			if !cont {
				return
			}
			if claims != nil {
				sub, err := claims.GetSubject()
				if err == nil && sub != "" {
					if be.SSO.SetUserIDHeader {
						req.Header.Set(xTLSProxyUserIDHeader, sub)
					}
					req = req.WithContext(context.WithValue(req.Context(), authCtxKey, claims))
				}
			}
		}
		// Filter out the tlsproxy auth cookie.
		cookiemanager.FilterOutAuthTokenCookie(req)
		next.ServeHTTP(w, req)
	})
}

func (be *Backend) checkCookies(w http.ResponseWriter, req *http.Request) (jwt.Claims, bool) {
	// If a valid ID Token is in the authorization header, use it and
	// ignore the cookies.
	if tok, err := be.SSO.cm.ValidateAuthorizationHeader(req); err == nil {
		return tok.Claims, true
	}

	authToken, err := be.SSO.cm.ValidateAuthTokenCookie(req)
	if err != nil {
		return nil, true
	}
	sub, err := authToken.Claims.GetSubject()
	if err != nil || sub == "" {
		return nil, true
	}
	authClaims := authToken.Claims

	if !be.SSO.GenerateIDTokens {
		return authClaims, true
	}

	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if !slices.Contains(be.ServerNames, host) {
		return authClaims, true
	}

	if err := be.SSO.cm.ValidateIDTokenCookie(req, authToken); err == nil {
		// Token is already set, and is valid.
		return authClaims, true
	}
	if err := be.SSO.cm.SetIDTokenCookie(w, req, authToken); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return nil, false
	}
	http.Redirect(w, req, req.URL.String(), http.StatusFound)
	return nil, false
}

func (be *Backend) serveSSOStatus(w http.ResponseWriter, req *http.Request) {
	var claims jwt.MapClaims
	if c := claimsFromCtx(req.Context()); c != nil {
		claims, _ = c.(jwt.MapClaims)
	}
	var keys []string
	for k := range claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	type kv struct {
		Key, Value string
	}
	var data struct {
		Token  string
		Claims []kv
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
	token, _, err := be.makeTokenForURL(req)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	data.Token = token
	ssoStatusTemplate.Execute(w, data)
}

func (be *Backend) serveLogout(w http.ResponseWriter, req *http.Request) {
	if be.SSO != nil {
		be.SSO.cm.ClearCookies(w)
	}
	req.ParseForm()
	if tokenStr := req.Form.Get("u"); tokenStr != "" {
		tok, err := be.tm.ValidateToken(tokenStr)
		if err == jwt.ErrTokenExpired {
			http.Error(w, "data expired", http.StatusBadRequest)
			return
		}
		if err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		c, ok := tok.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		url, ok := c["url"].(string)
		if !ok {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		be.SSO.p.RequestLogin(w, req, url)
		return
	}
	logoutTemplate.Execute(w, nil)
}

func (be *Backend) servePermissionDenied(w http.ResponseWriter, req *http.Request) {
	var subject string
	if claims := claimsFromCtx(req.Context()); claims != nil {
		subject, _ = claims.GetSubject()
	}
	token, url, err := be.makeTokenForURL(req)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	data := struct {
		Subject    string
		URL        string
		DisplayURL string
		Token      string
	}{
		Subject:    subject,
		URL:        url,
		DisplayURL: url,
		Token:      token,
	}
	if len(data.DisplayURL) > 100 {
		data.DisplayURL = data.DisplayURL[:97] + "..."
	}
	w.WriteHeader(http.StatusForbidden)
	permissionDeniedTemplate.Execute(w, data)
}

func (be *Backend) enforceSSOPolicy(w http.ResponseWriter, req *http.Request) bool {
	if be.SSO == nil || !pathMatches(be.SSO.Paths, req.URL.Path) {
		return true
	}
	claims := claimsFromCtx(req.Context())
	if claims == nil {
		u := req.URL
		u.Scheme = "https"
		u.Host = req.Host
		log.Printf("REQ %s ➔ %s %s ➔ status:%d (SSO)", formatReqDesc(req), req.Method, req.RequestURI, http.StatusFound)
		be.SSO.p.RequestLogin(w, req, u.String())
		return false
	}
	userID, _ := claims.GetSubject()
	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	_, userDomain, _ := strings.Cut(userID, "@")
	if be.SSO.ACL != nil && !slices.Contains(*be.SSO.ACL, userID) && !slices.Contains(*be.SSO.ACL, "@"+userDomain) {
		be.recordEvent(fmt.Sprintf("deny %s to %s", userID, host))
		log.Printf("REQ %s ➔ %s %s ➔ status:%d (SSO)", formatReqDesc(req), req.Method, req.RequestURI, http.StatusForbidden)
		be.servePermissionDenied(w, req)
		return false
	}
	be.recordEvent(fmt.Sprintf("allow %s to %s", userID, host))
	return true
}

func pathMatches(prefixes []string, path string) bool {
	if len(prefixes) == 0 {
		return true
	}
	for _, p := range prefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func (be *Backend) makeTokenForURL(req *http.Request) (string, string, error) {
	u := req.URL
	u.Scheme = "https"
	u.Host = req.Host
	token, err := be.tm.CreateToken(jwt.MapClaims{
		"url": u.String(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}, "ES256")
	return token, u.String(), err
}
