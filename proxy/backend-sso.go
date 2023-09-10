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
	"fmt"
	"log"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

const (
	xTLSProxyUserIDHeader = "X-tlsproxy-user-id"
)

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

func (be *Backend) enforceSSOPolicy(w http.ResponseWriter, req *http.Request) bool {
	if be.SSO == nil || !pathMatches(be.SSO.Paths, req.URL.Path) {
		return true
	}
	userID := req.Header.Get(xTLSProxyUserIDHeader)
	if userID == "" {
		u := req.URL
		u.Scheme = "https"
		u.Host = req.Host
		log.Printf("REQ %s ➔ %s %s ➔ status:%d (SSO)", formatReqDesc(req), req.Method, req.RequestURI, http.StatusFound)
		be.SSO.p.requestLogin(w, req, u.String())
		return false
	}
	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	_, userDomain, _ := strings.Cut(userID, "@")
	if be.SSO.ACL != nil && !slices.Contains(*be.SSO.ACL, userID) && !slices.Contains(*be.SSO.ACL, "@"+userDomain) {
		be.recordEvent(fmt.Sprintf("deny %s to %s", userID, host))
		log.Printf("REQ %s ➔ %s %s ➔ status:%d (SSO)", formatReqDesc(req), req.Method, req.RequestURI, http.StatusForbidden)
		cookie := &http.Cookie{
			Name:     tlsProxyAuthCookie,
			Value:    "",
			Domain:   be.SSO.p.domain(),
			MaxAge:   -1,
			Secure:   true,
			HttpOnly: true,
		}
		http.SetCookie(w, cookie)
		cookie = &http.Cookie{
			Name:     tlsProxyIDTokenCookie,
			Value:    "",
			MaxAge:   -1,
			Secure:   true,
			HttpOnly: true,
		}
		http.SetCookie(w, cookie)
		http.Error(w, "Forbidden: "+userID, http.StatusForbidden)
		return false
	}
	be.recordEvent(fmt.Sprintf("allow %s to %s", userID, host))
	return true
}

func (be *Backend) checkUserAuthentication(w http.ResponseWriter, req *http.Request) bool {
	req.Header.Del(xTLSProxyUserIDHeader)
	if be.SSO != nil && !be.checkCookies(w, req) {
		return false
	}
	// Filter out the tlsproxy auth cookie.
	cookies := req.Cookies()
	req.Header.Del("Cookie")
	for _, c := range cookies {
		if c.Name != tlsProxyAuthCookie {
			req.AddCookie(c)
		}
	}
	return true
}

func (be *Backend) checkCookies(w http.ResponseWriter, req *http.Request) bool {
	cookie, err := req.Cookie(tlsProxyAuthCookie)
	if err != nil {
		return true
	}
	tok, err := be.SSO.p.validateToken(cookie.Value)
	if err != nil {
		return true
	}
	sub, err := tok.Claims.GetSubject()
	if err != nil || sub == "" {
		return true
	}
	req.Header.Set(xTLSProxyUserIDHeader, sub)
	if !be.SSO.GenerateIDTokens {
		return true
	}

	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if !slices.Contains(be.ServerNames, host) {
		return true
	}
	aud := "https://" + host + "/"
	c, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return false
	}
	iss, ok := c["iss"].(string)
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return false
	}
	if cookie, err := req.Cookie(tlsProxyIDTokenCookie); err == nil {
		if tok2, err := be.SSO.p.tokenManager().ValidateToken(cookie.Value, jwt.WithIssuer(iss), jwt.WithAudience(aud)); err == nil {
			if c2, ok := tok2.Claims.(jwt.MapClaims); ok && c2["sid"] == c["sid"] {
				// Token is already set, and is valid.
				return true
			}
		}
	}
	now := time.Now().UTC()
	token, err := be.SSO.p.tokenManager().CreateToken(jwt.MapClaims{
		"iat": now.Unix(),
		"exp": c["exp"],
		"iss": c["iss"],
		"aud": aud,
		"sub": c["sub"],
		"sid": c["sid"],
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return false
	}
	cookie = &http.Cookie{
		Name:     tlsProxyIDTokenCookie,
		Value:    token,
		Path:     "/",
		Expires:  now.Add(24 * time.Hour),
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, req, req.URL.String(), http.StatusFound)
	return false
}
