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

	"github.com/c2FmZQ/tlsproxy/proxy/internal/cookiemanager"
)

const (
	xTLSProxyUserIDHeader = "X-tlsproxy-user-id"
)

func (be *Backend) getUserAuthentication(w http.ResponseWriter, req *http.Request) bool {
	// Filter out the tlsproxy auth cookie.
	defer cookiemanager.FilterOutAuthTokenCookie(req)

	req.Header.Del(xTLSProxyUserIDHeader)
	if be.SSO != nil && !be.checkCookies(w, req) {
		return false
	}
	return true
}

func (be *Backend) checkCookies(w http.ResponseWriter, req *http.Request) bool {
	authToken, err := be.SSO.cm.ValidateAuthTokenCookie(req)
	if err != nil {
		return true
	}
	sub, err := authToken.Claims.GetSubject()
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

	if err := be.SSO.cm.ValidateIDTokenCookie(req, authToken); err == nil {
		// Token is already set, and is valid.
		return true
	}
	if err := be.SSO.cm.SetIDTokenCookie(w, req, authToken); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return false
	}
	http.Redirect(w, req, req.URL.String(), http.StatusFound)
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
		be.SSO.p.RequestLogin(w, req, u.String())
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
		be.SSO.cm.ClearCookies(w)
		http.Error(w, "Forbidden: "+userID, http.StatusForbidden)
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
