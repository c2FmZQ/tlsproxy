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

package cookiemanager

import (
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"

	"github.com/c2FmZQ/tlsproxy/proxy/internal/tokenmanager"
)

const (
	tlsProxyAuthCookie    = "TLSPROXYAUTH"
	tlsProxyIDTokenCookie = "TLSPROXYIDTOKEN"
)

type CookieManager struct {
	tm       *tokenmanager.TokenManager
	provider string
	domain   string
	issuer   string
}

func New(tm *tokenmanager.TokenManager, provider, domain, issuer string) *CookieManager {
	return &CookieManager{
		tm:       tm,
		provider: provider,
		domain:   domain,
		issuer:   issuer,
	}
}

func (cm *CookieManager) SetAuthTokenCookie(w http.ResponseWriter, userID, sessionID string, extraClaims map[string]any) error {
	if userID == "" {
		return errors.New("userID cannot be empty")
	}
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iat":       now.Unix(),
		"exp":       now.Add(20 * time.Hour).Unix(),
		"iss":       cm.issuer,
		"aud":       cm.issuer,
		"sub":       userID,
		"proxyauth": cm.issuer,
		"provider":  cm.provider,
		"sid":       sessionID,
	}
	if extraClaims != nil {
		for k, v := range extraClaims {
			if _, exists := claims[k]; exists {
				continue
			}
			claims[k] = v
		}
	}
	token, err := cm.tm.CreateToken(claims, "ES256")
	if err != nil {
		return err
	}
	cookie := &http.Cookie{
		Name:     tlsProxyAuthCookie,
		Value:    token,
		Domain:   cm.domain,
		Path:     "/",
		Expires:  now.Add(24 * time.Hour),
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
	return nil
}

func (cm *CookieManager) SetIDTokenCookie(w http.ResponseWriter, req *http.Request, authToken *jwt.Token) error {
	audience := audienceFromReq(req)

	c, ok := authToken.Claims.(jwt.MapClaims)
	if !ok {
		return errors.New("internal error")
	}
	now := time.Now().UTC()
	claims := jwt.MapClaims{}
	for k, v := range c {
		if k == "scope" || k == "proxyauth" || k == "source" {
			continue
		}
		claims[k] = v
	}
	claims["iat"] = now.Unix()
	claims["aud"] = audience
	token, err := cm.tm.CreateToken(claims, "ES256")
	if err != nil {
		return err
	}
	cookie := &http.Cookie{
		Name:     tlsProxyIDTokenCookie,
		Value:    token,
		Path:     "/",
		Expires:  now.Add(24 * time.Hour),
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
	return nil
}

func (cm *CookieManager) ClearCookies(w http.ResponseWriter) error {
	cookie := &http.Cookie{
		Name:     tlsProxyAuthCookie,
		Domain:   cm.domain,
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
	cookie = &http.Cookie{
		Name:     tlsProxyIDTokenCookie,
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
	return nil
}

func (cm *CookieManager) ValidateAuthTokenCookie(req *http.Request) (*jwt.Token, error) {
	cookie, err := req.Cookie(tlsProxyAuthCookie)
	if err != nil {
		return nil, err
	}
	tok, err := cm.tm.ValidateToken(cookie.Value, jwt.WithIssuer(cm.issuer), jwt.WithAudience(cm.issuer))
	if err != nil {
		return nil, err
	}
	if c, ok := tok.Claims.(jwt.MapClaims); !ok || c["proxyauth"] != cm.issuer || c["provider"] != cm.provider {
		return nil, errors.New("invalid proxyauth or provider")
	}
	if sub, err := tok.Claims.GetSubject(); err != nil || sub == "" {
		return nil, errors.New("invalid subject")
	}
	return tok, nil
}

func (cm *CookieManager) ValidateIDTokenCookie(req *http.Request, authToken *jwt.Token) error {
	audience := audienceFromReq(req)

	c, ok := authToken.Claims.(jwt.MapClaims)
	if !ok {
		return errors.New("internal error")
	}
	cookie, err := req.Cookie(tlsProxyIDTokenCookie)
	if err != nil {
		return err
	}
	tok, err := cm.tm.ValidateToken(cookie.Value, jwt.WithIssuer(cm.issuer), jwt.WithAudience(audience))
	if err != nil {
		return err
	}
	if c2, ok := tok.Claims.(jwt.MapClaims); !ok || c2["sub"] != c["sub"] || c2["sid"] != c["sid"] {
		return errors.New("sid mismatch")
	}
	// Token is already set, and is valid.
	return nil
}

func (cm *CookieManager) ValidateAuthorizationHeader(req *http.Request) (*jwt.Token, error) {
	h := req.Header.Get("Authorization")
	if len(h) < 7 || strings.ToUpper(h[:7]) != "BEARER " {
		return nil, errors.New("invalid authorization header")
	}
	tok, err := cm.tm.ValidateToken(h[7:], jwt.WithIssuer(cm.issuer), jwt.WithAudience(audienceFromReq(req)))
	if err != nil {
		return nil, err
	}
	if c, ok := tok.Claims.(jwt.MapClaims); !ok || c["proxyauth"] != nil {
		return nil, errors.New("invalid proxyauth")
	}
	return tok, nil
}

func FilterOutAuthTokenCookie(req *http.Request) {
	cookies := req.Cookies()
	req.Header.Del("Cookie")
	for _, c := range cookies {
		if c.Name != tlsProxyAuthCookie {
			req.AddCookie(c)
		}
	}
}

func audienceFromReq(req *http.Request) string {
	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return "https://" + host + "/"
}
