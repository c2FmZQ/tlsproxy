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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"golang.org/x/net/idna"

	"github.com/c2FmZQ/tlsproxy/proxy/internal/fromctx"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/tokenmanager"
)

const (
	tlsProxyAuthCookie    = "TLSPROXYAUTH"
	tlsProxyIDTokenCookie = "TLSPROXYIDTOKEN"
	tlsProxyNonce         = "TLSPROXYNONCE"

	expiredAuthTokenLeeway = 7 * 24 * time.Hour
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

func (cm *CookieManager) Issuer() string {
	return cm.issuer
}

func (cm *CookieManager) SetAuthTokenCookie(w http.ResponseWriter, req *http.Request, userID, email, sessionID, host string, extraClaims map[string]any) error {
	if userID == "" || email == "" {
		return errors.New("userID and email cannot be empty")
	}
	hh := sha256.Sum256([]byte(host))
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"sub":       userID,
		"email":     email,
		"proxyauth": cm.issuer,
		"provider":  cm.provider,
		"hhash":     hex.EncodeToString(hh[:]),
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
	var th []any
	if v := fromctx.TokenHash(req.Context()); v != "" {
		th = append(th, v)
	}
	if c := fromctx.Claims(req.Context()); c != nil && c["sub"] == claims["sub"] && c["th"] != nil {
		if v, ok := c["th"].([]any); ok {
			th = append(th, v...)
		}
	} else if c := fromctx.ExpiredClaims(req.Context()); c != nil && c["sub"] == claims["sub"] && c["th"] != nil {
		if v, ok := c["th"].([]any); ok {
			th = append(th, v...)
		}
	}
	if len(th) > 0 {
		if n := 3; len(th) > n {
			th = th[:n]
		}
		claims["th"] = th
	}
	token, err := cm.MintToken(claims, 20*time.Hour, cm.issuer, "")
	if err != nil {
		return err
	}
	cookie := &http.Cookie{
		Name:     tlsProxyAuthCookie,
		Value:    token,
		Domain:   cm.domain,
		Path:     "/",
		Expires:  now.Add(20*time.Hour + expiredAuthTokenLeeway),
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
	return nil
}

func (cm *CookieManager) MintToken(claims jwt.MapClaims, ttl time.Duration, audience any, alg string) (string, error) {
	now := time.Now().UTC()
	claims["iss"] = cm.issuer
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(ttl).Unix()
	claims["aud"] = audience
	return cm.tm.CreateToken(claims, alg)
}

func (cm *CookieManager) IDClaims(authClaims jwt.MapClaims, groups []string) jwt.MapClaims {
	allowed := []string{
		"email",
		"email_verified",
		"name",
		"given_name",
		"middle_name",
		"family_name",
		"nickname",
		"preferred_username",
		"profile",
		"picture",
		"website",
		"gender",
		"birthdate",
		"zoneinfo",
		"locale",
		"iss",
		"sub",
		"client_id",
		"nonce",
		"sid",
	}
	claims := jwt.MapClaims{}
	for _, c := range allowed {
		if v := authClaims[c]; v != nil {
			claims[c] = v
		}
	}
	claims["scope"] = []string{"openid"}
	if len(groups) > 0 {
		claims["groups"] = groups
	}
	return claims
}

func (cm *CookieManager) SetIDTokenCookie(w http.ResponseWriter, req *http.Request, authClaims jwt.MapClaims, groups []string) error {
	exp, err := authClaims.GetExpirationTime()
	if err != nil {
		return err
	}
	token, err := cm.MintToken(cm.IDClaims(authClaims, groups), exp.Sub(time.Now()), AudienceForToken(req), "ES256")
	if err != nil {
		return err
	}
	cookie := &http.Cookie{
		Name:     tlsProxyIDTokenCookie,
		Value:    token,
		Path:     "/",
		Expires:  time.Now().UTC().Add(24 * time.Hour),
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
	return nil
}

func (cm *CookieManager) SetNonce(w http.ResponseWriter, nonce string) {
	http.SetCookie(w, &http.Cookie{
		Name:     tlsProxyNonce,
		Value:    nonce,
		Domain:   cm.domain,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
		HttpOnly: true,
	})
}

func (cm *CookieManager) Nonce(w http.ResponseWriter, req *http.Request) string {
	http.SetCookie(w, &http.Cookie{
		Name:     tlsProxyNonce,
		Domain:   cm.domain,
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
	})
	if c, err := req.Cookie(tlsProxyNonce); err == nil {
		return c.Value
	}
	return ""
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

func (cm *CookieManager) validateAuthToken(req *http.Request, leeway time.Duration) (*jwt.Token, string, error) {
	cookie, err := req.Cookie(tlsProxyAuthCookie)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", tlsProxyAuthCookie, err)
	}
	tok, err := cm.tm.ValidateToken(cookie.Value,
		jwt.WithIssuer(cm.issuer),
		jwt.WithAudience(cm.issuer),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(leeway),
	)
	if err != nil {
		return nil, "", err
	}
	if c, ok := tok.Claims.(jwt.MapClaims); !ok || c["proxyauth"] != cm.issuer || c["provider"] != cm.provider {
		return nil, "", errors.New("invalid proxyauth or provider")
	}
	if sub, err := tok.Claims.GetSubject(); err != nil || sub == "" {
		return nil, "", errors.New("invalid subject")
	}
	return tok, hex.EncodeToString(cm.tm.HMAC([]byte(cookie.Value))[:16]), nil
}

func (cm *CookieManager) ValidateAuthTokenCookie(req *http.Request) (*jwt.Token, string, error) {
	return cm.validateAuthToken(req, 0)
}

func (cm *CookieManager) ValidateExpiredAuthTokenCookie(req *http.Request) (*jwt.Token, string, error) {
	token, th, err := cm.validateAuthToken(req, expiredAuthTokenLeeway)
	if err != nil {
		return nil, "", err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, "", errors.New("internal error")
	}
	exp, err := claims.GetExpirationTime()
	if err != nil {
		return nil, "", err
	}
	if time.Now().Before(exp.Time) {
		return nil, "", errors.New("token is not expired")
	}
	return token, th, nil
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

func AudienceForToken(req *http.Request) any {
	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	uniHost, err := idna.Lookup.ToUnicode(host)
	if err != nil || uniHost == host {
		return "https://" + host + "/"
	}
	return []string{
		"https://" + host + "/",
		"https://" + uniHost + "/",
	}
}
