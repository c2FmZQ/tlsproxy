// MIT License
//
// Copyright (c) 2024 TTBT Enterprises LLC
// Copyright (c) 2024 Robin Thellend <rthellend@rthellend.com>
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

package tokenmanager

import (
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"slices"

	jwt "github.com/golang-jwt/jwt/v5"
	"golang.org/x/net/idna"

	"github.com/c2FmZQ/tlsproxy/proxy/internal/fromctx"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/sid"
)

// URLToken returns a signed token for URL u in the context of request req.
func (tm *TokenManager) URLToken(req *http.Request, u *url.URL, extra map[string]any) (string, string, error) {
	realHost := u.Host
	if h, err := idna.Lookup.ToUnicode(u.Hostname()); err == nil {
		u.Host = h
	}
	sid := sid.SessionID(req)
	if sid == "" {
		return "", "", errors.New("no session id")
	}
	displayURL := u.String()
	u.Host = realHost
	claims := make(jwt.MapClaims)
	for k, v := range extra {
		claims[k] = v
	}
	claims["url"] = u.String()
	claims["hsid"] = base64.StdEncoding.EncodeToString(tm.HMAC([]byte(sid)))
	token, err := tm.CreateToken(claims, "")
	return token, displayURL, err
}

// ValidateURLToken validates a signed token and returns the URL. The request
// must on the same host as the one where the token was created.
func (tm *TokenManager) ValidateURLToken(req *http.Request, token string) (*url.URL, jwt.MapClaims, error) {
	tok, err := tm.ValidateToken(token)
	if err != nil {
		return nil, nil, err
	}
	c, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return nil, nil, errors.New("invalid token")
	}
	if !tm.sidOK(req, c["hsid"]) {
		tm.logger.Errorf("ERR session ID mismatch %v", c["sid"])
		return nil, nil, errors.New("url token is expired")
	}
	u, ok := c["url"].(string)
	if !ok {
		return nil, nil, errors.New("invalid token")
	}
	tokURL, err := url.Parse(u)
	return tokURL, c, err
}

func (tm *TokenManager) sidOK(req *http.Request, v any) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	want, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return false
	}
	match := func(v any) bool {
		s, ok := v.(string)
		if !ok {
			return false
		}
		return hmac.Equal(want, tm.HMAC([]byte(s)))
	}
	if match(sid.SessionID(req)) {
		return true
	}
	c := fromctx.Claims(req.Context())
	if c == nil {
		c = fromctx.ExpiredClaims(req.Context())
	}
	if c == nil {
		return false
	}
	th, ok := c["th"].([]any)
	if !ok {
		return false
	}
	return slices.ContainsFunc(th, match)
}
