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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"golang.org/x/net/idna"
)

const (
	SessionIDCookieName = "TLSPROXYSID"
)

func sessionID(w http.ResponseWriter, req *http.Request) string {
	var sid string
	if cookie, err := req.Cookie(SessionIDCookieName); err == nil {
		sid = cookie.Value
	} else {
		var buf [16]byte
		io.ReadFull(rand.Reader, buf[:])
		sid = hex.EncodeToString(buf[:])
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionIDCookieName,
		Value:    sid,
		Path:     "/",
		Expires:  time.Now().Add(30 * 24 * time.Hour),
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
		HttpOnly: true,
	})
	return sid
}

// URLToken returns a signed token for URL u in the context of request req.
func (tm *TokenManager) URLToken(w http.ResponseWriter, req *http.Request, u *url.URL) (string, string, error) {
	sid := sessionID(w, req)
	realHost := u.Host
	if h, err := idna.Lookup.ToUnicode(u.Hostname()); err == nil {
		u.Host = h
	}
	displayURL := u.String()
	u.Host = realHost
	token, err := tm.CreateToken(jwt.MapClaims{
		"url": u.String(),
		"sid": sid,
	}, "")
	return token, displayURL, err
}

// ValidateURLToken validates a signed token and returns the URL. The request
// must on the same host as the one where the token was created.
func (tm *TokenManager) ValidateURLToken(w http.ResponseWriter, req *http.Request, token string) (*url.URL, error) {
	tok, err := tm.ValidateToken(token)
	if err != nil {
		return nil, err
	}
	c, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token")
	}
	if sid := sessionID(w, req); sid != c["sid"] {
		log.Printf("ERR session ID mismatch %q != %q", sid, c["sid"])
		return nil, errors.New("invalid token")
	}
	u, ok := c["url"].(string)
	if !ok {
		return nil, errors.New("invalid token")
	}
	return url.Parse(u)
}
