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

package sid

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	tlsProxySessionIDCookie = "__tlsproxySid"
)

func SetSessionID(w http.ResponseWriter, req *http.Request, value string) {
	if value == "" {
		var buf [16]byte
		io.ReadFull(rand.Reader, buf[:])
		value = hex.EncodeToString(buf[:])
	}
	cookie := &http.Cookie{
		Name:     tlsProxySessionIDCookie,
		Value:    value,
		Path:     "/",
		Expires:  time.Now().Add(30 * 24 * time.Hour),
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
		HttpOnly: false,
	}
	if req != nil {
		cookies := req.Cookies()
		req.Header.Del("Cookie")
		for _, c := range cookies {
			if c.Name != tlsProxySessionIDCookie {
				req.AddCookie(c)
			}
		}
		req.AddCookie(cookie)
	}
	if w != nil {
		if h := w.Header()["Set-Cookie"]; h != nil {
			out := make([]string, 0, len(h))
			for _, hh := range h {
				if !strings.HasPrefix(hh, tlsProxySessionIDCookie+"=") {
					out = append(out, hh)
				}
			}
			w.Header()["Set-Cookie"] = out
		}
		http.SetCookie(w, cookie)
	}
}

func SessionID(req *http.Request) string {
	if cookie, err := req.Cookie(tlsProxySessionIDCookie); err == nil {
		return cookie.Value
	}
	return ""
}
