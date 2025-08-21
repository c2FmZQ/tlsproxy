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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/c2FmZQ/storage"
	"github.com/c2FmZQ/storage/crypto"
	jwt "github.com/golang-jwt/jwt/v5"

	"github.com/c2FmZQ/tlsproxy/proxy/internal/tokenmanager"
)

func TestCookies(t *testing.T) {
	dir := t.TempDir()
	mk, err := crypto.CreateAESMasterKeyForTest()
	if err != nil {
		t.Fatalf("crypto.CreateMasterKey: %v", err)
	}
	store := storage.New(dir, mk)
	tm, err := tokenmanager.New(store, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cm := New(tm, "idp", "example.com", "https://idp.example.com")

	recorder := httptest.NewRecorder()

	if err := cm.SetAuthTokenCookie(recorder, "test@example.com", "test@example.com", "session123", "example.com", nil); err != nil {
		t.Fatalf("SetAuthTokenCookie: %v", err)
	}

	v := recorder.Header().Get("Set-Cookie")
	if v == "" {
		t.Fatal("cookie not set")
	}
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("cookie", v)

	tok, err := cm.ValidateAuthTokenCookie(req)
	if err != nil {
		t.Fatalf("ValidateAuthTokenCookie: %v", err)
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("not jwt.MapClaims")
	}
	if got, want := claims["sub"], "test@example.com"; got != want {
		t.Errorf("sub = %q, want %q", got, want)
	}
	if got, want := claims["sid"], "session123"; got != want {
		t.Errorf("sid = %q, want %q", got, want)
	}

	recorder = httptest.NewRecorder()
	if err := cm.SetIDTokenCookie(recorder, req, tok, nil); err != nil {
		t.Fatal("cookie not set")
	}
	v = recorder.Header().Get("Set-Cookie")
	if v == "" {
		t.Fatal("cookie not set")
	}
	req.Header.Set("cookie", v)
	if err := cm.ValidateIDTokenCookie(req, tok); err != nil {
		t.Fatalf("ValidateIDTokenCookie: %v", err)
	}
}
