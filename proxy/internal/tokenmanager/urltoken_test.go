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
	"net/http/httptest"
	"testing"

	"github.com/c2FmZQ/storage"
	"github.com/c2FmZQ/storage/crypto"
)

func TestURLToken(t *testing.T) {
	dir := t.TempDir()
	mk, err := crypto.CreateAESMasterKeyForTest()
	if err != nil {
		t.Fatalf("crypto.CreateMasterKey: %v", err)
	}
	store := storage.New(dir, mk)
	tm, err := New(store, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("GET", "https://example.com/foo/bar", nil)
	w := httptest.NewRecorder()
	tok, displayURL, err := tm.URLToken(w, req, req.URL, nil)
	if err != nil {
		t.Errorf("URLToken() err = %v", err)
	}
	if got, want := displayURL, "https://example.com/foo/bar"; got != want {
		t.Errorf("displayURL = %q, want %q", got, want)
	}

	// Wrong session id
	if _, _, err := tm.ValidateURLToken(w, req, tok); err == nil {
		t.Fatal("ValidateURLToken should fail")
	}

	// Correct session id
	req.Header.Set("cookie", w.Header().Get("set-cookie"))
	u, _, err := tm.ValidateURLToken(w, req, tok)
	if err != nil {
		t.Errorf("ValidateURLToken err = %v", err)
	}
	if got, want := u.String(), "https://example.com/foo/bar"; got != want {
		t.Errorf("url = %q, want %q", got, want)
	}
}
