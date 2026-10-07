// MIT License
//
// Copyright (c) 2026 TTBT Enterprises LLC
// Copyright (c) 2026 Robin Thellend <rthellend@rthellend.com>
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

package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"

	"github.com/c2FmZQ/tlsproxy/proxy/internal/fromctx"
)

type nopRecorder struct{}

func (nopRecorder) Record(string) {}

func TestDeviceAuthorizationLimits(t *testing.T) {
	s := NewServer(ServerOptions{
		Clients:       []Client{{ID: "client"}},
		ACLMatcher:    func([]string, string) bool { return true },
		EventRecorder: nopRecorder{},
		Logger:        nopLogger{},
	})

	deviceAuth := func() (int, string) {
		req := httptest.NewRequest(http.MethodPost, "https://idp.example.com/device/authorization", strings.NewReader("client_id=client"))
		req.Header.Set("content-type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		s.ServeDeviceAuthorization(w, req)
		var resp struct {
			UserCode string `json:"user_code"`
		}
		json.NewDecoder(w.Body).Decode(&resp)
		return w.Code, resp.UserCode
	}

	// An expired request can't be used, even before it is vacuumed.
	code, userCode := deviceAuth()
	if code != http.StatusOK {
		t.Fatalf("deviceAuth: code %d", code)
	}
	s.mu.Lock()
	s.deviceCodes[userCode].created = time.Now().Add(-2 * codeExpiration)
	s.mu.Unlock()

	form := url.Values{"user_code": {userCode}, "approve": {"true"}}
	req := httptest.NewRequest(http.MethodPost, "https://idp.example.com/device/verify", strings.NewReader(form.Encode()))
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	req = req.WithContext(fromctx.WithClaims(req.Context(), jwt.MapClaims{"email": "bob@example.com"}))
	w := httptest.NewRecorder()
	s.ServeDeviceVerification(w, req)
	if got, want := w.Code, http.StatusBadRequest; got != want {
		t.Errorf("ServeDeviceVerification(expired) = %d, want %d", got, want)
	}

	// The number of pending requests is limited.
	for range maxPendingRequests {
		if code, _ := deviceAuth(); code != http.StatusOK {
			s.mu.Lock()
			n := len(s.deviceTokens)
			s.mu.Unlock()
			if code != http.StatusServiceUnavailable || n < maxPendingRequests {
				t.Fatalf("deviceAuth: code %d with %d pending", code, n)
			}
			break
		}
	}
	if code, _ := deviceAuth(); code != http.StatusServiceUnavailable {
		t.Errorf("deviceAuth: code %d, want %d", code, http.StatusServiceUnavailable)
	}
}

type nopLogger struct{}

func (nopLogger) Errorf(string, ...any) {}
