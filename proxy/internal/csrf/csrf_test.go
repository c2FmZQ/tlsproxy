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

package csrf

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/c2FmZQ/tlsproxy/proxy/internal/fromctx"
)

func TestCheck(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
		auth   string
		bearer bool
		want   bool
	}{
		{"GET", http.MethodGet, "", false, true},
		{"POST without token", http.MethodPost, "", false, false},
		{"POST with Basic auth", http.MethodPost, "Basic Zm9vOmJhcg==", false, false},
		{"POST with invalid bearer", http.MethodPost, "Bearer foo", false, false},
		{"POST with valid bearer", http.MethodPost, "Bearer foo", true, true},
	} {
		req := httptest.NewRequest(tc.method, "https://example.com/", nil)
		if tc.auth != "" {
			req.Header.Set("Authorization", tc.auth)
		}
		if tc.bearer {
			req = req.WithContext(fromctx.WithBearerAuth(req.Context()))
		}
		if got := Check(httptest.NewRecorder(), req); got != tc.want {
			t.Errorf("%s: Check() = %v, want %v", tc.name, got, tc.want)
		}
	}
}
