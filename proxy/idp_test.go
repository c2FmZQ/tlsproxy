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
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/c2FmZQ/storage"
	"github.com/c2FmZQ/storage/crypto"
	jwt "github.com/golang-jwt/jwt/v5"
	jwttest "github.com/golang-jwt/jwt/v5/test"
)

func TestTokenManager(t *testing.T) {
	dir := t.TempDir()
	mk, err := crypto.CreateAESMasterKeyForTest()
	if err != nil {
		t.Fatalf("crypto.CreateMasterKey: %v", err)
	}
	store := storage.New(dir, mk)
	tm1, err := newTokenManager(store)
	if err != nil {
		t.Fatalf("newTokenManager: %v", err)
	}
	tok, err := tm1.createToken(jwt.MapClaims{
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"sub": "test@example.com",
		"iss": "https://login.example.com",
		"aud": "https://login.example.com",
	})
	if err != nil {
		t.Fatalf("tm.createToken: %v", err)
	}
	t.Logf("TOKEN: %s", tok)

	tm2, err := newTokenManager(store)
	if err != nil {
		t.Fatalf("newTokenManager: %v", err)
	}
	for _, tm := range []*tokenManager{tm1, tm2} {
		if _, err := tm.validateToken(tok,
			jwt.WithAudience("https://login.example.com"),
			jwt.WithIssuer("https://login.example.com"),
			jwt.WithSubject("test@example.com"),
		); err != nil {
			t.Fatalf("tm.validateToken: %v", err)
		}
	}

	tok2, err := tm1.createToken(jwt.MapClaims{
		"iat": time.Now().Add(-10 * time.Minute).Unix(),
		"exp": time.Now().Add(-5 * time.Minute).Unix(),
		"sub": "test@example.com",
		"iss": "https://login.example.com",
		"aud": "https://login.example.com",
	})
	if err != nil {
		t.Fatalf("tm.createToken: %v", err)
	}
	t.Logf("TOKEN2: %s", tok2)
	if _, err := tm1.validateToken(tok2); err == nil {
		t.Fatal("tm.validateToken should fail")
	}
}

type eventRecorder struct {
	events []string
}

func (er *eventRecorder) record(e string) {
	er.events = append(er.events, e)
}

type idpServer struct {
	*httptest.Server
	t *testing.T

	mu    sync.Mutex
	codes map[string]string
}

func newIDPServer(t *testing.T) *idpServer {
	idp := &idpServer{
		t:     t,
		codes: make(map[string]string),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/auth", idp.auth)
	mux.HandleFunc("/token", idp.token)
	idp.Server = httptest.NewServer(mux)
	return idp
}

func (idp *idpServer) auth(w http.ResponseWriter, req *http.Request) {
	log.Printf("IDP %s %s", req.Method, req.RequestURI)
	idp.mu.Lock()
	defer idp.mu.Unlock()
	req.ParseForm()
	for _, v := range []string{"response_type", "client_id", "scope", "redirect_uri", "state", "nonce"} {
		log.Printf("IDP [/auth] %s: %s", v, req.Form.Get(v))
	}
	code := fmt.Sprintf("CODE-%d", len(idp.codes))
	idp.codes[code] = req.Form.Get("nonce")

	url := req.Form.Get("redirect_uri") + "?" +
		"code=" + url.QueryEscape(code) +
		"&state=" + url.QueryEscape(req.Form.Get("state"))
	log.Printf("IDP [/auth] redirect to %s", url)
	http.Redirect(w, req, url, http.StatusFound)
}

func (idp *idpServer) token(w http.ResponseWriter, req *http.Request) {
	log.Printf("IDP %s %s", req.Method, req.RequestURI)
	idp.mu.Lock()
	defer idp.mu.Unlock()
	req.ParseForm()
	for _, v := range []string{"code", "client_id", "client_secret", "redirect_uri", "grant_type"} {
		log.Printf("IDP [/token] %s: %s", v, req.PostForm.Get(v))
	}
	nonce := idp.codes[req.Form.Get("code")]

	var data struct {
		IDToken string `json:"id_token"`
	}
	token := jwttest.MakeSampleToken(
		jwt.MapClaims{
			"email":          "john@example.net",
			"email_verified": true,
			"nonce":          nonce,
		},
		jwt.SigningMethodHS256,
		[]byte("key"),
	)
	data.IDToken = token
	log.Printf("IDP [/token] Return %+v", data)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(data); err != nil {
		idp.t.Errorf("token encode: %v", err)
	}
}
