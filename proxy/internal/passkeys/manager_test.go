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

package passkeys

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/c2FmZQ/storage"
	"github.com/c2FmZQ/storage/crypto"
	cbor "github.com/fxamacker/cbor/v2"

	"github.com/c2FmZQ/tlsproxy/proxy/internal/cookiemanager"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/idp"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/sid"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/tokenmanager"
)

func TestAssertionOptionsUnknownEmail(t *testing.T) {
	mk, err := crypto.CreateAESMasterKeyForTest()
	if err != nil {
		t.Fatalf("crypto.CreateAESMasterKeyForTest: %v", err)
	}
	store := storage.New(t.TempDir(), mk)
	tm, err := tokenmanager.New(store, nil, nil)
	if err != nil {
		t.Fatalf("tokenmanager.New: %v", err)
	}
	m, err := NewManager(Config{Store: store, TokenManager: tm})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	fakeID := func(email string) Bytes {
		t.Helper()
		opts, err := m.assertionOptions(email)
		if err != nil {
			t.Fatalf("assertionOptions: %v", err)
		}
		if len(opts.AllowCredentials) != 1 {
			t.Fatalf("AllowCredentials = %v", opts.AllowCredentials)
		}
		return opts.AllowCredentials[0].ID
	}

	id1 := fakeID("alice@example.com")
	if len(id1) != 32 {
		t.Errorf("len(id) = %d, want 32", len(id1))
	}
	if id2 := fakeID("alice@example.com"); !bytes.Equal(id1, id2) {
		t.Errorf("fake ID changed: %x != %x", id1, id2)
	}
	if id3 := fakeID("bob@example.com"); bytes.Equal(id1, id3) {
		t.Errorf("fake IDs are the same for different emails: %x", id1)
	}
}

type fakeIDP struct {
	loginRequested bool
}

func (f *fakeIDP) RequestLogin(w http.ResponseWriter, req *http.Request, origURL string, opts ...idp.Option) {
	f.loginRequested = true
	http.Redirect(w, req, "https://idp.example.com/login", http.StatusFound)
}

func (f *fakeIDP) HandleCallback(w http.ResponseWriter, req *http.Request) {}

type nopRecorder struct{}

func (nopRecorder) Record(string) {}

type nopLogger struct{}

func (nopLogger) Errorf(string, ...any) {}

func TestDuplicateCredentialIDAndRefreshIDLoop(t *testing.T) {
	mk, err := crypto.CreateAESMasterKeyForTest()
	if err != nil {
		t.Fatalf("crypto.CreateAESMasterKeyForTest: %v", err)
	}
	store := storage.New(t.TempDir(), mk)
	tm, err := tokenmanager.New(store, nil, nil)
	if err != nil {
		t.Fatalf("tokenmanager.New: %v", err)
	}
	cm := cookiemanager.New(tm, "passkey", "example.com", "https://example.com/", time.Hour, nil)
	otherCM := cookiemanager.New(tm, "other", "example.com", "https://example.com/", time.Hour, nil)
	otherIDP := &fakeIDP{}

	m, err := NewManager(Config{
		Store:              store,
		Other:              otherIDP,
		RefreshInterval:    10 * time.Minute,
		Endpoint:           "https://example.com/passkey",
		EventRecorder:      nopRecorder{},
		CookieManager:      cm,
		OtherCookieManager: otherCM,
		TokenManager:       tm,
		ACLMatcher:         func([]string, string) bool { return true },
		Logger:             nopLogger{},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	auth, err := NewFakeAuthenticator()
	if err != nil {
		t.Fatalf("NewFakeAuthenticator: %v", err)
	}
	auth.SetOrigin("https://example.com")

	// Overwrite passkeyFile with nil Handles/Subjects maps to simulate a zeroed DB on disk.
	m.db.Handles = nil
	m.db.Subjects = nil
	if err := store.SaveDataFile(passkeyFile, &m.db); err != nil {
		t.Fatalf("SaveDataFile(nil maps): %v", err)
	}

	aliceClaims := map[string]any{"email": "alice@example.com", "sub": "alice"}
	opts, err := m.attestationOptions(aliceClaims)
	if err != nil {
		t.Fatalf("attestationOptions: %v", err)
	}
	cdJSON, attObj, err := auth.Create(opts)
	if err != nil {
		t.Fatalf("auth.Create: %v", err)
	}
	jsArgs, _ := json.Marshal(map[string]any{
		"clientDataJSON":    Bytes(cdJSON),
		"attestationObject": Bytes(attObj),
	})
	if _, err := m.processAttestation(aliceClaims, "example.com", string(jsArgs), true); err != nil {
		t.Fatalf("processAttestation(1): %v", err)
	}

	// Registering the exact same credential ID again must be rejected.
	opts2, err := m.attestationOptions(aliceClaims)
	if err != nil {
		t.Fatalf("attestationOptions(2): %v", err)
	}
	var att attestation
	if err := cbor.Unmarshal(attObj, &att); err != nil {
		t.Fatalf("cbor.Unmarshal: %v", err)
	}
	cd2, _ := json.Marshal(clientData{
		Type:      "webauthn.create",
		Challenge: base64.RawURLEncoding.EncodeToString(opts2.Challenge),
		Origin:    "https://example.com",
	})
	jsArgs2, _ := json.Marshal(map[string]any{
		"clientDataJSON":    Bytes(cd2),
		"attestationObject": Bytes(attObj),
	})
	if _, err := m.processAttestation(aliceClaims, "example.com", string(jsArgs2), true); err == nil {
		t.Errorf("processAttestation allowed duplicate credential ID")
	}

	// RefreshID when OtherCookieManager has a valid token for a DIFFERENT user (bob@example.com)
	// must trigger Other.RequestLogin rather than looping.
	req := httptest.NewRequest(http.MethodGet, "https://example.com/passkey", nil)
	w := httptest.NewRecorder()
	sid.SetSessionID(w, req, "sid123")
	for _, c := range w.Result().Cookies() {
		req.AddCookie(c)
	}
	u, _ := url.Parse("https://example.com/dest")
	redirectTok, _, err := tm.URLToken(httptest.NewRecorder(), req, u, map[string]any{"email": "alice@example.com"})
	if err != nil {
		t.Fatalf("URLToken: %v", err)
	}
	w = httptest.NewRecorder()
	if err := otherCM.SetAuthTokenCookie(w, req, "bob", "bob@example.com", "sid123", "example.com", nil); err != nil {
		t.Fatalf("SetAuthTokenCookie: %v", err)
	}
	for _, c := range w.Result().Cookies() {
		req.AddCookie(c)
	}

	refreshReq := httptest.NewRequest(http.MethodGet, "https://example.com/passkey?get=RefreshID&email=alice@example.com&redirect="+url.QueryEscape(redirectTok), nil)
	for _, c := range req.Cookies() {
		refreshReq.AddCookie(c)
	}
	w = httptest.NewRecorder()
	m.HandleCallback(w, refreshReq)
	if !otherIDP.loginRequested {
		t.Errorf("HandleCallback(RefreshID) with mismatched user token did not request login from Other IdP")
	}
}
