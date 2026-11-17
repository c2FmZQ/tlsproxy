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
	"github.com/c2FmZQ/webauthn"
	cbor "github.com/fxamacker/cbor/v2"

	"github.com/c2FmZQ/tlsproxy/proxy/internal/cookiemanager"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/fromctx"
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

	fakeID := func(email string) webauthn.Bytes {
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
	lastOpts       idp.LoginOptions
}

func (f *fakeIDP) RequestLogin(w http.ResponseWriter, req *http.Request, origURL string, opts ...idp.Option) {
	f.loginRequested = true
	f.lastOpts = idp.ApplyOptions(opts)
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

	auth, err := webauthn.NewFakeAuthenticator()
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
		"clientDataJSON":    webauthn.Bytes(cdJSON),
		"attestationObject": webauthn.Bytes(attObj),
	})
	if _, err := m.processAttestation(aliceClaims, "example.com", string(jsArgs), true); err != nil {
		t.Fatalf("processAttestation(1): %v", err)
	}

	// Registering the exact same credential ID again must be rejected.
	opts2, err := m.attestationOptions(aliceClaims)
	if err != nil {
		t.Fatalf("attestationOptions(2): %v", err)
	}
	var att webauthn.Attestation
	if err := cbor.Unmarshal(attObj, &att); err != nil {
		t.Fatalf("cbor.Unmarshal: %v", err)
	}
	cd2, _ := json.Marshal(webauthn.ClientData{
		Type:      "webauthn.create",
		Challenge: base64.RawURLEncoding.EncodeToString(opts2.Challenge),
		Origin:    "https://example.com",
	})
	jsArgs2, _ := json.Marshal(map[string]any{
		"clientDataJSON":    webauthn.Bytes(cd2),
		"attestationObject": webauthn.Bytes(attObj),
	})
	if _, err := m.processAttestation(aliceClaims, "example.com", string(jsArgs2), true); err == nil {
		t.Errorf("processAttestation allowed duplicate credential ID")
	}

	// RefreshID when OtherCookieManager has a valid token for a DIFFERENT user (bob@example.com)
	// must trigger Other.RequestLogin for alice@example.com (even if redirectClaims had email=bob@example.com).
	req := httptest.NewRequest(http.MethodGet, "https://example.com/passkey", nil)
	w := httptest.NewRecorder()
	sid.SetSessionID(w, req, "sid123")
	for _, c := range w.Result().Cookies() {
		req.AddCookie(c)
	}
	u, _ := url.Parse("https://example.com/dest")
	redirectTok, _, err := tm.URLToken(httptest.NewRecorder(), req, u, map[string]any{"email": "bob@example.com", "depth": 1})
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
	if got := otherIDP.lastOpts.LoginHint(); got != "alice@example.com" {
		t.Errorf("Other.RequestLogin LoginHint = %q, want %q", got, "alice@example.com")
	}
	if got := otherIDP.lastOpts.Depth(); got != 2 {
		t.Errorf("Other.RequestLogin Depth = %d, want 2", got)
	}

	// Verify processAssertion succeeds when OtherCookieManager's token contains []any (e.g. "th"),
	// map[string]any, and "depth", and that "depth" is stripped from persisted user.Claims.
	reqWithTH := httptest.NewRequest(http.MethodGet, "https://example.com/passkey", nil)
	reqWithTH = reqWithTH.WithContext(fromctx.WithTokenHash(reqWithTH.Context(), "prev-token-hash"))
	w = httptest.NewRecorder()
	if err := otherCM.SetAuthTokenCookie(w, reqWithTH, "alice", "alice@example.com", "sid123", "example.com", map[string]any{
		"groups": []string{"admin", "users"},
		"meta":   map[string]any{"role": "owner"},
		"depth":  1,
	}); err != nil {
		t.Fatalf("SetAuthTokenCookie(alice with th): %v", err)
	}
	for _, c := range w.Result().Cookies() {
		reqWithTH.AddCookie(c)
	}
	aliceTok, _, err := otherCM.ValidateAuthTokenCookie(reqWithTH)
	if err != nil {
		t.Fatalf("ValidateAuthTokenCookie(alice): %v", err)
	}
	aso, err := m.assertionOptions("alice@example.com")
	if err != nil {
		t.Fatalf("assertionOptions(alice): %v", err)
	}
	id, cd, ad, sig, vh, err := auth.Get(aso)
	if err != nil {
		t.Fatalf("auth.Get: %v", err)
	}
	assertArgs, _ := json.Marshal(map[string]any{
		"id":                base64.RawURLEncoding.EncodeToString(id),
		"clientDataJSON":    webauthn.Bytes(cd),
		"authenticatorData": webauthn.Bytes(ad),
		"signature":         webauthn.Bytes(sig),
		"userHandle":        webauthn.Bytes(vh),
		"loginId":           "alice@example.com",
	})
	if _, err := m.processAssertion("example.com", string(assertArgs), aliceTok); err != nil {
		t.Fatalf("processAssertion with []any/map[string]any claims: %v", err)
	}
	reloadedDB := m.db
	reloadedDB.Handles = nil
	reloadedDB.Subjects = nil
	if err := store.ReadDataFile(passkeyFile, &reloadedDB); err != nil {
		t.Fatalf("ReadDataFile after processAssertion: %v", err)
	}
	aliceUser := reloadedDB.Handles[reloadedDB.Subjects["alice@example.com"]]
	if _, ok := aliceUser.Claims["th"].([]any); !ok {
		t.Errorf("reloadedDB Claims[th] = %T (%v), want []any", aliceUser.Claims["th"], aliceUser.Claims["th"])
	}
	if _, ok := aliceUser.Claims["depth"]; ok {
		t.Errorf("reloadedDB Claims[depth] = %v, want nil", aliceUser.Claims["depth"])
	}
}

func TestBackwardCompatibility(t *testing.T) {
	mk, err := crypto.CreateAESMasterKeyForTest()
	if err != nil {
		t.Fatalf("crypto.CreateAESMasterKeyForTest: %v", err)
	}
	store := storage.New(t.TempDir(), mk)
	tm, err := tokenmanager.New(store, nil, nil)
	if err != nil {
		t.Fatalf("tokenmanager.New: %v", err)
	}

	// Simulate a passkey database file written by the previous implementation
	// before switching to github.com/c2FmZQ/webauthn.
	type legacyBytes []byte
	type legacyUserKey struct {
		Name       string
		ID         legacyBytes
		PublicKey  legacyBytes
		RPIDHash   legacyBytes
		Transports []string
		CreatedAt  time.Time
		LastSeen   time.Time
		SignCount  uint32
	}
	type legacyUser struct {
		Handle legacyBytes
		Keys   []*legacyUserKey
		Claims map[string]any
	}
	var legacyDB struct {
		Handles  map[string]*legacyUser
		Subjects map[string]string
	}

	auth, err := webauthn.NewFakeAuthenticator()
	if err != nil {
		t.Fatalf("NewFakeAuthenticator: %v", err)
	}
	auth.SetOrigin("https://example.com")

	userHandle := []byte("legacy-alice-handle-0123456789ab")
	userHandleStr := base64.RawURLEncoding.EncodeToString(userHandle)
	legacyDB.Handles = map[string]*legacyUser{
		userHandleStr: {
			Handle: legacyBytes(userHandle),
			Claims: map[string]any{
				"email": "alice@example.com",
				"sub":   "alice-sub",
				"sid":   "alice-sid",
			},
		},
	}
	legacyDB.Subjects = map[string]string{
		"alice@example.com": userHandleStr,
	}

	// Create legacy ES256 and RS256 keys via FakeAuthenticator and store them in legacyDB.
	for _, alg := range []int{webauthn.AlgES256, webauthn.AlgRS256} {
		opts, err := webauthn.NewAttestationOptions()
		if err != nil {
			t.Fatalf("NewAttestationOptions: %v", err)
		}
		opts.RelyingParty.ID = "example.com"
		opts.User.ID = userHandle
		opts.PubKeyCredParams = []webauthn.PubKeyCredParam{{Type: "public-key", Alg: alg}}
		_, attObj, err := auth.Create(opts)
		if err != nil {
			t.Fatalf("auth.Create(%d): %v", alg, err)
		}
		ao, err := webauthn.ParseAttestationObject(attObj)
		if err != nil {
			t.Fatalf("ParseAttestationObject(%d): %v", alg, err)
		}
		creds := ao.AuthData.AttestedCredentials
		legacyDB.Handles[userHandleStr].Keys = append(legacyDB.Handles[userHandleStr].Keys, &legacyUserKey{
			ID:         legacyBytes(creds.ID),
			PublicKey:  legacyBytes(creds.COSEKey),
			RPIDHash:   legacyBytes(ao.AuthData.RPIDHash),
			Transports: []string{"internal"},
			CreatedAt:  time.Now().Add(-time.Hour).UTC(),
			LastSeen:   time.Now().Add(-time.Hour).UTC(),
			SignCount:  ao.AuthData.SignCount,
		})
	}

	store.CreateEmptyFile(passkeyFile, &legacyDB)
	if err := store.SaveDataFile(passkeyFile, &legacyDB); err != nil {
		t.Fatalf("SaveDataFile(legacyDB): %v", err)
	}

	// Open with the new Manager and verify all legacy keys load and work.
	m, err := NewManager(Config{
		Store:         store,
		Endpoint:      "https://example.com/passkey",
		EventRecorder: nopRecorder{},
		TokenManager:  tm,
		Logger:        nopLogger{},
	})
	if err != nil {
		t.Fatalf("NewManager with legacy DB: %v", err)
	}
	if !m.subjectIsRegistered("alice@example.com") {
		t.Fatalf("subjectIsRegistered(alice@example.com) = false, want true")
	}
	if got := len(m.keys("alice@example.com")); got != 2 {
		t.Fatalf("len(m.keys) = %d, want 2", got)
	}

	// Authenticate using the legacy keys sending JSON number arrays (like webauthn.js does).
	toIntSlice := func(b []byte) []int {
		out := make([]int, len(b))
		for i, v := range b {
			out[i] = int(v)
		}
		return out
	}

	for i, key := range m.db.Handles[userHandleStr].Keys {
		aso, err := m.assertionOptions("alice@example.com")
		if err != nil {
			t.Fatalf("assertionOptions(%d): %v", i, err)
		}
		if len(aso.AllowCredentials) != 2 {
			t.Fatalf("AllowCredentials len = %d, want 2", len(aso.AllowCredentials))
		}
		// Restrict AllowCredentials to test each legacy key individually.
		asoSingle := *aso
		asoSingle.AllowCredentials = []webauthn.CredentialID{{Type: "public-key", ID: key.ID}}
		id, cd, ad, sig, vh, err := auth.Get(&asoSingle)
		if err != nil {
			t.Fatalf("auth.Get(%d): %v", i, err)
		}
		assertArgs, err := json.Marshal(map[string]any{
			"id":                base64.RawURLEncoding.EncodeToString(id),
			"clientDataJSON":    toIntSlice(cd),
			"authenticatorData": toIntSlice(ad),
			"signature":         toIntSlice(sig),
			"userHandle":        toIntSlice(vh),
			"loginId":           "alice@example.com",
		})
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		claims, err := m.processAssertion("example.com", string(assertArgs), nil)
		if err != nil {
			t.Fatalf("processAssertion(legacy key %d): %v", i, err)
		}
		if claims["email"] != "alice@example.com" {
			t.Errorf("claims[email] = %v, want alice@example.com", claims["email"])
		}
	}

	// Also verify registering a new Ed25519 (AlgEdDSA) passkey for the legacy user
	// with webauthn.js byte-array args, and then authenticating with it.
	aliceClaims := m.db.Handles[userHandleStr].Claims
	attOpts, err := m.attestationOptions(aliceClaims)
	if err != nil {
		t.Fatalf("attestationOptions: %v", err)
	}
	if len(attOpts.ExcludeCredentials) != 2 {
		t.Fatalf("ExcludeCredentials len = %d, want 2", len(attOpts.ExcludeCredentials))
	}
	edOpts := *attOpts
	edOpts.PubKeyCredParams = []webauthn.PubKeyCredParam{{Type: "public-key", Alg: webauthn.AlgEdDSA}}
	cdJSON, attObj, err := auth.Create(&edOpts)
	if err != nil {
		t.Fatalf("auth.Create(EdDSA): %v", err)
	}
	regArgs, _ := json.Marshal(map[string]any{
		"clientDataJSON":    toIntSlice(cdJSON),
		"attestationObject": toIntSlice(attObj),
		"transports":        []string{"hybrid"},
	})
	if _, err := m.processAttestation(aliceClaims, "example.com", string(regArgs), true); err != nil {
		t.Fatalf("processAttestation(EdDSA): %v", err)
	}
	if got := len(m.keys("alice@example.com")); got != 3 {
		t.Fatalf("len(m.keys) after EdDSA registration = %d, want 3", got)
	}
}
