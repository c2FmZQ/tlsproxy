package cookiemanager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"

	"github.com/c2FmZQ/storage"
	"github.com/c2FmZQ/storage/crypto"
	"github.com/c2FmZQ/tlsproxy/jwks"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/tokenmanager"
)

func TestTrustedIssuers(t *testing.T) {
	// 1. Setup Mock JWKS Server
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}

	mockJWKS := jwks.JWKS{
		Keys: []jwks.JWK{
			{
				Type:  "EC",
				Use:   "sig",
				ID:    "test-kid-1",
				Alg:   "ES256",
				Curve: "P-256",
				X:     base64.RawURLEncoding.EncodeToString(privKey.X.Bytes()),
				Y:     base64.RawURLEncoding.EncodeToString(privKey.Y.Bytes()),
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=3600")
		json.NewEncoder(w).Encode(mockJWKS)
	}))
	defer server.Close()

	// 2. Setup TokenManager
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

	trustedIssuer := "https://trusted.example.com"
	tm.SetTrustedIssuers([]jwks.Issuer{
		{
			Issuer:  trustedIssuer,
			JWKSURI: server.URL,
		},
	})

	// Wait for background refresh
	time.Sleep(100 * time.Millisecond)

	// 3. Setup CookieManager with Trusted Issuer
	cm := New(tm, "idp", "example.com", "https://idp.example.com", 0, []string{trustedIssuer})

	// 4. Test Token Validation

	// Case A: Valid Token from Trusted Issuer
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss":       trustedIssuer,
		"aud":       trustedIssuer,
		"sub":       "user123",
		"exp":       time.Now().Add(time.Hour).Unix(),
		"proxyauth": trustedIssuer,
	})
	token.Header["kid"] = "test-kid-1"
	signedToken, err := token.SignedString(privKey)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}

	req, _ := http.NewRequest("GET", "https://example.com", nil)
	req.AddCookie(&http.Cookie{
		Name:  tlsProxyAuthCookie,
		Value: signedToken,
	})

	tok, _, err := cm.ValidateAuthTokenCookie(req)
	if err != nil {
		t.Errorf("ValidateAuthTokenCookie(valid trusted): %v", err)
	}
	if tok == nil || !tok.Valid {
		t.Error("ValidateAuthTokenCookie(valid trusted): returned invalid token")
	}

	// Case B: Untrusted Issuer (not in CM's list)
	cmUntrusted := New(tm, "idp", "example.com", "https://idp.example.com", 0, nil)
	tok, _, err = cmUntrusted.ValidateAuthTokenCookie(req)
	if err == nil {
		t.Error("ValidateAuthTokenCookie(untrusted issuer): expected error, got nil")
	} else if err.Error() != `issuer "https://trusted.example.com" is not trusted` {
		t.Errorf("ValidateAuthTokenCookie(untrusted issuer): expected specific error, got %q", err)
	}

	// Case C: Trusted Issuer, Wrong Audience
	tokenWrongAud := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss":       trustedIssuer,
		"aud":       "https://wrong.com",
		"sub":       "user123",
		"exp":       time.Now().Add(time.Hour).Unix(),
		"proxyauth": trustedIssuer,
	})
	tokenWrongAud.Header["kid"] = "test-kid-1"
	signedTokenWrongAud, _ := tokenWrongAud.SignedString(privKey)

	reqWrongAud, _ := http.NewRequest("GET", "https://example.com", nil)
	reqWrongAud.AddCookie(&http.Cookie{
		Name:  tlsProxyAuthCookie,
		Value: signedTokenWrongAud,
	})

	_, _, err = cm.ValidateAuthTokenCookie(reqWrongAud)
	if err == nil {
		t.Error("ValidateAuthTokenCookie(wrong aud): expected error, got nil")
	}

	// Case D: Trusted Issuer, Wrong ProxyAuth
	tokenWrongProxyAuth := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss":       trustedIssuer,
		"aud":       trustedIssuer,
		"sub":       "user123",
		"exp":       time.Now().Add(time.Hour).Unix(),
		"proxyauth": "https://evil.com",
	})
	tokenWrongProxyAuth.Header["kid"] = "test-kid-1"
	signedTokenWrongProxyAuth, _ := tokenWrongProxyAuth.SignedString(privKey)

	reqWrongProxyAuth, _ := http.NewRequest("GET", "https://example.com", nil)
	reqWrongProxyAuth.AddCookie(&http.Cookie{
		Name:  tlsProxyAuthCookie,
		Value: signedTokenWrongProxyAuth,
	})

	_, _, err = cm.ValidateAuthTokenCookie(reqWrongProxyAuth)
	if err == nil {
		t.Error("ValidateAuthTokenCookie(wrong proxyauth): expected error, got nil")
	}

	// Case E: Trusted Issuer's key, local issuer claim, as bearer token
	tokenLocalIss := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss":   "https://idp.example.com",
		"aud":   "https://example.com/",
		"sub":   "user123",
		"email": "admin@example.com",
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	tokenLocalIss.Header["kid"] = "test-kid-1"
	signedTokenLocalIss, _ := tokenLocalIss.SignedString(privKey)

	reqBearer, _ := http.NewRequest("GET", "https://example.com", nil)
	reqBearer.Header.Set("Authorization", "Bearer "+signedTokenLocalIss)
	if _, err := cm.ValidateAuthorizationHeader(reqBearer); err == nil {
		t.Error("ValidateAuthorizationHeader(trusted key, local iss): expected error, got nil")
	}

	// Case F: Local key, bearer token with and without exp
	localClaims := jwt.MapClaims{
		"iss": "https://idp.example.com",
		"aud": "https://example.com/",
		"sub": "user123",
	}
	signedNoExp, err := tm.CreateToken(localClaims, "")
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	reqBearer.Header.Set("Authorization", "Bearer "+signedNoExp)
	if _, err := cm.ValidateAuthorizationHeader(reqBearer); err == nil {
		t.Error("ValidateAuthorizationHeader(no exp): expected error, got nil")
	}
	localClaims["exp"] = time.Now().Add(time.Hour).Unix()
	signedWithExp, err := tm.CreateToken(localClaims, "")
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	reqBearer.Header.Set("Authorization", "Bearer "+signedWithExp)
	if _, err := cm.ValidateAuthorizationHeader(reqBearer); err != nil {
		t.Errorf("ValidateAuthorizationHeader(local key, exp): %v", err)
	}
}

func TestTrustedIssuersKidCollision(t *testing.T) {
	privKeyA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	privKeyB, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}

	makeJWKSServer := func(priv *ecdsa.PrivateKey, kid string) *httptest.Server {
		ks := jwks.JWKS{
			Keys: []jwks.JWK{{
				Type:  "EC",
				Use:   "sig",
				ID:    kid,
				Alg:   "ES256",
				Curve: "P-256",
				X:     base64.RawURLEncoding.EncodeToString(priv.X.Bytes()),
				Y:     base64.RawURLEncoding.EncodeToString(priv.Y.Bytes()),
			}},
		}
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "max-age=3600")
			json.NewEncoder(w).Encode(ks)
		}))
	}

	serverA := makeJWKSServer(privKeyA, "shared-kid")
	defer serverA.Close()
	serverB := makeJWKSServer(privKeyB, "shared-kid")
	defer serverB.Close()

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

	issuerA := "https://issuer-a.example.com/"
	issuerB := "https://issuer-b.example.com/"
	localJWKS := httptest.NewServer(http.HandlerFunc(tm.ServeJWKS))
	defer localJWKS.Close()
	issuerLocalOther := "https://other-local.example.com/"

	tm.SetTrustedIssuers([]jwks.Issuer{
		{Issuer: issuerA, JWKSURI: serverA.URL},
		{Issuer: issuerB, JWKSURI: serverB.URL},
		{Issuer: issuerLocalOther, JWKSURI: localJWKS.URL},
	})
	time.Sleep(100 * time.Millisecond)

	// cmA only trusts issuerA and issuerLocalOther, NOT issuerB.
	cmA := New(tm, "idp-a", "a.example.com", "https://a.example.com/", 0, []string{issuerA, issuerLocalOther})

	// 1. Token signed by issuerB's key claiming to be from issuerA MUST ALWAYS fail.
	forgedByB := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss":       issuerA,
		"aud":       issuerA,
		"sub":       "admin",
		"email":     "admin@example.com",
		"exp":       time.Now().Add(time.Hour).Unix(),
		"proxyauth": issuerA,
	})
	forgedByB.Header["kid"] = "shared-kid"
	signedForged, err := forgedByB.SignedString(privKeyB)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	reqForged, _ := http.NewRequest("GET", "https://a.example.com/", nil)
	reqForged.AddCookie(&http.Cookie{Name: tlsProxyAuthCookie, Value: signedForged})

	// 2. Valid token signed by issuerA's key MUST ALWAYS succeed.
	validFromA := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss":       issuerA,
		"aud":       issuerA,
		"sub":       "user1",
		"email":     "user1@example.com",
		"exp":       time.Now().Add(time.Hour).Unix(),
		"proxyauth": issuerA,
	})
	validFromA.Header["kid"] = "shared-kid"
	signedValidA, err := validFromA.SignedString(privKeyA)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	reqValidA, _ := http.NewRequest("GET", "https://a.example.com/", nil)
	reqValidA.AddCookie(&http.Cookie{Name: tlsProxyAuthCookie, Value: signedValidA})

	for i := range 50 {
		if _, _, err := cmA.ValidateAuthTokenCookie(reqForged); err == nil {
			t.Fatalf("iteration %d: forged token signed by issuerB was accepted as issuerA", i)
		}
		if _, _, err := cmA.ValidateAuthTokenCookie(reqValidA); err != nil {
			t.Fatalf("iteration %d: valid token from issuerA was rejected: %v", i, err)
		}
	}

	// 3. Token issued by another CookieManager on the same TokenManager instance (issuerLocalOther)
	// and trusted via TrustedIssuers MUST succeed.
	cmOther := New(tm, "idp-other", "other.example.com", issuerLocalOther, 0, nil)
	wOther := httptest.NewRecorder()
	reqOther, _ := http.NewRequest("GET", issuerLocalOther, nil)
	if err := cmOther.SetAuthTokenCookie(wOther, reqOther, "user2", "user2@example.com", "sid2", "other.example.com", nil); err != nil {
		t.Fatalf("SetAuthTokenCookie: %v", err)
	}
	reqCrossLocal, _ := http.NewRequest("GET", "https://a.example.com/", nil)
	for _, c := range wOther.Result().Cookies() {
		reqCrossLocal.AddCookie(c)
	}
	if _, _, err := cmA.ValidateAuthTokenCookie(reqCrossLocal); err != nil {
		t.Fatalf("ValidateAuthTokenCookie(same-instance trusted issuer): %v", err)
	}
}
