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

	"github.com/c2FmZQ/storage"
	"github.com/c2FmZQ/storage/crypto"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/tokenmanager"
	jwt "github.com/golang-jwt/jwt/v5"
)

type jwks struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Type  string `json:"kty"`
	Use   string `json:"use"`
	ID    string `json:"kid"`
	Alg   string `json:"alg"`
	Curve string `json:"crv,omitempty"`
	X     string `json:"x,omitempty"`
	Y     string `json:"y,omitempty"`
}

func TestTrustedIssuers(t *testing.T) {
	// 1. Setup Mock JWKS Server
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}

	mockJWKS := jwks{
		Keys: []jwk{
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
	tm.SetTrustedIssuers([]struct{ Issuer, JWKSURI string }{
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
}
