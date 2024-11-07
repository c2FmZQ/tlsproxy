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

package tokenmanager

import (
	"testing"
	"time"

	"github.com/c2FmZQ/storage"
	"github.com/c2FmZQ/storage/crypto"
	"github.com/c2FmZQ/tpm"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/go-tpm-tools/simulator"
)

func TestTokenManager(t *testing.T) {
	rwc, err := simulator.Get()
	if err != nil {
		panic(err)
	}
	tpmSim, err := tpm.New(tpm.WithTPM(rwc))
	if err != nil {
		panic(err)
	}
	defer tpmSim.Close()

	for _, tc := range []struct {
		name string
		tpm  *tpm.TPM
	}{
		{"Without TPM", nil},
		{"With TPM", tpmSim},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			mk, err := crypto.CreateAESMasterKeyForTest()
			if err != nil {
				t.Fatalf("crypto.CreateMasterKey: %v", err)
			}
			store := storage.New(dir, mk)
			tm1, err := New(store, tc.tpm, nil)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			tok, err := tm1.CreateToken(jwt.MapClaims{
				"iat": time.Now().Unix(),
				"exp": time.Now().Add(5 * time.Minute).Unix(),
				"sub": "test@example.com",
				"iss": "https://login.example.com",
				"aud": "https://login.example.com",
			}, "ES256")
			if err != nil {
				t.Fatalf("tm.CreateToken: %v", err)
			}
			t.Logf("TOKEN: %s", tok)

			tm2, err := New(store, tc.tpm, nil)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			for _, tm := range []*TokenManager{tm1, tm2} {
				if _, err := tm.ValidateToken(tok,
					jwt.WithAudience("https://login.example.com"),
					jwt.WithIssuer("https://login.example.com"),
					jwt.WithSubject("test@example.com"),
				); err != nil {
					t.Fatalf("tm.ValidateToken: %v", err)
				}
			}

			tok2, err := tm1.CreateToken(jwt.MapClaims{
				"iat": time.Now().Add(-10 * time.Minute).Unix(),
				"exp": time.Now().Add(5 * time.Minute).Unix(),
				"sub": "test@example.com",
				"iss": "https://login.example.com",
				"aud": "https://login.example.com",
			}, "RS256")
			if err != nil {
				t.Fatalf("tm.CreateToken: %v", err)
			}
			t.Logf("TOKEN2: %s", tok2)
			if _, err := tm1.ValidateToken(tok2); err != nil {
				t.Fatalf("tm.ValidateToken: %v", err)
			}

			if tc.tpm != nil {
				return
			}
			tok3, err := tm1.CreateToken(jwt.MapClaims{
				"iat": time.Now().Add(-10 * time.Minute).Unix(),
				"exp": time.Now().Add(5 * time.Minute).Unix(),
				"sub": "test@example.com",
				"iss": "https://login.example.com",
				"aud": "https://login.example.com",
			}, "EdDSA")
			if err != nil {
				t.Fatalf("tm.CreateToken: %v", err)
			}
			t.Logf("TOKEN3: %s", tok3)
			if _, err := tm1.ValidateToken(tok3); err != nil {
				t.Fatalf("tm.ValidateToken: %v", err)
			}
		})
	}
}
