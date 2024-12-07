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

package sshca

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/c2FmZQ/storage"
	"github.com/c2FmZQ/storage/crypto"
	"github.com/c2FmZQ/tpm"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/go-tpm-tools/simulator"
	"golang.org/x/crypto/ssh"
)

func newCA(t *testing.T, tpm *tpm.TPM) *SSHCA {
	dir := t.TempDir()
	mk, err := crypto.CreateAESMasterKeyForTest()
	if err != nil {
		t.Fatalf("crypto.CreateMasterKey: %v", err)
	}
	opts := Options{
		Name:                "sshca-test",
		PublicKeyEndpoint:   "https://ssh.example.com/ca",
		CertificateEndpoint: "https://ssh.example.com/cert",
		Store:               storage.New(dir, mk),
		TPM:                 tpm,
		ClaimsFromCtx: func(context.Context) jwt.MapClaims {
			return jwt.MapClaims{
				"email": "alice@example.com",
			}
		},
	}
	ca, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return ca
}

func TestNewSSHCA(t *testing.T) {
	ca := newCA(t, nil)
	if ca.db == nil {
		t.Fatal("ssh.example.com doesn't exist")
	}
	if ca.db.PrivateKey == nil {
		t.Fatal("ca key is not set")
	}
}

func TestCertificate(t *testing.T) {
	rwc, err := simulator.Get()
	if err != nil {
		t.Fatalf("simulator.Get: %v", err)
	}
	tpmSim, err := tpm.New(tpm.WithTPM(rwc))
	if err != nil {
		t.Fatalf("tpm.New: %v", err)
	}
	for _, tc := range []struct {
		name string
		tpm  *tpm.TPM
	}{
		{"Without TPM", nil},
		{"With TPM", tpmSim},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newCA(t, tc.tpm)
			mux := http.NewServeMux()
			mux.HandleFunc("/ca", m.ServePublicKey)
			mux.HandleFunc("/cert", m.ServeCertificate)
			server := httptest.NewServer(mux)
			defer server.Close()
			resp, err := http.Get(server.URL + "/ca")
			if err != nil {
				t.Fatalf("Get(/ca): %v", err)
			}
			defer resp.Body.Close()
			caKeyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("key body: %v", err)
			}
			caKey, _, _, _, err := ssh.ParseAuthorizedKey(caKeyBytes)
			if err != nil {
				t.Fatalf("ssh.ParseAuthorizedKey: %v", err)
			}

			pub, _, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("ed25519.GenerateKey: %v", err)
			}
			sshPub, err := ssh.NewPublicKey(pub)
			if err != nil {
				t.Fatalf("ssh.NewPublicKey: %v", err)
			}

			req, err := http.NewRequest("POST", server.URL+"/cert", bytes.NewReader(ssh.MarshalAuthorizedKey(sshPub)))
			if err != nil {
				t.Fatalf("http.NewRequest: %v", err)
			}
			req.Header.Set("x-csrf-check", "1")
			req.Header.Set("content-type", "text/plain")
			if resp, err = http.DefaultClient.Do(req); err != nil {
				t.Fatalf("Post(/cert): %v", err)
			}
			defer resp.Body.Close()
			certBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("cert body: %v", err)
			}

			c, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
			if err != nil {
				t.Fatalf("ssh.ParseAuthorizedKey: %v", err)
			}
			cert, ok := c.(*ssh.Certificate)
			if !ok {
				t.Fatalf("Parsed cert is %T", c)
			}

			if got, want := cert.SignatureKey.Marshal(), caKey.Marshal(); !bytes.Equal(got, want) {
				t.Fatalf("cert.SignatureKey doesn't match caKey")
			}
			if got, want := cert.Key.Marshal(), sshPub.Marshal(); !bytes.Equal(got, want) {
				t.Fatalf("cert.Key doesn't match sshKey")
			}
			if got, want := cert.KeyId, "alice@example.com"; got != want {
				t.Fatalf("cert.KeyId = %q, want %q", got, want)
			}
			if len(cert.ValidPrincipals) != 1 {
				t.Fatalf("cert.Principals = %v", cert.ValidPrincipals)
			}
			if got, want := cert.ValidPrincipals[0], "alice@example.com"; got != want {
				t.Fatalf("cert.ValidPrincipals[0] = %q, want %q", got, want)
			}
		})
	}
}
