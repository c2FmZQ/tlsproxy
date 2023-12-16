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
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"strings"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// RevokeAllCertificates revokes all the certificates in the cache.
func (p *Proxy) RevokeAllCertificates(ctx context.Context, reason string) (retErr error) {
	const accountKeyKey = "acme_account+key"

	revocationReason, err := parseRevocationReason(reason)
	if err != nil {
		return err
	}
	var cache struct {
		Entries map[string]string `json:"entries"`
	}
	commit, err := p.store.OpenForUpdate("autocert", &cache)
	if err != nil {
		return err
	}
	defer commit(false, &retErr)

	b64AccountKey, ok := cache.Entries[accountKeyKey]
	if !ok {
		return errors.New("no account key")
	}
	pemAccountKey, err := base64.StdEncoding.DecodeString(b64AccountKey)
	if err != nil {
		return fmt.Errorf("invalid account key: %w", err)
	}
	derAccountKey, _ := pem.Decode(pemAccountKey)
	if derAccountKey == nil {
		return errors.New("invalid account key")
	}
	accountKey, err := parsePrivateKey(derAccountKey.Bytes)
	if err != nil {
		return fmt.Errorf("invalid account key: %w", err)
	}

	client := &acme.Client{
		DirectoryURL: autocert.DefaultACMEDirectory,
		Key:          accountKey,
		UserAgent:    "tlsproxy",
	}
L:
	for k, v := range cache.Entries {
		if k == accountKeyKey {
			continue
		}
		data, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			log.Printf("ERR %s: %v", k, err)
			continue
		}
		var privKey crypto.Signer
		var certs [][]byte
		for {
			var b *pem.Block
			if b, data = pem.Decode(data); b == nil {
				break
			}
			if strings.Contains(b.Type, "PRIVATE KEY") {
				var err error
				if privKey, err = parsePrivateKey(b.Bytes); err != nil {
					log.Printf("ERR %s: %v", k, err)
					continue L
				}
			}
			if b.Type == "CERTIFICATE" {
				certs = append(certs, b.Bytes)
			}
		}
		if privKey == nil {
			log.Printf("ERR %s: missing private key", k)
			continue
		}
		if len(certs) == 0 {
			log.Printf("ERR %s: missing cert", k)
			continue
		}
		if err := client.RevokeCert(ctx, privKey, certs[0], revocationReason); err != nil {
			log.Printf("ERR %s: %v", k, err)
			continue
		}
		delete(cache.Entries, k)
	}
	return commit(true, nil)
}

func parseRevocationReason(reason string) (acme.CRLReasonCode, error) {
	switch reason {
	case "unspecified":
		return acme.CRLReasonUnspecified, nil
	case "keyCompromise":
		return acme.CRLReasonUnspecified, nil
	case "superseded":
		return acme.CRLReasonUnspecified, nil
	case "cessationOfOperation":
		return acme.CRLReasonUnspecified, nil
	default:
		return acme.CRLReasonUnspecified, errors.New("invalid revocation reason")
	}
}

func parsePrivateKey(b []byte) (crypto.Signer, error) {
	var privKey any
	var err error
	privKey, err = x509.ParsePKCS8PrivateKey(b)
	if err != nil {
		privKey, err = x509.ParseECPrivateKey(b)
	}
	if err != nil {
		privKey, err = x509.ParsePKCS1PrivateKey(b)
	}
	if key, ok := privKey.(crypto.Signer); ok {
		return key, nil
	}
	return nil, errors.New("invalid private key")
}
