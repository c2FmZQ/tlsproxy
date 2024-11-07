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
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/c2FmZQ/storage/autocertcache"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

const acmeAccountKey = "acme_account+key"

// RevokeAllCertificates revokes all the certificates in the cache.
func (p *Proxy) RevokeAllCertificates(ctx context.Context, reason string) error {
	reasonCode, err := parseRevocationReason(reason)
	if err != nil {
		return err
	}
	certs, err := p.acmeAllCerts(ctx)
	if err != nil {
		return err
	}
	var toRevoke []string
	for k := range certs {
		toRevoke = append(toRevoke, k)
	}
	sort.Strings(toRevoke)

	if len(toRevoke) == 0 {
		return nil
	}

	accountKey, err := p.acmeAccountKey(ctx)
	if err != nil {
		return err
	}
	client := &acme.Client{
		DirectoryURL: autocert.DefaultACMEDirectory,
		Key:          accountKey,
		UserAgent:    "tlsproxy",
	}
	p.logErrorF("!!!")
	p.logErrorF("!!! WARNING")
	p.logErrorF("!!!")
	if n := len(toRevoke); n == 1 {
		p.logErrorF("!!! About to REVOKE 1 certificate:")
	} else {
		p.logErrorF("!!! About to REVOKE %d certificates:", n)
	}
	p.logErrorF("!!!")
	for _, key := range toRevoke {
		p.logErrorF("!!!   %s", key)
	}
	p.logErrorF("!!!")
	p.logErrorF("!!! Press CTRL-C now to abort.")
	p.logErrorF("!!!")
	time.Sleep(10 * time.Second)

	now := time.Now()
	for _, key := range toRevoke {
		if now.After(certs[key].Leaf.NotAfter) {
			p.logErrorF("!!! Expired: %s", key)
			continue
		}
		if err := client.RevokeCert(ctx, certs[key].PrivateKey.(crypto.Signer), certs[key].Certificate[0], reasonCode); err != nil {
			return err
		}
		p.logErrorF("!!! Revoked: %s", key)
	}
	return p.certManager.(*autocert.Manager).Cache.(*autocertcache.Cache).DeleteKeys(ctx, toRevoke)
}

func (p *Proxy) revokeUnusedCertificates(ctx context.Context) error {
	actuallyRevoke := p.cfg.RevokeUnusedCertificates == nil || *p.cfg.RevokeUnusedCertificates

	names := make(map[string]bool)
	p.mu.Lock()
	for _, be := range p.cfg.Backends {
		for _, n := range be.ServerNames {
			names[n] = true
		}
	}
	p.mu.Unlock()
	certs, err := p.acmeAllCerts(ctx)
	if err != nil {
		return err
	}
	var toRevoke []string
L:
	for k, cert := range certs {
		for _, n := range cert.Leaf.DNSNames {
			if names[n] {
				continue L
			}
		}
		if len(cert.Leaf.DNSNames) > 0 {
			n := idnaToUnicode(cert.Leaf.DNSNames[0])
			p.logErrorF("INF Unused certificate: %s (%s)", n, k)
			toRevoke = append(toRevoke, k)
		}
	}
	sort.Strings(toRevoke)

	if !actuallyRevoke {
		if len(toRevoke) > 0 {
			p.logErrorF("INF Set \"revokeUnusedCertificates: true\" to automatically revoke unused certificates")
		}
		return nil
	}

	accountKey, err := p.acmeAccountKey(ctx)
	if err != nil {
		return err
	}
	client := &acme.Client{
		DirectoryURL: autocert.DefaultACMEDirectory,
		Key:          accountKey,
		UserAgent:    "tlsproxy",
	}
	now := time.Now()
	for _, key := range toRevoke {
		if now.After(certs[key].Leaf.NotAfter) {
			p.logErrorF("INF Expired certificate: %s", key)
			continue
		}
		if err := client.RevokeCert(ctx, certs[key].PrivateKey.(crypto.Signer), certs[key].Certificate[0], acme.CRLReasonUnspecified); err != nil {
			return err
		}
		p.logErrorF("INF Revoked unused certificate: %s", key)
	}
	return p.certManager.(*autocert.Manager).Cache.(*autocertcache.Cache).DeleteKeys(ctx, toRevoke)
}

func (p *Proxy) acmeAccountKey(ctx context.Context) (crypto.Signer, error) {
	m, ok := p.certManager.(*autocert.Manager)
	if !ok {
		return nil, fmt.Errorf("not implemented with %T", p.certManager)
	}
	cache, ok := m.Cache.(*autocertcache.Cache)
	if !ok {
		return nil, fmt.Errorf("not implemented with %T", m.Cache)
	}
	pemAccountKey, err := cache.Get(ctx, acmeAccountKey)
	if err != nil {
		return nil, fmt.Errorf("invalid account key: %w", err)
	}
	derAccountKey, _ := pem.Decode(pemAccountKey)
	if derAccountKey == nil {
		return nil, errors.New("invalid account key")
	}
	accountKey, err := parsePrivateKey(derAccountKey.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid account key: %w", err)
	}
	return accountKey, nil
}

func (p *Proxy) acmeAllCerts(ctx context.Context) (map[string]*tls.Certificate, error) {
	m, ok := p.certManager.(*autocert.Manager)
	if !ok {
		return nil, fmt.Errorf("not implemented with %T", p.certManager)
	}
	cache, ok := m.Cache.(*autocertcache.Cache)
	if !ok {
		return nil, fmt.Errorf("not implemented with %T", m.Cache)
	}
	keys, err := cache.Keys(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]*tls.Certificate)
L:
	for _, k := range keys {
		if k == acmeAccountKey {
			continue
		}
		data, err := cache.Get(ctx, k)
		if err != nil {
			p.logErrorF("ERR %s: %v", k, err)
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
					p.logErrorF("ERR %s: %v", k, err)
					continue L
				}
			}
			if b.Type == "CERTIFICATE" {
				certs = append(certs, b.Bytes)
			}
		}
		if privKey == nil {
			p.logErrorF("ERR %s: missing private key", k)
			continue
		}
		if len(certs) == 0 {
			p.logErrorF("ERR %s: missing cert", k)
			continue
		}
		leaf, err := x509.ParseCertificate(certs[0])
		if err != nil {
			p.logErrorF("ERR %s: %s", k, err)
			continue
		}
		out[k] = &tls.Certificate{
			Certificate: certs,
			PrivateKey:  privKey,
			Leaf:        leaf,
		}
	}
	return out, nil
}

func parseRevocationReason(reason string) (acme.CRLReasonCode, error) {
	switch reason {
	case "unspecified":
		return acme.CRLReasonUnspecified, nil
	case "keyCompromise":
		return acme.CRLReasonKeyCompromise, nil
	case "superseded":
		return acme.CRLReasonSuperseded, nil
	case "cessationOfOperation":
		return acme.CRLReasonCessationOfOperation, nil
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
