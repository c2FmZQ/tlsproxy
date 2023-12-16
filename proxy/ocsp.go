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
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/c2FmZQ/storage"
	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/crypto/ocsp"
)

const (
	ocspCacheSize = 200
	ocspFile      = "ocsp-cache"
)

var (
	errOCSPRevoked  = errors.New("revoked cert")
	errOCSPUnknown  = errors.New("unknown cert")
	errOCSPProtocol = errors.New("protocol error")
	errOCSPInternal = errors.New("internal error")
)

func newOCSPCache(store *storage.Storage) *ocspCache {
	var empty []ocspCacheItem
	store.CreateEmptyFile(ocspFile, &empty)
	c, err := lru.New2Q[string, *ocsp.Response](ocspCacheSize)
	if err != nil {
		log.Panicf("newOCSPCache: %v", err)
	}
	cache := &ocspCache{
		store: store,
		cache: c,
	}
	cache.load()
	return cache
}

type ocspCache struct {
	store *storage.Storage
	cache *lru.TwoQueueCache[string, *ocsp.Response]
}

type ocspCacheItem struct {
	Key   string
	Value []byte
}

func (c *ocspCache) load() {
	var items []ocspCacheItem
	if err := c.store.ReadDataFile(ocspFile, &items); err != nil {
		log.Printf("ERR OCSP ReadDataFile: %v", err)
		return
	}
	now := time.Now()
	for _, item := range items {
		if resp, err := ocsp.ParseResponse(item.Value, nil); err == nil && now.Before(resp.NextUpdate) {
			c.cache.Add(item.Key, resp)
		}
	}
}

func (c *ocspCache) flushLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Minute):
			if err := c.flush(); err != nil {
				log.Printf("ERR OCSP flush: %v", err)
			}
		}
	}
}

func (c *ocspCache) flush() error {
	var items []ocspCacheItem
	now := time.Now()
	for _, k := range c.cache.Keys() {
		if v, ok := c.cache.Peek(k); ok {
			if now.After(v.NextUpdate) {
				continue
			}
			items = append(items, ocspCacheItem{
				Key:   k,
				Value: v.Raw,
			})
		}
	}
	return c.store.SaveDataFile(ocspFile, &items)
}

func (c *ocspCache) verifyChains(chains [][]*x509.Certificate) error {
	var lastError error
nextChain:
	for _, chain := range chains {
		for i, cert := range chain {
			if len(cert.OCSPServer) == 0 {
				continue
			}
			issuer := cert
			if i+1 < len(chain) {
				issuer = chain[i+1]
			}
			resp, err := c.getResponse(cert, issuer)
			if err == errOCSPInternal {
				continue
			}
			if err != nil {
				lastError = err
				continue nextChain
			}
			switch resp.Status {
			case ocsp.Revoked:
				log.Printf("BAD OCSP: %q is revoked", cert.Subject.String())
				lastError = errOCSPRevoked
				continue nextChain
			case ocsp.Unknown:
				log.Printf("BAD OCSP: %q is unknown", cert.Subject.String())
				lastError = errOCSPUnknown
				continue nextChain
			case ocsp.Good:
				log.Printf("INF OCSP: %q is GOOD", cert.Subject.String())
				lastError = nil
			default:
				log.Printf("BAD OCSP: %q has unexpected status %v", cert.Subject.String(), resp.Status)
				lastError = errOCSPProtocol
				continue nextChain
			}
		}
		// Every cert in the chain is good.
		break
	}
	return lastError
}

func certHash(b []byte) string {
	hash := sha256.Sum256(b)
	return hex.EncodeToString(hash[:])
}

func (c *ocspCache) getResponse(cert, issuer *x509.Certificate) (*ocsp.Response, error) {
	hash := certHash(cert.Raw)
	if resp, ok := c.cache.Get(hash); ok && time.Now().Before(resp.NextUpdate) {
		return resp, nil
	}
	resp, err := fetchOCSP(cert, issuer)
	if err == nil {
		c.cache.Add(hash, resp)
	}
	return resp, err
}

func fetchOCSP(cert, issuer *x509.Certificate) (*ocsp.Response, error) {
	ocspReq, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		log.Printf("ERR ocsp.CreateRequest: %v", err)
		return nil, errOCSPInternal
	}
	var ocspResp *ocsp.Response
	for _, server := range cert.OCSPServer {
		ocspResp, err = fetchOneOCSP(issuer, ocspReq, server)
		if err != nil || ocspResp.Status == ocsp.Unknown {
			continue
		}
		if err == nil {
			break
		}
	}
	return ocspResp, err
}

func fetchOneOCSP(issuer *x509.Certificate, ocspReq []byte, server string) (*ocsp.Response, error) {
	httpReq, err := http.NewRequest(http.MethodPost, server, bytes.NewReader(ocspReq))
	if err != nil {
		log.Printf("ERR http.NewRequest: %v", err)
		return nil, errOCSPInternal
	}
	httpReq.Header.Set("content-type", "application/ocsp-request")
	httpReq.Header.Set("accept", "application/ocsp-response")
	httpReq.Header.Set("user-agent", "tlsproxy")
	httpResp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		log.Printf("ERR %s: %v", server, err)
		return nil, errOCSPProtocol
	}
	defer httpResp.Body.Close()
	body, err := io.ReadAll(&io.LimitedReader{R: httpResp.Body, N: 4096})
	if err != nil {
		log.Printf("ERR body: %v", err)
		return nil, errOCSPProtocol
	}
	ocspResp, err := ocsp.ParseResponse(body, issuer)
	if err != nil {
		log.Printf("ERR ocsp.ParseResponse: %v", err)
		return nil, errOCSPProtocol
	}
	return ocspResp, nil
}
