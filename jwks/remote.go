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

package jwks

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-retryablehttp"
)

// Issuer contains the configuration for a trusted issuer.
type Issuer struct {
	// Issuer is the name of the issuer, usually a URL.
	Issuer string
	// JWKSURI is the URL of the JWKS endpoint.
	JWKSURI string
}

// Logger is the interface used for logging.
type Logger interface {
	Errorf(format string, args ...any)
}

type defaultLogger struct{}

func (defaultLogger) Errorf(format string, args ...any) {
	log.Printf(format, args...)
}

// Remote manages trusted issuers and their JWKS.
type Remote struct {
	client *retryablehttp.Client
	logger Logger

	mu             sync.Mutex
	trustedIssuers map[string]*trustedIssuer
}

type trustedIssuer struct {
	issuer     string
	jwksURI    string
	publicKeys map[string]crypto.PublicKey
	nextUpdate time.Time
	cancel     func()
}

// NewRemote returns a new Remote manager.
func NewRemote(client *retryablehttp.Client, logger Logger) *Remote {
	if logger == nil {
		logger = defaultLogger{}
	}
	if client == nil {
		client = retryablehttp.NewClient()
		client.Logger = nil
	}
	return &Remote{
		client:         client,
		logger:         logger,
		trustedIssuers: make(map[string]*trustedIssuer),
	}
}

// Stop removes all issuers and stops refreshing.
func (r *Remote) Stop() {
	r.SetIssuers(nil)
}

// SetIssuers updates the list of trusted issuers.
func (r *Remote) SetIssuers(issuers []Issuer) {
	r.mu.Lock()
	defer r.mu.Unlock()

	inUse := make(map[string]bool)
	for _, cfg := range issuers {
		inUse[cfg.Issuer] = true
		ti, exists := r.trustedIssuers[cfg.Issuer]
		if !exists {
			ctx, cancel := context.WithCancel(context.Background())
			ti = &trustedIssuer{
				issuer: cfg.Issuer,
				cancel: cancel,
			}
			r.trustedIssuers[cfg.Issuer] = ti
			go r.backgroundJWKSRefresh(ctx, ti)
		}
		// update mutable fields
		ti.jwksURI = cfg.JWKSURI
	}

	for k, ti := range r.trustedIssuers {
		if !inUse[k] {
			ti.cancel()
			delete(r.trustedIssuers, k)
		}
	}
}

// GetKey returns the public key for the given key ID (kid) if found in any of
// the trusted issuers.
func (r *Remote) GetKey(kid string) (crypto.PublicKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, ti := range r.trustedIssuers {
		if pk, ok := ti.publicKeys[kid]; ok {
			return pk, nil
		}
	}
	return nil, errors.New("not found")
}

// IssuerForKey returns the issuer URL for the given key ID (kid) if found.
func (r *Remote) IssuerForKey(kid string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, ti := range r.trustedIssuers {
		if _, ok := ti.publicKeys[kid]; ok {
			return ti.issuer, true
		}
	}
	return "", false
}

func (r *Remote) backgroundJWKSRefresh(ctx context.Context, ti *trustedIssuer) {
	for {
		if err := r.fetchJWKS(ctx, ti); err != nil {
			r.logger.Errorf("ERR fetchJWKS(%s): %v", ti.issuer, err)
			// Retry sooner on error
			r.mu.Lock()
			ti.nextUpdate = time.Now().Add(5 * time.Minute)
			r.mu.Unlock()
		}

		r.mu.Lock()
		nextUpdate := ti.nextUpdate
		r.mu.Unlock()

		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Until(nextUpdate)):
		}
	}
}

func (r *Remote) fetchJWKS(ctx context.Context, ti *trustedIssuer) error {
	r.mu.Lock()
	uri := ti.jwksURI
	r.mu.Unlock()

	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var keys JWKS
	if err := json.NewDecoder(&io.LimitedReader{R: resp.Body, N: 1048576}).Decode(&keys); err != nil {
		return err
	}
	publicKeys := make(map[string]crypto.PublicKey)
	for _, k := range keys.Keys {
		pk, err := k.PublicKey()
		if err != nil {
			r.logger.Errorf("ERR JWK %s: %v", k.ID, err)
			continue
		}
		publicKeys[k.ID] = pk
	}

	// Parse Cache-Control
	ttl := time.Hour
	if cc := resp.Header.Get("cache-control"); cc != "" {
		for _, part := range strings.Split(cc, ",") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "max-age=") {
				if v, err := strconv.Atoi(part[8:]); err == nil && v > 0 {
					ttl = time.Duration(v) * time.Second
				}
			}
		}
	}
	if age := resp.Header.Get("age"); age != "" {
		if v, err := strconv.Atoi(age); err == nil && v > 0 {
			ttl -= time.Duration(v) * time.Second
		}
	}
	if ttl < 5*time.Minute {
		ttl = 5 * time.Minute
	}

	r.mu.Lock()
	ti.publicKeys = publicKeys
	ti.nextUpdate = time.Now().Add(ttl)
	r.mu.Unlock()
	return nil
}
