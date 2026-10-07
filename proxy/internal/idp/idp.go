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

package idp

import "time"

type LoginOptions struct {
	loginHint     string
	selectAccount bool
	depth         int
}

func (o LoginOptions) LoginHint() string {
	return o.loginHint
}

func (o LoginOptions) SelectAccount() bool {
	return o.selectAccount
}

func (o LoginOptions) Depth() int {
	return o.depth
}

type Option func(*LoginOptions)

func WithLoginHint(v string) Option {
	return func(o *LoginOptions) {
		o.loginHint = v
	}
}

func WithSelectAccount(v bool) Option {
	return func(o *LoginOptions) {
		o.selectAccount = v
	}
}

func WithDepth(v int) Option {
	return func(o *LoginOptions) {
		o.depth = v
	}
}

func ApplyOptions(opts []Option) LoginOptions {
	var lo LoginOptions
	for _, opt := range opts {
		opt(&lo)
	}
	return lo
}

const (
	// MaxPendingLogins is the maximum number of pending login requests
	// that an identity provider keeps track of.
	MaxPendingLogins = 50000
	// MaxOriginalURLLength is the maximum length of the URL that users
	// are sent back to after logging in.
	MaxOriginalURLLength = 4096
	// pruneInterval is how often pending login requests are pruned.
	pruneInterval = 30 * time.Second
)

// PendingLogins keeps track of pending login requests, with a limited lifetime
// and size. It is not safe for concurrent use.
type PendingLogins[V any] struct {
	ttl       time.Duration
	created   func(V) time.Time
	m         map[string]V
	lastPrune time.Time
}

// NewPendingLogins returns a new PendingLogins. Entries expire ttl after the
// time returned by created.
func NewPendingLogins[V any](ttl time.Duration, created func(V) time.Time) *PendingLogins[V] {
	return &PendingLogins[V]{
		ttl:     ttl,
		created: created,
		m:       make(map[string]V),
	}
}

func (p *PendingLogins[V]) expired(v V) bool {
	return time.Since(p.created(v)) > p.ttl
}

// Add adds a new entry. It returns false if there are too many pending
// requests.
func (p *PendingLogins[V]) Add(key string, v V) bool {
	if time.Since(p.lastPrune) > pruneInterval || len(p.m) >= MaxPendingLogins {
		p.lastPrune = time.Now()
		for k, v := range p.m {
			if p.expired(v) {
				delete(p.m, k)
			}
		}
	}
	if len(p.m) >= MaxPendingLogins {
		return false
	}
	p.m[key] = v
	return true
}

// Get returns the entry for key, if it exists and isn't expired.
func (p *PendingLogins[V]) Get(key string) (V, bool) {
	v, ok := p.m[key]
	if ok && p.expired(v) {
		delete(p.m, key)
		var zero V
		return zero, false
	}
	return v, ok
}

// Delete deletes the entry for key.
func (p *PendingLogins[V]) Delete(key string) {
	delete(p.m, key)
}
