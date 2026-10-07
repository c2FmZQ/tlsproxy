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

package proxy

import (
	"net"
	"sync"
)

func newConnTracker() *connTracker {
	return &connTracker{}
}

type connKey struct {
	dst string
	src string
}

type connTracker struct {
	mu    sync.Mutex
	conns map[connKey]annotatedConnection
}

func (t *connTracker) slice() []annotatedConnection {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]annotatedConnection, 0, len(t.conns))
	for _, v := range t.conns {
		out = append(out, v)
	}
	return out
}

func (t *connTracker) add(c annotatedConnection) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conns == nil {
		t.conns = make(map[connKey]annotatedConnection)
	}
	cc := localNetConn(c)
	t.conns[connKey{src: cc.LocalAddr().String(), dst: cc.RemoteAddr().String()}] = c
	return len(t.conns)
}

func (t *connTracker) remove(c annotatedConnection) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	cc := localNetConn(c)
	delete(t.conns, connKey{src: cc.LocalAddr().String(), dst: cc.RemoteAddr().String()})
	return len(t.conns)
}

// ipCounter counts open connections per client IP address.
type ipCounter struct {
	mu sync.Mutex
	m  map[string]int
}

// inc increments the number of connections for addr's IP address. It returns
// the IP address and its new number of connections.
func (c *ipCounter) inc(addr net.Addr) (string, int) {
	ip := addr.String()
	if h, _, err := net.SplitHostPort(ip); err == nil {
		ip = h
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = make(map[string]int)
	}
	c.m[ip]++
	return ip, c.m[ip]
}

// dec decrements the number of connections for ip.
func (c *ipCounter) dec(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m[ip]--; c.m[ip] <= 0 {
		delete(c.m, ip)
	}
}
