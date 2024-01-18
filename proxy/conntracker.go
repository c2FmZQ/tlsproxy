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
	dst net.Addr
	src net.Addr
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
	t.conns[connKey{src: cc.LocalAddr(), dst: cc.RemoteAddr()}] = c
	return len(t.conns)
}

func (t *connTracker) remove(c annotatedConnection) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	cc := localNetConn(c)
	delete(t.conns, connKey{src: cc.LocalAddr(), dst: cc.RemoteAddr()})
	return len(t.conns)
}
