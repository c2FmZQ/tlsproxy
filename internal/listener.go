// MIT License
//
// Copyright (c) 2023 TTBT Enterprises LLC
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

package internal

import (
	"crypto/tls"
	"net"
	"sync"
)

func tlsListen(network, laddr string, config *tls.Config) (net.Listener, error) {
	l, err := net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}
	return tls.NewListener(&proxyListener{l}, config), nil
}

type proxyListener struct {
	net.Listener
}

func (l *proxyListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	return &proxyConn{Conn: c}, err
}

type proxyConn struct {
	net.Conn

	mu       sync.RWMutex
	sni      string
	acmeOnly bool
}

func unwrapProxyConn(c net.Conn) *proxyConn {
	switch conn := c.(type) {
	case *proxyConn:
		return conn
	case *tls.Conn:
		return unwrapProxyConn(conn.NetConn())
	default:
		return nil
	}
}

func setSNI(c net.Conn, sni string) {
	if conn := unwrapProxyConn(c); conn != nil {
		conn.mu.Lock()
		defer conn.mu.Unlock()
		conn.sni = sni
	}
}

func sniFromConn(c net.Conn) string {
	if conn := unwrapProxyConn(c); conn != nil {
		conn.mu.RLock()
		defer conn.mu.RUnlock()
		return conn.sni
	}
	return ""
}

func setACMEOnly(c net.Conn) {
	if conn := unwrapProxyConn(c); conn != nil {
		conn.mu.Lock()
		defer conn.mu.Unlock()
		conn.acmeOnly = true
	}
}

func acmeOnly(c net.Conn) bool {
	if conn := unwrapProxyConn(c); conn != nil {
		conn.mu.RLock()
		defer conn.mu.RUnlock()
		return conn.acmeOnly
	}
	return false
}
