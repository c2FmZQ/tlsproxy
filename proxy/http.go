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
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/c2FmZQ/tlsproxy/proxy/internal/netw"
)

type ctxKey int

var connCtxKey ctxKey = 1

func startInternalHTTPServer(handler http.Handler, conns <-chan net.Conn) *http.Server {
	l := &proxyListener{
		ch: conns,
	}
	s := &http.Server{
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  30 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connCtxKey, c)
		},
	}
	go func() {
		if err := s.Serve(l); err != net.ErrClosed {
			log.Printf("ERR internal http server exited: %v", err)
		}
	}()
	return s
}

type proxyListener struct {
	ch   <-chan net.Conn
	addr net.Addr

	mu     sync.Mutex
	closed bool
}

func (l *proxyListener) Accept() (net.Conn, error) {
	c, ok := <-l.ch
	if !ok {
		l.Close()
		return nil, net.ErrClosed
	}
	return c, nil
}

func (l *proxyListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.closed {
		l.closed = true
		go func() {
			for range l.ch {
			}
		}()
	}
	return nil
}

func (l *proxyListener) Addr() net.Addr {
	return l.addr
}

func logRequest(req *http.Request) {
	tlsConn := req.Context().Value(connCtxKey).(*tls.Conn)
	desc := formatConnDesc(tlsConn.NetConn().(*netw.Conn))
	log.Printf("REQ %s ➔ %s %s", desc, req.Method, req.URL)
}
