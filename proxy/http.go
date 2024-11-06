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
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

type ctxKey int

var connCtxKey ctxKey = 1

func startInternalHTTPServer(handler http.Handler, conns <-chan net.Conn) *http.Server {
	l := &proxyListener{
		ch:       conns,
		closedCh: make(chan struct{}),
	}
	s := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       30 * time.Second,
		ReadTimeout:       24 * time.Hour,
		WriteTimeout:      24 * time.Hour,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connCtxKey, c)
		},
	}
	go serveHTTP(s, l)
	return s
}

func serveHTTP(s *http.Server, l net.Listener) {
	if err := s.Serve(l); err != net.ErrClosed && err != http.ErrServerClosed {
		log.Printf("ERR http server exited: %v", err)
	}
}

type proxyListener struct {
	ch   <-chan net.Conn
	addr net.Addr

	mu       sync.Mutex
	closed   bool
	closedCh chan struct{}
}

func (l *proxyListener) Accept() (net.Conn, error) {
	select {
	case <-l.closedCh:
		return nil, net.ErrClosed
	case c, ok := <-l.ch:
		if !ok {
			l.Close()
			return nil, net.ErrClosed
		}
		return c, nil
	}
}

func (l *proxyListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.closed {
		l.closed = true
		close(l.closedCh)
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

func userAgent(req *http.Request) string {
	ua := req.Header.Get("user-agent")
	if len(ua) > 200 {
		ua = ua[:197] + "..."
	}
	return ua
}

func logHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if be := connBackend(req.Context().Value(connCtxKey).(anyConn)); be != nil {
			be.logRequestF("REQ %s ➔ %s %s (%q)", formatReqDesc(req), req.Method, req.URL, userAgent(req))
		}
		next.ServeHTTP(w, req)
	})
}
