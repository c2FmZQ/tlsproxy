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

package internal

import (
	"context"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

func startInternalHTTPServer(ctx context.Context, handler http.Handler, conns <-chan net.Conn) *http.Server {
	l := &proxyListener{
		ctx: ctx,
		ch:  conns,
	}
	s := &http.Server{
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  30 * time.Second,
	}
	go func() {
		log.Print("INFO internal http server started")
		log.Printf("INFO internal http server exited: %v", s.Serve(l))
	}()
	return s
}

type proxyListener struct {
	ctx  context.Context
	ch   <-chan net.Conn
	addr net.Addr

	mu     sync.Mutex
	closed bool
}

func (l *proxyListener) Accept() (net.Conn, error) {
	select {
	case c, ok := <-l.ch:
		if !ok {
			l.Close()
			return nil, net.ErrClosed
		}
		return c, nil
	case <-l.ctx.Done():
		l.Close()
		return nil, net.ErrClosed
	}
}

func (l *proxyListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.closed {
		l.closed = true
		go func() {
			for {
				select {
				case <-l.ch:
				case <-l.ctx.Done():
					return
				}
			}
		}()
	}
	return nil
}

func (l *proxyListener) Addr() net.Addr {
	return l.addr
}
