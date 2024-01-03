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

// Package netw is a wrapper around network connections that stores annotations
// and records metrics.
package netw

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/c2FmZQ/tlsproxy/proxy/internal/counter"
)

// Listen creates a net listener that is instrumented to store per connection
// annotations and metrics.
func Listen(network, laddr string) (net.Listener, error) {
	l, err := net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}
	return listener{l}, nil
}

type listener struct {
	net.Listener
}

// Accept returns the next connection to the listener.
func (l listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Conn{
		Conn:          c,
		ctx:           ctx,
		cancel:        cancel,
		bytesSent:     newCounter(),
		bytesReceived: newCounter(),
	}, nil
}

func NewConnForTest(c net.Conn) *Conn {
	return &Conn{
		Conn:   c,
		ctx:    context.Background(),
		cancel: func() {},
	}
}

// Conn is a wrapper around net.Conn that stores annotations and metrics.
type Conn struct {
	net.Conn

	ctx             context.Context
	cancel          func()
	ingressLimiter  *rate.Limiter
	egressLimiter   *rate.Limiter
	bytesSent       *counter.Counter
	bytesReceived   *counter.Counter
	upBytesSent     *counter.Counter
	upBytesReceived *counter.Counter

	mu          sync.Mutex
	onClose     func()
	annotations map[string]any

	peekBuf []byte
}

func (c *Conn) StreamID() int64 {
	if cc, ok := c.Conn.(interface {
		streamID() int64
	}); ok {
		return cc.streamID()
	}
	return -1
}

// SetAnnotation sets an annotation. The value can be any go value.
func (c *Conn) SetAnnotation(key string, value any) {
	if cc, ok := c.Conn.(interface {
		SetAnnotation(key string, value any)
	}); ok {
		cc.SetAnnotation(key, value)
		return
	}
	SetAnnotation(c, key, value)
}

// SetAnnotation sets an annotation on a connection. The value can be any go
// value.
func SetAnnotation(conn net.Conn, key string, value any) {
	switch c := conn.(type) {
	case *Conn:
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.annotations == nil {
			c.annotations = make(map[string]any)
		}
		c.annotations[key] = value
	}
}

// Annotation retrieves an annotation that was previously set on the connection.
// The defaultValue is returned if the annotation was never set.
func (c *Conn) Annotation(key string, defaultValue any) any {
	if cc, ok := c.Conn.(interface {
		Annotation(key string, defaultValue any) any
	}); ok {
		return cc.Annotation(key, defaultValue)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if v, ok := c.annotations[key]; ok {
		return v
	}
	return defaultValue
}

// SetLimiter sets the rate limiters for this connection.
// It must be called before the first Read() or Write(). Peek() is OK.
func (c *Conn) SetLimiters(ingress, egress *rate.Limiter) {
	if cc, ok := c.Conn.(interface {
		SetLimiters(ingress, egress *rate.Limiter)
	}); ok {
		cc.SetLimiters(ingress, egress)
		return
	}
	c.ingressLimiter = ingress
	c.egressLimiter = egress
}

func (c *Conn) SetCounters(sent, received *counter.Counter) {
	if cc, ok := c.Conn.(interface {
		SetCounters(sent, received *counter.Counter)
	}); ok {
		cc.SetCounters(sent, received)
	}
	c.upBytesSent = sent
	c.upBytesReceived = received
}

// BytesSent returns the number of bytes sent on this connection so far.
func (c *Conn) BytesSent() int64 {
	if cc, ok := c.Conn.(interface {
		BytesSent() int64
	}); ok {
		return cc.BytesSent()
	}
	return c.bytesSent.Value()
}

// BytesReceived returns the number of bytes received on this connection so far.
func (c *Conn) BytesReceived() int64 {
	if cc, ok := c.Conn.(interface {
		BytesReceived() int64
	}); ok {
		return cc.BytesReceived()
	}
	return c.bytesReceived.Value()
}

// ByteRateSent returns the rate of bytes sent on this connection in the last
// minute.
func (c *Conn) ByteRateSent() float64 {
	if cc, ok := c.Conn.(interface {
		ByteRateSent() float64
	}); ok {
		return cc.ByteRateSent()
	}
	return c.bytesSent.Rate(time.Minute)
}

// ByteRateReceived returns the rate of bytes received on this connection in the
// last minute.
func (c *Conn) ByteRateReceived() float64 {
	if cc, ok := c.Conn.(interface {
		ByteRateReceived() float64
	}); ok {
		return cc.ByteRateReceived()
	}
	return c.bytesReceived.Rate(time.Minute)
}

// OnClose sets a callback function that will be called when the connection
// is closed.
func (c *Conn) OnClose(f func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onClose = f
}

func (c *Conn) Peek(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	want := len(b)
	have := len(c.peekBuf)
	if want > have {
		c.Conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		bb := make([]byte, want-have)
		n, _ := io.ReadFull(c.Conn, bb)
		c.peekBuf = append(c.peekBuf, bb[:n]...)
		c.Conn.SetReadDeadline(time.Time{})
	}
	n := copy(b, c.peekBuf)
	var err error
	if n < want {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}

func (c *Conn) Read(b []byte) (int, error) {
	if l := c.ingressLimiter; l != nil {
		if err := l.WaitN(c.ctx, len(b)); err != nil {
			return 0, err
		}
	}
	c.mu.Lock()
	if len(c.peekBuf) > 0 {
		n := copy(b, c.peekBuf)
		c.peekBuf = c.peekBuf[n:]
		c.bytesReceived.Incr(int64(n))
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()
	n, err := c.Conn.Read(b)
	c.bytesReceived.Incr(int64(n))
	c.upBytesReceived.Incr(int64(n))
	return n, err
}

func (c *Conn) Write(b []byte) (int, error) {
	if l := c.egressLimiter; l != nil {
		if err := l.WaitN(c.ctx, len(b)); err != nil {
			return 0, err
		}
	}
	n, err := c.Conn.Write(b)
	c.bytesSent.Incr(int64(n))
	c.upBytesSent.Incr(int64(n))
	return n, err
}

func (c *Conn) Close() error {
	c.mu.Lock()
	f := c.onClose
	c.onClose = nil
	c.mu.Unlock()
	c.cancel()
	if f != nil {
		f()
	}
	return c.Conn.Close()
}

func newCounter() *counter.Counter {
	return counter.New(time.Minute, time.Second)
}
