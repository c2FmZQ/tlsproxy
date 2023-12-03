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

//go:build quic

package netw

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/time/rate"
)

var quicConfig = &quic.Config{
	MaxIdleTimeout: 30 * time.Second,
}

// NewQUIC returns a wrapper around a quic.Transport to keep track of metrics
// and annotations.
func NewQUIC(addr string, statelessResetKey quic.StatelessResetKey) (*QUICTransport, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	return &QUICTransport{
		qt: quic.Transport{
			Conn:              conn,
			StatelessResetKey: &statelessResetKey,
		},
	}, nil
}

// QUICTransport is a wrapper around quic.Transport.
type QUICTransport struct {
	qt quic.Transport
}

func (t *QUICTransport) Addr() net.Addr {
	return t.qt.Conn.LocalAddr()
}

func (t *QUICTransport) Close() error {
	return t.qt.Close()
}

func (t *QUICTransport) Listen(tc *tls.Config) (*QUICListener, error) {
	ln, err := t.qt.Listen(tc, quicConfig)
	if err != nil {
		return nil, err
	}
	return &QUICListener{ln}, nil
}

func (t *QUICTransport) Dial(ctx context.Context, addr net.Addr, tc *tls.Config) (*QUICConn, error) {
	conn, err := t.qt.Dial(ctx, addr, tc, quicConfig)
	if err != nil {
		return nil, err
	}
	return &QUICConn{qc: conn}, nil
}

func (t *QUICTransport) DialEarly(ctx context.Context, addr net.Addr, tc *tls.Config) (*QUICConn, error) {
	conn, err := t.qt.Dial(ctx, addr, tc, quicConfig)
	if err != nil {
		return nil, err
	}
	return &QUICConn{qc: conn}, nil
}

// QUICListener is a wrapper around quic.Listener.
type QUICListener struct {
	ln *quic.Listener
}

func (l *QUICListener) Accept(ctx context.Context) (*QUICConn, error) {
	conn, err := l.ln.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return &QUICConn{qc: conn}, nil
}

func (l *QUICListener) Addr() net.Addr {
	return l.ln.Addr()
}

func (l *QUICListener) Close() error {
	return l.ln.Close()
}

var _ net.Conn = (*QUICConn)(nil)
var _ quic.Connection = (*QUICConn)(nil)
var _ quic.EarlyConnection = (*QUICConn)(nil)

// QUICConn is a wrapper around quic.Connection.
type QUICConn struct {
	qc quic.Connection

	ingressLimiter *rate.Limiter
	egressLimiter  *rate.Limiter

	mu            sync.Mutex
	onClose       func()
	bytesSent     int64
	bytesReceived int64
}

// SetLimiter sets the rate limiters for this connection.
// It must be called before the first Read() or Write(). Peek() is OK.
func (c *QUICConn) SetLimiters(ingress, egress *rate.Limiter) {
	c.ingressLimiter = ingress
	c.egressLimiter = egress
}

// BytesSent returns the number of bytes sent on this connection so far.
func (c *QUICConn) BytesSent() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bytesSent
}

// BytesReceived returns the number of bytes received on this connection so far.
func (c *QUICConn) BytesReceived() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bytesReceived
}

func (c *QUICConn) HandshakeComplete() <-chan struct{} {
	if cc, ok := c.qc.(quic.EarlyConnection); ok {
		return cc.HandshakeComplete()
	}
	ch := make(chan struct{})
	close(ch)
	return ch
}

func (c *QUICConn) NextConnection() quic.Connection {
	if cc, ok := c.qc.(quic.EarlyConnection); ok {
		return cc.NextConnection()
	}
	return c.qc
}

func (c *QUICConn) TLSConnectionState() tls.ConnectionState {
	return c.qc.ConnectionState().TLS
}

func (c *QUICConn) Close() error {
	c.mu.Lock()
	f := c.onClose
	c.onClose = nil
	c.mu.Unlock()
	if f != nil {
		f()
	}
	return c.qc.CloseWithError(0, "done")
}

func (c *QUICConn) Read([]byte) (int, error) {
	return 0, errors.New("read on QUICConn")
}

func (c *QUICConn) Write([]byte) (int, error) {
	return 0, errors.New("write on QUICConn")
}

func (c *QUICConn) SetDeadline(t time.Time) error {
	return errors.New("setDeadline on QUICConn")
}

func (c *QUICConn) SetReadDeadline(t time.Time) error {
	return errors.New("setReadDeadline on QUICConn")
}

func (c *QUICConn) SetWriteDeadline(t time.Time) error {
	return errors.New("setWriteDeadline on QUICConn")
}

func (c *QUICConn) WrapStream(s any) *Conn {
	var stream quic.Stream
	switch v := s.(type) {
	case *Conn:
		return v
	case *QUICConn:
		ctx, cancel := context.WithCancel(c.Context())
		return &Conn{
			Conn:        v,
			ctx:         ctx,
			cancel:      cancel,
			annotations: make(map[string]any),
		}
	case *QUICStream:
		ctx, cancel := context.WithCancel(c.Context())
		return &Conn{
			Conn:        v,
			ctx:         ctx,
			cancel:      cancel,
			annotations: make(map[string]any),
		}
	case quic.Stream:
		stream = v
	case quic.SendStream:
		stream = &SendOnlyStream{v, c.Context()}
	case quic.ReceiveStream:
		stream = &ReceiveOnlyStream{v, c.Context()}
	default:
		log.Panicf("PANIC WrapStream called with %T", v)
	}
	ctx, cancel := context.WithCancel(c.Context())
	return &Conn{
		Conn: &QUICStream{
			Stream: stream,
			qc:     c,
		},
		ctx:         ctx,
		cancel:      cancel,
		annotations: make(map[string]any),
	}
}

func (c *QUICConn) LocalAddr() net.Addr {
	return c.qc.LocalAddr()
}

func (c *QUICConn) RemoteAddr() net.Addr {
	return c.qc.RemoteAddr()
}

func (c *QUICConn) ConnectionState() quic.ConnectionState {
	return c.qc.ConnectionState()
}

func (c *QUICConn) AcceptStream(ctx context.Context) (quic.Stream, error) {
	s, err := c.qc.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return &QUICStream{
		Stream: s,
		qc:     c,
	}, nil
}

func (c *QUICConn) AcceptUniStream(ctx context.Context) (quic.ReceiveStream, error) {
	s, err := c.qc.AcceptUniStream(ctx)
	if err != nil {
		return nil, err
	}
	return &QUICStream{
		Stream: &ReceiveOnlyStream{s, c.Context()},
		qc:     c,
	}, nil
}

func (c *QUICConn) OpenStream() (quic.Stream, error) {
	s, err := c.qc.OpenStream()
	if err != nil {
		return nil, err
	}
	return &QUICStream{
		Stream: s,
		qc:     c,
	}, nil
}

func (c *QUICConn) OpenStreamSync(ctx context.Context) (quic.Stream, error) {
	s, err := c.qc.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return &QUICStream{
		Stream: s,
		qc:     c,
	}, nil
}

func (c *QUICConn) OpenUniStream() (quic.SendStream, error) {
	s, err := c.qc.OpenUniStream()
	if err != nil {
		return nil, err
	}
	return &QUICStream{
		Stream: &SendOnlyStream{s, c.Context()},
		qc:     c,
	}, nil
}

func (c *QUICConn) OpenUniStreamSync(ctx context.Context) (quic.SendStream, error) {
	s, err := c.qc.OpenUniStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return &QUICStream{
		Stream: &SendOnlyStream{s, c.Context()},
		qc:     c,
	}, nil
}

func (c *QUICConn) CloseWithError(code quic.ApplicationErrorCode, msg string) error {
	return c.qc.CloseWithError(code, msg)
}

func (c *QUICConn) Context() context.Context {
	return c.qc.Context()
}

func (c *QUICConn) SendDatagram(b []byte) error {
	return c.qc.SendDatagram(b)
}

func (c *QUICConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return c.qc.ReceiveDatagram(ctx)
}

var _ quic.Stream = (*SendOnlyStream)(nil)
var _ quic.Stream = (*ReceiveOnlyStream)(nil)
var _ quic.Stream = (*QUICStream)(nil)

type SendOnlyStream struct {
	quic.SendStream
	ctx context.Context
}

func (s *SendOnlyStream) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (s *SendOnlyStream) CancelRead(quic.StreamErrorCode) {
}

func (s *SendOnlyStream) SetReadDeadline(time.Time) error {
	return nil
}

func (s *SendOnlyStream) SetDeadline(t time.Time) error {
	return s.SendStream.SetWriteDeadline(t)
}

type ReceiveOnlyStream struct {
	quic.ReceiveStream
	ctx context.Context
}

func (s *ReceiveOnlyStream) Write([]byte) (int, error) {
	return 0, io.EOF
}

func (s *ReceiveOnlyStream) Close() error {
	return nil
}

func (s *ReceiveOnlyStream) CancelWrite(quic.StreamErrorCode) {
}

func (s *ReceiveOnlyStream) Context() context.Context {
	return s.ctx
}

func (s *ReceiveOnlyStream) SetDeadline(t time.Time) error {
	return s.ReceiveStream.SetReadDeadline(t)
}

func (s *ReceiveOnlyStream) SetWriteDeadline(time.Time) error {
	return nil
}

var _ net.Conn = (*QUICStream)(nil)

// QUICStream is a wrapper around quic.Stream that implements the net.Conn
// interface.
type QUICStream struct {
	quic.Stream
	qc *QUICConn
}

func (s *QUICStream) streamID() int64 {
	return int64(s.Stream.StreamID())
}

func (s *QUICStream) LocalAddr() net.Addr {
	return s.qc.LocalAddr()
}

func (s *QUICStream) RemoteAddr() net.Addr {
	return s.qc.RemoteAddr()
}

func (s *QUICStream) Read(b []byte) (int, error) {
	if l := s.qc.ingressLimiter; l != nil {
		if err := l.WaitN(s.Context(), len(b)); err != nil {
			return 0, err
		}
	}
	n, err := s.Stream.Read(b)
	s.qc.mu.Lock()
	defer s.qc.mu.Unlock()
	s.qc.bytesReceived += int64(n)
	return n, err
}

func (s *QUICStream) Write(b []byte) (int, error) {
	if l := s.qc.egressLimiter; l != nil {
		if err := l.WaitN(s.Context(), len(b)); err != nil {
			return 0, err
		}
	}
	n, err := s.Stream.Write(b)
	s.qc.mu.Lock()
	defer s.qc.mu.Unlock()
	s.qc.bytesSent += int64(n)
	return n, err
}

func (s *QUICStream) Close() error {
	return s.Stream.Close()
}

func (s *QUICStream) CancelRead(e quic.StreamErrorCode) {
	s.Stream.CancelRead(e)
}

func (s *QUICStream) CancelWrite(e quic.StreamErrorCode) {
	s.Stream.CancelWrite(e)
}

func (s *QUICStream) CloseRead() error {
	s.Stream.CancelRead(0)
	return nil
}

func (s *QUICStream) CloseWrite() error {
	return s.Stream.Close()
}
