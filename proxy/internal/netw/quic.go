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

//go:build !noquic

package netw

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"maps"
	"net"
	"slices"
	"sync"
	"time"

	quicapi "github.com/c2FmZQ/quic-api"
	"github.com/quic-go/quic-go"
	"golang.org/x/time/rate"

	"github.com/c2FmZQ/tlsproxy/proxy/internal/counter"
)

var quicConfig = &quic.Config{
	MaxIdleTimeout:                   30 * time.Second,
	EnableDatagrams:                  true,
	EnableStreamResetPartialDelivery: true,
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
	tr := &quic.Transport{
		Conn:              conn,
		StatelessResetKey: &statelessResetKey,
	}
	return &QUICTransport{
		qt: quicapi.WrapTransport(tr),
	}, nil
}

// QUICTransport is a wrapper around quic.Transport.
type QUICTransport struct {
	qt quicapi.Transport
}

func (t *QUICTransport) Addr() net.Addr {
	return t.qt.(quicapi.TransportUnwrapper).Unwrap().Conn.LocalAddr()
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
	return newQUICConn(conn), nil
}

func (t *QUICTransport) DialEarly(ctx context.Context, addr net.Addr, tc *tls.Config, enableDatagrams, enableStreamResetPartialDelivery bool) (*QUICConn, error) {
	cfg := quicConfig.Clone()
	cfg.EnableDatagrams = enableDatagrams
	cfg.EnableStreamResetPartialDelivery = enableStreamResetPartialDelivery
	conn, err := t.qt.Dial(ctx, addr, tc, cfg)
	if err != nil {
		return nil, err
	}
	return newQUICConn(conn), nil
}

// QUICListener is a wrapper around quic.Listener.
type QUICListener struct {
	ln quicapi.Listener
}

func (l *QUICListener) Accept(ctx context.Context) (*QUICConn, error) {
	conn, err := l.ln.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return newQUICConn(conn), nil
}

func (l *QUICListener) Addr() net.Addr {
	return l.ln.Addr()
}

func (l *QUICListener) Close() error {
	return l.ln.Close()
}

var _ net.Conn = (*QUICConn)(nil)
var _ quicapi.Conn = (*QUICConn)(nil)

func newQUICConn(qc quicapi.Conn) *QUICConn {
	return &QUICConn{
		qc:            qc,
		bytesSent:     newCounter(),
		bytesReceived: newCounter(),
	}
}

// QUICConn is a wrapper around quic.Connection.
type QUICConn struct {
	qc quicapi.Conn

	ingressLimiter *rate.Limiter
	egressLimiter  *rate.Limiter

	mu              sync.Mutex
	onClose         func()
	annotations     map[string]any
	bytesSent       *counter.Counter
	bytesReceived   *counter.Counter
	upBytesSent     *counter.Counter
	upBytesReceived *counter.Counter
	streams         []*QUICStream
}

// SetAnnotation sets an annotation. The value can be any go value.
func (c *QUICConn) SetAnnotation(key string, value any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.annotations == nil {
		c.annotations = make(map[string]any)
	}
	c.annotations[key] = value
}

// Annotation retrieves an annotation that was previously set on the connection.
// The defaultValue is returned if the annotation was never set.
func (c *QUICConn) Annotation(key string, defaultValue any) any {
	c.mu.Lock()
	defer c.mu.Unlock()
	if v, ok := c.annotations[key]; ok {
		return v
	}
	return defaultValue
}

func (c *QUICConn) Streams() []*QUICStream {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.streams)
}

func (c *QUICConn) removeStream(qs *QUICStream) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.streams = slices.DeleteFunc(c.streams, func(s *QUICStream) bool {
		return qs == s
	})
}

// SetLimiter sets the rate limiters for this connection.
// It must be called before the first Read() or Write(). Peek() is OK.
func (c *QUICConn) SetLimiters(ingress, egress *rate.Limiter) {
	c.ingressLimiter = ingress
	c.egressLimiter = egress
}

// SetCounters sets the byte counters to use for this connection.
func (c *QUICConn) SetCounters(sent, received *counter.Counter) {
	c.upBytesSent = sent
	c.upBytesReceived = received
}

// BytesSent returns the number of bytes sent on this connection so far.
func (c *QUICConn) BytesSent() int64 {
	return c.bytesSent.Value()
}

// BytesReceived returns the number of bytes received on this connection so far.
func (c *QUICConn) BytesReceived() int64 {
	return c.bytesReceived.Value()
}

// ByteRateSent returns the rate of bytes sent on this connection in the last
// minute.
func (c *QUICConn) ByteRateSent() float64 {
	return c.bytesSent.Rate(time.Minute)
}

// ByteRateReceived returns the rate of bytes received on this connection in the
// last minute.
func (c *QUICConn) ByteRateReceived() float64 {
	return c.bytesReceived.Rate(time.Minute)
}

func (c *QUICConn) HandshakeComplete() <-chan struct{} {
	return c.HandshakeComplete()
}

func (c *QUICConn) NextConnection(ctx context.Context) (quicapi.Conn, error) {
	return c.NextConnection(ctx)
}

func (c *QUICConn) TLSConnectionState() tls.ConnectionState {
	return c.qc.ConnectionState().TLS
}

// OnClose sets a callback function that will be called when the connection
// is closed.
func (c *QUICConn) OnClose(f func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onClose = f
	go func() {
		<-c.qc.Context().Done()
		c.Close()
	}()
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

func (c *QUICConn) WrapConn(s any) *Conn {
	var stream quicapi.Stream
	var readDone, writeDone bool
	switch v := s.(type) {
	case *Conn:
		return v
	case *QUICStream:
		ctx, cancel := context.WithCancel(c.Context())
		cc := &Conn{
			Conn:        v,
			ctx:         ctx,
			cancel:      cancel,
			annotations: make(map[string]any),
		}
		c.mu.Lock()
		maps.Copy(cc.annotations, c.annotations)
		c.mu.Unlock()
		return cc
	case quicapi.Stream:
		stream = v
	case quicapi.SendStream:
		stream = &SendOnlyStream{v, c.Context()}
		readDone = true
	case quicapi.ReceiveStream:
		stream = &ReceiveOnlyStream{v, c.Context()}
		writeDone = true
	default:
		log.Panicf("PANIC WrapConn called with %T", v)
	}
	ctx, cancel := context.WithCancel(c.Context())
	cc := &Conn{
		Conn: &QUICStream{
			Stream:    stream,
			qc:        c,
			readDone:  readDone,
			writeDone: writeDone,
		},
		ctx:         ctx,
		cancel:      cancel,
		annotations: make(map[string]any),
	}
	c.mu.Lock()
	maps.Copy(cc.annotations, c.annotations)
	c.mu.Unlock()
	return cc
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

func (c *QUICConn) ConnectionStats() quic.ConnectionStats {
	return c.qc.ConnectionStats()
}

func (c *QUICConn) AddPath(t quicapi.TransportUnwrapper) (quicapi.Path, error) {
	return c.qc.AddPath(t)
}

func (c *QUICConn) AcceptStream(ctx context.Context) (quicapi.Stream, error) {
	s, err := c.qc.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	qs := &QUICStream{
		Stream: s,
		qc:     c,
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.streams = append(c.streams, qs)
	return qs, nil
}

func (c *QUICConn) AcceptUniStream(ctx context.Context) (quicapi.ReceiveStream, error) {
	s, err := c.qc.AcceptUniStream(ctx)
	if err != nil {
		return nil, err
	}
	qs := &QUICStream{
		Stream: &ReceiveOnlyStream{s, c.Context()},
		qc:     c,
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.streams = append(c.streams, qs)
	return qs, nil
}

func (c *QUICConn) OpenStream() (quicapi.Stream, error) {
	s, err := c.qc.OpenStream()
	if err != nil {
		return nil, err
	}
	qs := &QUICStream{
		Stream: s,
		qc:     c,
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.streams = append(c.streams, qs)
	return qs, nil
}

func (c *QUICConn) OpenStreamSync(ctx context.Context) (quicapi.Stream, error) {
	s, err := c.qc.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	qs := &QUICStream{
		Stream: s,
		qc:     c,
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.streams = append(c.streams, qs)
	return qs, nil
}

func (c *QUICConn) OpenUniStream() (quicapi.SendStream, error) {
	s, err := c.qc.OpenUniStream()
	if err != nil {
		return nil, err
	}
	qs := &QUICStream{
		Stream: &SendOnlyStream{s, c.Context()},
		qc:     c,
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.streams = append(c.streams, qs)
	return qs, nil
}

func (c *QUICConn) OpenUniStreamSync(ctx context.Context) (quicapi.SendStream, error) {
	s, err := c.qc.OpenUniStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	qs := &QUICStream{
		Stream: &SendOnlyStream{s, c.Context()},
		qc:     c,
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.streams = append(c.streams, qs)
	return qs, nil
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

var _ quicapi.Stream = (*SendOnlyStream)(nil)
var _ quicapi.Stream = (*ReceiveOnlyStream)(nil)
var _ quicapi.Stream = (*QUICStream)(nil)

type SendOnlyStream struct {
	quicapi.SendStream
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
	quicapi.ReceiveStream
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
	quicapi.Stream
	qc *QUICConn

	mu         sync.Mutex
	readDone   bool
	writeDone  bool
	bridgeAddr string
}

func (s *QUICStream) streamID() int64 {
	return int64(s.Stream.StreamID())
}

func (s *QUICStream) BridgeAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bridgeAddr
}

func (s *QUICStream) SetBridgeAddr(v string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bridgeAddr = v
}

func (s *QUICStream) LocalAddr() net.Addr {
	return s.qc.LocalAddr()
}

func (s *QUICStream) RemoteAddr() net.Addr {
	return s.qc.RemoteAddr()
}

func (s *QUICStream) markReadDone() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readDone = true
	if s.writeDone {
		s.qc.removeStream(s)
	}
}

func (s *QUICStream) markWriteDone() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writeDone = true
	if s.readDone {
		s.qc.removeStream(s)
	}
}

func (s *QUICStream) Read(b []byte) (int, error) {
	if l := s.qc.ingressLimiter; l != nil {
		if err := l.WaitN(s.Context(), len(b)); err != nil {
			return 0, err
		}
	}
	n, err := s.Stream.Read(b)
	if err != nil {
		s.markReadDone()
	}
	s.qc.bytesReceived.Incr(int64(n))
	s.qc.upBytesReceived.Incr(int64(n))
	return n, err
}

func (s *QUICStream) Write(b []byte) (int, error) {
	if l := s.qc.egressLimiter; l != nil {
		if err := l.WaitN(s.Context(), len(b)); err != nil {
			return 0, err
		}
	}
	n, err := s.Stream.Write(b)
	if err != nil {
		s.markWriteDone()
	}
	s.qc.bytesSent.Incr(int64(n))
	s.qc.upBytesSent.Incr(int64(n))
	return n, err
}

func (s *QUICStream) Close() error {
	err := s.Stream.Close()
	s.markWriteDone()
	return err
}

func (s *QUICStream) CancelRead(e quic.StreamErrorCode) {
	s.Stream.CancelRead(e)
	s.markReadDone()
}

func (s *QUICStream) CancelWrite(e quic.StreamErrorCode) {
	s.Stream.CancelWrite(e)
	s.markWriteDone()
}

func (s *QUICStream) CloseRead() error {
	s.CancelRead(0)
	return nil
}

func (s *QUICStream) CloseWrite() error {
	return s.Close()
}

func (s *QUICStream) SetReliableBoundary() {
	if ss, ok := s.Stream.(quicapi.SendStream); ok {
		ss.SetReliableBoundary()
	}
}
