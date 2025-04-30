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

package proxy

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/c2FmZQ/ech"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/c2FmZQ/tlsproxy/proxy/internal/netw"
)

const (
	quicIsEnabled         = true
	statelessResetKeyFile = "quic-stateless-reset-key"

	quicUnrecognizedName = quic.ApplicationErrorCode(0x1001)
	quicAccessDenied     = quic.ApplicationErrorCode(0x1002)
	quicBadGateway       = quic.ApplicationErrorCode(0x1003)
	quicStreamError      = quic.ApplicationErrorCode(0x1004)
	quicTooBusy          = quic.ApplicationErrorCode(0x1005)
)

func (p *Proxy) startQUIC(ctx context.Context) error {
	var statelessResetKey [32]byte
	var empty []byte
	p.store.CreateEmptyFile(statelessResetKeyFile, &empty)
	if err := p.store.ReadDataFile(statelessResetKeyFile, &statelessResetKey); err != nil {
		if _, err := io.ReadFull(rand.Reader, statelessResetKey[:]); err != nil {
			return err
		}
		if err := p.store.SaveDataFile(statelessResetKeyFile, &statelessResetKey); err != nil {
			return err
		}
	}
	qt, err := netw.NewQUIC(*p.cfg.TLSAddr, statelessResetKey)
	if err != nil {
		return err
	}
	p.quicTransport = qt
	for _, be := range p.cfg.Backends {
		be.quicTransport = qt
	}
	return p.startQUICListener(ctx)
}

func (p *Proxy) startQUICListener(ctx context.Context) error {
	if p.quicListener != nil {
		p.quicListener.Close()
		p.quicListener = nil
	}
	tc := p.baseTLSConfig()
	tc.MinVersion = tls.VersionTLS13
	tc.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		p.mu.RLock()
		defer p.mu.RUnlock()
		for _, proto := range hello.SupportedProtos {
			be, ok := p.backends[beKey{serverName: hello.ServerName, proto: proto}]
			if ok && be.Mode != ModeTLSPassthrough {
				return be.tlsConfig(true), nil
			}
		}
		p.logErrorF("ERR QUIC connection %s %s", hello.ServerName, hello.SupportedProtos)
		return nil, tlsUnrecognizedName
	}
	quicListener, err := p.quicTransport.(*netw.QUICTransport).Listen(tc)
	if err != nil {
		return err
	}
	p.quicListener = quicListener
	go p.quicAcceptLoop(ctx, quicListener)
	return nil
}

func (p *Proxy) quicAcceptLoop(ctx context.Context, ln *netw.QUICListener) {
	p.logConnF("INF Accepting QUIC connections on %s %s", ln.Addr().Network(), ln.Addr())
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			if errors.Is(err, quic.ErrServerClosed) || errors.Is(err, quic.ErrTransportClosed) || errors.Is(err, context.Canceled) || err.Error() == "closing" {
				p.logErrorF("INF QUIC Accept loop terminated")
				break
			}
			p.logErrorF("ERR QUIC Accept: %v", err)
			continue
		}
		go p.handleQUICConnection(conn)
	}
}

func (p *Proxy) handleQUICConnection(qc *netw.QUICConn) {
	defer func() {
		if r := recover(); r != nil {
			p.recordEvent("panic")
			p.logErrorF("ERR [%s] %s: PANIC: %v", certSummary(connClientCert(qc)), qc.RemoteAddr(), r)
			qc.Close()
		}
	}()
	ctx := context.WithValue(qc.Context(), connCtxKey, qc)
	p.recordEvent("quic connection")
	defer qc.Close()

	numOpen := p.inConns.add(qc)
	qc.OnClose(func() {
		p.inConns.remove(qc)
		if be := connBackend(qc); be != nil {
			be.incInFlight(-1)
			startTime := qc.Annotation(startTimeKey, time.Time{}).(time.Time)
			be.logConnF("END %s; Dur:%s Recv:%d Sent:%d",
				formatConnDesc(qc), time.Since(startTime).Truncate(time.Millisecond),
				qc.BytesReceived(), qc.BytesSent())
		}
		p.connClosed.Broadcast()
	})
	qc.SetAnnotation(startTimeKey, time.Now())

	cs := qc.TLSConnectionState()
	qc.SetAnnotation(serverNameKey, cs.ServerName)
	qc.SetAnnotation(protoKey, cs.NegotiatedProtocol)
	qc.SetAnnotation(echAcceptedKey, cs.ECHAccepted)
	if cs.ECHAccepted {
		p.recordEvent("encrypted client hello accepted " + idnaToUnicode(cs.ServerName))
	}

	var clientCert *x509.Certificate
	if len(cs.PeerCertificates) > 0 {
		clientCert = cs.PeerCertificates[0]
	}
	qc.SetAnnotation(clientCertKey, clientCert)

	sum := certSummary(clientCert)
	if sum == "" {
		sum = "-"
	}

	p.mu.RLock()
	be, ok := p.backends[beKey{serverName: cs.ServerName, proto: cs.NegotiatedProtocol}]
	p.mu.RUnlock()
	if !ok {
		p.recordEvent("unexpected SNI")
		p.logErrorF("BAD [%s] %s:%s ➔ %q: unexpected SNI", sum, qc.RemoteAddr().Network(), qc.RemoteAddr(), cs.ServerName)
		qc.CloseWithError(quicUnrecognizedName, "unrecognized name")
		return
	}
	be.incInFlight(1)
	qc.SetAnnotation(backendKey, be)
	p.setCounters(qc, cs.ServerName)

	if numOpen >= *p.cfg.MaxOpen {
		p.recordEvent("too many open connections")
		be.logErrorF("ERR [%s] %s:%s: too many open connections: %d >= %d", sum, qc.RemoteAddr().Network(), qc.RemoteAddr(), numOpen, *p.cfg.MaxOpen)
		return
	}

	if l := be.bwLimit; l != nil {
		qc.SetLimiters(l.ingress, l.egress)
	}

	if err := be.checkIP(qc.RemoteAddr()); err != nil {
		p.recordEvent(idnaToUnicode(cs.ServerName) + " CheckIP " + err.Error())
		be.logErrorF("BAD [%s] %s:%s ➔ %q CheckIP: %v", sum, qc.RemoteAddr().Network(), qc.RemoteAddr(), idnaToUnicode(cs.ServerName), err)
		qc.CloseWithError(quicAccessDenied, "access denied")
		return
	}

	var showECH string
	if cs.ECHAccepted {
		showECH = "+ECH"
	}
	be.logConnF("QUC [%s] %s:%s ➔ %s|%s:%s%s", sum, qc.RemoteAddr().Network(), qc.RemoteAddr(), idnaToUnicode(cs.ServerName), be.Mode, cs.NegotiatedProtocol, showECH)
	if err := be.connLimit.Wait(ctx); err != nil {
		if !errors.Is(err, context.Canceled) {
			p.recordEvent(err.Error())
			be.logErrorF("ERR [%s] %s ➔  %q Wait: %v", sum, qc.RemoteAddr(), idnaToUnicode(cs.ServerName), err)
		}
		return
	}

	reportErr := func(err error, tag string) {
		var appErr *quic.ApplicationError
		if errors.Is(err, context.Canceled) {
			return
		}
		if errors.As(err, &appErr) && appErr.ErrorCode == 0 {
			return
		}
		var idleTimeout *quic.IdleTimeoutError
		if errors.As(err, &idleTimeout) && idleTimeout.Timeout() {
			return
		}
		be.logErrorF("ERR [%s] %s:%s ➔ %s|%s:%s %s: %v", sum, qc.RemoteAddr().Network(), qc.RemoteAddr(), idnaToUnicode(cs.ServerName), be.Mode, cs.NegotiatedProtocol, tag, err)
	}

	if serv, ok := be.http3Server.(*http3.Server); ok && cs.NegotiatedProtocol == "h3" {
		if err := serv.ServeQUICConn(qc); err != nil {
			reportErr(err, "ServeQUICConn")
		}
		return
	}

	if be.Mode == ModeQUIC {
		beConn, err := be.dialQUICBackend(ctx, cs.NegotiatedProtocol)
		if err != nil {
			qc.CloseWithError(quicBadGateway, "bad gateway")
			be.logErrorF("ERR [%s] %s:%s ➔ %s|%s:%s dialQUICBackend: %v", sum, qc.RemoteAddr().Network(), qc.RemoteAddr(), idnaToUnicode(cs.ServerName), be.Mode, cs.NegotiatedProtocol, err)
			return
		}
		defer beConn.Close()

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				recvStream, err := beConn.AcceptUniStream(ctx)
				if err != nil {
					reportErr(err, "AcceptUniStream")
					return
				}
				go be.handleQUICQUICStream(ctx, qc, qc.WrapConn(recvStream))
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				stream, err := beConn.AcceptStream(ctx)
				if err != nil {
					reportErr(err, "AcceptStream")
					return
				}
				wg.Add(1)
				go func() {
					defer wg.Done()
					be.handleQUICQUICStream(ctx, qc, qc.WrapConn(stream))
				}()
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				recvStream, err := qc.AcceptUniStream(ctx)
				if err != nil {
					reportErr(err, "AcceptUniStream")
					return
				}
				wg.Add(1)
				go func() {
					defer wg.Done()
					be.handleQUICQUICStream(ctx, beConn, qc.WrapConn(recvStream))
				}()
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				stream, err := qc.AcceptStream(ctx)
				if err != nil {
					reportErr(err, "AcceptStream")
					return
				}
				wg.Add(1)
				go func() {
					defer wg.Done()
					be.handleQUICQUICStream(ctx, beConn, qc.WrapConn(stream))
				}()
			}
		}()
		if qc.ConnectionState().SupportsDatagrams && beConn.ConnectionState().SupportsDatagrams {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					b, err := qc.ReceiveDatagram(ctx)
					if err != nil {
						reportErr(err, "->ReceiveDatagram")
						return
					}
					if err := beConn.SendDatagram(b); err != nil {
						reportErr(err, "SendDatagram->")
					}
				}
			}()
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					b, err := beConn.ReceiveDatagram(ctx)
					if err != nil {
						reportErr(err, "ReceiveDatagram<-")
						return
					}
					if err := qc.SendDatagram(b); err != nil {
						reportErr(err, "<-SendDatagram")
					}
				}
			}()
		}
		wg.Wait()
		return
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			recvStream, err := qc.AcceptUniStream(ctx)
			if err != nil {
				reportErr(err, "AcceptUniStream")
				return
			}
			cc := qc.WrapConn(recvStream)
			wg.Add(1)
			go func() {
				defer wg.Done()
				p.handleQUICTCPStream(ctx, be, cc)
			}()
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			stream, err := qc.AcceptStream(ctx)
			if err != nil {
				reportErr(err, "AcceptStream")
				return
			}
			cc := qc.WrapConn(stream)
			wg.Add(1)
			go func() {
				defer wg.Done()
				p.handleQUICTCPStream(ctx, be, cc)
			}()
		}
	}()
	wg.Wait()
}

func (p *Proxy) handleQUICTCPStream(ctx context.Context, be *Backend, conn *netw.Conn) {
	serverName := idnaToUnicode(connServerName(conn))
	closeConnNeeded := true
	defer func() {
		if closeConnNeeded {
			conn.Close()
		}
	}()

	conn.SetAnnotation(startTimeKey, time.Now())

	switch be.Mode {
	case ModeConsole, ModeLocal, ModeHTTP, ModeHTTPS:
		be.logConnF("STR %s", formatConnDesc(conn))
		closeConnNeeded = false
		be.httpConnChan <- conn

	case ModeTCP, ModeTLS:
		intConn, err := be.dial(ctx, connProto(conn))
		if err != nil {
			p.recordEvent("dial error")
			be.logErrorF("ERR [-] %s:%s ➔  %q Dial: %v", conn.RemoteAddr().Network(), conn.RemoteAddr(), serverName, err)
			return
		}
		defer intConn.Close()
		setKeepAlive(intConn)

		conn.SetAnnotation(dialDoneKey, time.Now())
		if cc, ok := conn.Conn.(interface {
			SetBridgeAddr(string)
		}); ok {
			cc.SetBridgeAddr(intConn.RemoteAddr().Network() + ":" + intConn.RemoteAddr().String())
		}
		be.logConnF("STR %s", formatConnDesc(conn))

		if err := be.bridgeConns(conn, intConn); err != nil {
			be.logErrorF("DBG %s %v", formatConnDesc(conn), err)
		}

		startTime := conn.Annotation(startTimeKey, time.Time{}).(time.Time)
		dialTime := conn.Annotation(dialDoneKey, time.Time{}).(time.Time)
		totalTime := time.Since(startTime).Truncate(time.Millisecond)

		be.logConnF("END %s; Dial:%s Dur:%s Recv:%d Sent:%d", formatConnDesc(conn),
			dialTime.Sub(startTime).Truncate(time.Millisecond), totalTime,
			conn.BytesReceived(), conn.BytesSent())

	default:
		be.logErrorF("ERR [-] %s:%s: unhandled stream %q", conn.RemoteAddr().Network(), conn.RemoteAddr(), be.Mode)
	}
}

func (be *Backend) handleQUICQUICStream(ctx context.Context, dest *netw.QUICConn, conn *netw.Conn) {
	serverName := idnaToUnicode(connServerName(conn))
	qs, ok := conn.Conn.(*netw.QUICStream)
	if !ok {
		be.logErrorF("ERR [-] %s ➔  %q not a QUICStream", conn.RemoteAddr(), serverName)
		return
	}
	var intConn *netw.Conn
	if _, ok := qs.Stream.(*netw.ReceiveOnlyStream); ok {
		sendStream, err := dest.OpenUniStreamSync(ctx)
		if err != nil {
			be.recordEvent("openstream error")
			be.logErrorF("ERR [-] %s:%s ➔  %q OpenUniStreamSync: %v", conn.RemoteAddr().Network(), conn.RemoteAddr(), serverName, err)
			var appErr *quic.ApplicationError
			if errors.As(err, &appErr) {
				qs.CancelRead(quic.StreamErrorCode(appErr.ErrorCode))
			}
			return
		}
		intConn = dest.WrapConn(sendStream)
	} else {
		stream, err := dest.OpenStreamSync(ctx)
		if err != nil {
			be.recordEvent("openstream error")
			be.logErrorF("ERR [-] %s:%s ➔  %q OpenStreamSync: %v", conn.RemoteAddr().Network(), conn.RemoteAddr(), serverName, err)
			var appErr *quic.ApplicationError
			if errors.As(err, &appErr) {
				qs.CancelRead(quic.StreamErrorCode(appErr.ErrorCode))
			}
			return
		}
		intConn = dest.WrapConn(stream)
	}
	defer intConn.Close()

	now := time.Now()
	conn.SetAnnotation(startTimeKey, now)
	conn.SetAnnotation(dialDoneKey, now)

	desc := formatConnDesc(conn)
	be.logConnF("STR %s", desc)

	if err := be.bridgeConns(conn, intConn); err != nil {
		be.logErrorF("DBG %s %v", desc, err)
	}

	startTime := conn.Annotation(startTimeKey, time.Time{}).(time.Time)
	dialTime := conn.Annotation(dialDoneKey, time.Time{}).(time.Time)
	totalTime := time.Since(startTime).Truncate(time.Millisecond)

	be.logConnF("END %s; Dial:%s Dur:%s Recv:%d Sent:%d", desc,
		dialTime.Sub(startTime).Truncate(time.Millisecond), totalTime,
		conn.BytesReceived(), conn.BytesSent())
}

func (be *Backend) dialQUIC(ctx context.Context, addr string, tc *tls.Config) (*netw.QUICConn, error) {
	qt, ok := be.quicTransport.(*netw.QUICTransport)
	if !ok {
		return nil, errors.New("invalid QUIC transport")
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	var enableDatagrams bool
	if cc, ok := ctx.Value(connCtxKey).(*netw.QUICConn); ok {
		enableDatagrams = cc.ConnectionState().SupportsDatagrams
	}
	return qt.DialEarly(ctx, udpAddr, tc, enableDatagrams)
}

func (be *Backend) dialQUICStream(ctx context.Context, addr string, tc *tls.Config) (net.Conn, error) {
	conn, err := be.dialQUIC(ctx, addr, tc)
	if err != nil {
		return nil, err
	}
	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return conn.WrapConn(s), nil
}

func (be *Backend) dialQUICBackend(ctx context.Context, proto string) (*netw.QUICConn, error) {
	var (
		addresses          = be.Addresses
		timeout            = be.ForwardTimeout
		insecureSkipVerify = be.InsecureSkipVerify
		serverName         = be.ForwardServerName
		rootCAs            = be.forwardRootCAs
		next               = &be.state.next

		echConfigList []byte
		echPublicName string
		echRequired   bool
	)
	if be.ForwardECH != nil {
		setIfNotNil(&echConfigList, be.ForwardECH.echConfigList)
		setIfNotNil(&echPublicName, be.ForwardECH.ECHPublicName)
		setIfNotNil(&echRequired, be.ForwardECH.RequireECH)
	}
	if id, ok := ctx.Value(ctxOverrideIDKey).(int); ok && id >= 0 && id < len(be.PathOverrides) {
		po := be.PathOverrides[id]
		addresses = po.Addresses
		timeout = po.ForwardTimeout
		insecureSkipVerify = po.InsecureSkipVerify
		serverName = po.ForwardServerName
		rootCAs = po.forwardRootCAs
		next = &be.state.oNext[id]
		if po.ForwardECH != nil {
			setIfNotNil(&echConfigList, po.ForwardECH.echConfigList)
			setIfNotNil(&echPublicName, po.ForwardECH.ECHPublicName)
			setIfNotNil(&echRequired, po.ForwardECH.RequireECH)
		}
	}

	if len(addresses) == 0 {
		return nil, errors.New("no backend addresses")
	}

	tc := &tls.Config{
		InsecureSkipVerify:   insecureSkipVerify,
		ServerName:           serverName,
		NextProtos:           []string{proto},
		RootCAs:              rootCAs,
		GetClientCertificate: be.getClientCert(ctx),
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return tlsCertificateRequired
			}
			cert := cs.PeerCertificates[0]
			if m, ok := be.pkiMap[hex.EncodeToString(cert.AuthorityKeyId)]; ok {
				if m.IsRevoked(cert.SerialNumber) {
					return tlsCertificateRevoked
				}
			} else if len(cert.OCSPServer) > 0 {
				if err := be.ocspCache.VerifyChains(ctx, cs.VerifiedChains, cs.OCSPResponse); err != nil {
					be.recordEvent(fmt.Sprintf("backend X509 %s [%s] (OCSP:%v)", idnaToUnicode(cs.ServerName), cert.Subject, err))
					return tlsCertificateRevoked
				}
			}
			return nil
		},
		EncryptedClientHelloConfigList: echConfigList,
	}

	dialer := ech.Dialer[*netw.QUICConn]{
		RequireECH: echRequired,
		Resolver:   be.resolver,
		PublicName: echPublicName,
		DialFunc: func(ctx context.Context, network, addr string, tc *tls.Config) (*netw.QUICConn, error) {
			return be.dialQUIC(ctx, addr, tc)
		},
	}

	be.state.mu.Lock()
	addr := strings.Join(slices.Concat(addresses[*next:], addresses[:*next]), ",")
	*next = (*next + 1) % len(addresses)
	be.state.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, timeout)
	conn, err := dialer.Dial(ctx, "udp", addr, tc)
	cancel()
	if err != nil {
		return nil, err
	}

	conn.OnClose(func() {
		be.outConns.remove(conn)
	})
	be.outConns.add(conn)
	conn.SetAnnotation(startTimeKey, time.Now())
	conn.SetAnnotation(modeKey, be.Mode)
	conn.SetAnnotation(protoKey, proto)
	if cc, ok := ctx.Value(connCtxKey).(net.Conn); ok {
		conn.SetAnnotation(serverNameKey, connServerName(cc))
		annotatedConn(cc).SetAnnotation(internalConnKey, conn)
	}
	return conn, nil
}

func (be *Backend) http3Transport() http.RoundTripper {
	return &http3.Transport{
		DisableCompression: true,
		Dial: func(ctx context.Context, _ string, _ *tls.Config, _ *quic.Config) (quic.EarlyConnection, error) {
			conn, err := be.dialQUICBackend(ctx, "h3")
			if err != nil {
				return nil, err
			}
			return conn, nil
		},
	}
}

func http3Server(handler http.Handler) *http3.Server {
	return &http3.Server{
		Handler: handler,
		ConnContext: func(ctx context.Context, c quic.Connection) context.Context {
			if _, ok := c.(*netw.QUICConn); !ok {
				panic(fmt.Sprintf("http3.Server.ConnContext called with: %#v", c))
			}
			return context.WithValue(ctx, connCtxKey, c)
		},
		EnableDatagrams: false,
	}
}
