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
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/c2FmZQ/tlsproxy/proxy/internal/netw"
)

const (
	quicIsEnabled         = true
	statelessResetKeyFile = "quic-stateless-reset-key"

	tlsUnrecognizedName = tls.AlertError(0x70)

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

	tc := p.baseTLSConfig()
	tc.MinVersion = tls.VersionTLS13
	tc.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		p.mu.Lock()
		defer p.mu.Unlock()
		for _, proto := range hello.SupportedProtos {
			if be, ok := p.backends[beKey{serverName: hello.ServerName, proto: proto}]; ok && be.Mode != ModeTLSPassthrough {
				return be.tlsConfigQUIC, nil
			}
		}
		log.Printf("ERR QUIC connection %s %s", hello.ServerName, hello.SupportedProtos)
		return nil, tlsUnrecognizedName
	}
	qt, err := netw.NewQUIC(p.cfg.TLSAddr, statelessResetKey)
	if err != nil {
		return err
	}
	quicListener, err := qt.Listen(tc)
	if err != nil {
		return err
	}
	p.quicTransport = qt
	for _, be := range p.cfg.Backends {
		be.quicTransport = qt
	}
	go p.quicAcceptLoop(ctx, quicListener)
	return nil
}

func (p *Proxy) quicAcceptLoop(ctx context.Context, ln *netw.QUICListener) {
	log.Printf("INF Accepting QUIC connections on %s %s", ln.Addr().Network(), ln.Addr())
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			if errors.Is(err, quic.ErrServerClosed) || errors.Is(err, context.Canceled) || err.Error() == "closing" {
				log.Print("INF QUIC Accept loop terminated")
				break
			}
			log.Printf("ERR QUIC Accept: %v", err)
			continue
		}
		go p.handleQUICConnection(conn)
	}
}

func (p *Proxy) handleQUICConnection(qc *netw.QUICConn) {
	defer func() {
		if r := recover(); r != nil {
			p.recordEvent("panic")
			log.Printf("ERR [%s] %s: PANIC: %v", certSummary(connClientCert(qc)), qc.RemoteAddr(), r)
			qc.Close()
		}
	}()
	conn := qc.WrapStream(qc)
	defer conn.Close()
	ctx := context.WithValue(qc.Context(), connCtxKey, conn)

	p.recordEvent("quic connection")
	numOpen := p.addConn(conn)
	conn.OnClose(func() {
		p.removeConn(conn)
		startTime := conn.Annotation(startTimeKey, time.Time{}).(time.Time)
		log.Printf("END %s; Dur:%s Recv:%d Sent:%d",
			formatConnDesc(conn), time.Since(startTime).Truncate(time.Millisecond),
			conn.BytesReceived(), conn.BytesSent())
		if be := connBackend(conn); be != nil {
			be.incInFlight(-1)
		}
		p.connClosed.Broadcast()
	})
	conn.SetAnnotation(startTimeKey, time.Now())

	cs := qc.TLSConnectionState()
	conn.SetAnnotation(serverNameKey, cs.ServerName)
	conn.SetAnnotation(protoKey, cs.NegotiatedProtocol)

	var clientCert *x509.Certificate
	if len(cs.PeerCertificates) > 0 {
		clientCert = cs.PeerCertificates[0]
	}
	conn.SetAnnotation(clientCertKey, clientCert)

	sum := certSummary(clientCert)
	if sum == "" {
		sum = "-"
	}

	be, err := p.backend(cs.ServerName, cs.NegotiatedProtocol)
	if err != nil {
		p.recordEvent(err.Error())
		log.Printf("BAD [%s] %s:%s ➔ %q: %v", sum, conn.RemoteAddr().Network(), conn.RemoteAddr(), cs.ServerName, err)
		qc.CloseWithError(quicUnrecognizedName, "unrecognized name")
		return
	}
	be.incInFlight(1)
	conn.SetAnnotation(backendKey, be)
	p.setCounters(conn, cs.ServerName)

	if numOpen >= p.cfg.MaxOpen {
		p.recordEvent("too many open connections")
		log.Printf("ERR [%s] %s:%s: too many open connections: %d >= %d", sum, conn.RemoteAddr().Network(), conn.RemoteAddr(), numOpen, p.cfg.MaxOpen)
		return
	}

	if l := be.bwLimit; l != nil {
		conn.SetLimiters(l.ingress, l.egress)
	}

	if err := be.checkIP(conn.RemoteAddr()); err != nil {
		p.recordEvent(idnaToUnicode(cs.ServerName) + " CheckIP " + err.Error())
		log.Printf("BAD [%s] %s:%s ➔ %q CheckIP: %v", sum, conn.RemoteAddr().Network(), conn.RemoteAddr(), idnaToUnicode(cs.ServerName), err)
		qc.CloseWithError(quicAccessDenied, "access denied")
		return
	}

	log.Printf("QUC [%s] %s:%s ➔ %s|%s:%s", sum, conn.RemoteAddr().Network(), conn.RemoteAddr(), idnaToUnicode(cs.ServerName), be.Mode, cs.NegotiatedProtocol)
	if err := be.connLimit.Wait(ctx); err != nil {
		if !errors.Is(err, context.Canceled) {
			p.recordEvent(err.Error())
			log.Printf("ERR [%s] %s ➔  %q Wait: %v", sum, conn.RemoteAddr(), idnaToUnicode(cs.ServerName), err)
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
		log.Printf("ERR [%s] %s:%s ➔ %s|%s:%s %s: %v", sum, conn.RemoteAddr().Network(), conn.RemoteAddr(), idnaToUnicode(cs.ServerName), be.Mode, cs.NegotiatedProtocol, tag, err)
	}

	if be.http3Handler != nil && cs.NegotiatedProtocol == "h3" {
		// Creating a new http3 server for every request isn't great,
		// but it seems to be the only way to pass a context value to
		// the request.
		serv := &http3.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				req = req.WithContext(context.WithValue(req.Context(), connCtxKey, conn))
				be.http3Handler.ServeHTTP(w, req)
			}),
		}
		if err := serv.ServeQUICConn(qc); err != nil {
			reportErr(err, "ServeQUICConn")
		}
		return
	}

	if be.Mode == ModeQUIC {
		beConn, err := be.dialQUICBackend(ctx, cs.NegotiatedProtocol)
		if err != nil {
			qc.CloseWithError(quicBadGateway, "bad gateway")
			log.Printf("ERR [%s] %s:%s ➔ %s|%s:%s dialQUICBackend: %v", sum, conn.RemoteAddr().Network(), conn.RemoteAddr(), idnaToUnicode(cs.ServerName), be.Mode, cs.NegotiatedProtocol, err)
			return
		}
		defer beConn.Close()
		conn.SetAnnotation(internalConnKey, beConn)

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
				go be.handleQUICQUICStream(ctx, qc, qc.WrapStream(recvStream))
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
					be.handleQUICQUICStream(ctx, qc, qc.WrapStream(stream))
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
					be.handleQUICQUICStream(ctx, beConn, qc.WrapStream(recvStream))
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
					be.handleQUICQUICStream(ctx, beConn, qc.WrapStream(stream))
				}()
			}
		}()
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
			cc := qc.WrapStream(recvStream)
			cc.CopyAnnotationsFrom(conn)
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
			cc := qc.WrapStream(stream)
			cc.CopyAnnotationsFrom(conn)
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
		log.Printf("STR %s", formatConnDesc(conn))
		closeConnNeeded = false
		be.httpConnChan <- conn

	case ModeTCP, ModeTLS:
		intConn, err := be.dial(ctx, connProto(conn))
		if err != nil {
			p.recordEvent("dial error")
			log.Printf("ERR [-] %s:%s ➔  %q Dial: %v", conn.RemoteAddr().Network(), conn.RemoteAddr(), serverName, err)
			return
		}
		defer intConn.Close()
		setKeepAlive(intConn)

		conn.SetAnnotation(dialDoneKey, time.Now())
		conn.SetAnnotation(internalConnKey, intConn)
		if cc, ok := conn.Conn.(interface {
			SetBridgeAddr(string)
		}); ok {
			cc.SetBridgeAddr(intConn.RemoteAddr().Network() + ":" + intConn.RemoteAddr().String())
		}
		log.Printf("STR %s", formatConnDesc(conn))

		if err := be.bridgeConns(conn, intConn); err != nil {
			log.Printf("DBG %s %v", formatConnDesc(conn), err)
		}

		startTime := conn.Annotation(startTimeKey, time.Time{}).(time.Time)
		dialTime := conn.Annotation(dialDoneKey, time.Time{}).(time.Time)
		totalTime := time.Since(startTime).Truncate(time.Millisecond)

		log.Printf("END %s; Dial:%s Dur:%s Recv:%d Sent:%d", formatConnDesc(conn),
			dialTime.Sub(startTime).Truncate(time.Millisecond), totalTime,
			conn.BytesReceived(), conn.BytesSent())

	default:
		log.Printf("ERR [-] %s:%s: unhandled stream %q", conn.RemoteAddr().Network(), conn.RemoteAddr(), be.Mode)
	}
}

func (be *Backend) handleQUICQUICStream(ctx context.Context, dest *netw.QUICConn, conn *netw.Conn) {
	serverName := idnaToUnicode(connServerName(conn))
	qs, ok := conn.Conn.(*netw.QUICStream)
	if !ok {
		log.Printf("ERR [-] %s ➔  %q not a QUICStream", conn.RemoteAddr(), serverName)
		return
	}
	var intConn *netw.Conn
	if _, ok := qs.Stream.(*netw.ReceiveOnlyStream); ok {
		sendStream, err := dest.OpenUniStreamSync(ctx)
		if err != nil {
			be.recordEvent("openstream error")
			log.Printf("ERR [-] %s:%s ➔  %q OpenUniStreamSync: %v", conn.RemoteAddr().Network(), conn.RemoteAddr(), serverName, err)
			var appErr *quic.ApplicationError
			if errors.As(err, &appErr) {
				qs.CancelRead(quic.StreamErrorCode(appErr.ErrorCode))
			}
			return
		}
		intConn = dest.WrapStream(sendStream)
	} else {
		stream, err := dest.OpenStreamSync(ctx)
		if err != nil {
			be.recordEvent("openstream error")
			log.Printf("ERR [-] %s:%s ➔  %q OpenStreamSync: %v", conn.RemoteAddr().Network(), conn.RemoteAddr(), serverName, err)
			var appErr *quic.ApplicationError
			if errors.As(err, &appErr) {
				qs.CancelRead(quic.StreamErrorCode(appErr.ErrorCode))
			}
			return
		}
		intConn = dest.WrapStream(stream)
	}
	defer intConn.Close()

	now := time.Now()
	conn.SetAnnotation(startTimeKey, now)
	conn.SetAnnotation(dialDoneKey, now)
	conn.SetAnnotation(internalConnKey, intConn)

	desc := formatConnDesc(conn)
	log.Printf("STR %s", desc)

	if err := be.bridgeConns(conn, intConn); err != nil {
		log.Printf("DBG %s %v", desc, err)
	}

	startTime := conn.Annotation(startTimeKey, time.Time{}).(time.Time)
	dialTime := conn.Annotation(dialDoneKey, time.Time{}).(time.Time)
	totalTime := time.Since(startTime).Truncate(time.Millisecond)

	log.Printf("END %s; Dial:%s Dur:%s Recv:%d Sent:%d", desc,
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
	conn, err := qt.DialEarly(ctx, udpAddr, tc)
	if err != nil {
		return nil, err
	}
	return conn, nil
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
	return conn.WrapStream(s), nil
}

func (be *Backend) dialQUICBackend(ctx context.Context, proto string) (*netw.QUICConn, error) {
	var (
		addresses          = be.Addresses
		timeout            = be.ForwardTimeout
		insecureSkipVerify = be.InsecureSkipVerify
		serverName         = be.ForwardServerName
		rootCAs            = be.forwardRootCAs
		next               = &be.next
	)
	if id, ok := ctx.Value(ctxOverrideIDKey).(int); ok && id >= 0 && id < len(be.PathOverrides) {
		po := be.PathOverrides[id]
		addresses = po.Addresses
		timeout = po.ForwardTimeout
		insecureSkipVerify = po.InsecureSkipVerify
		serverName = po.ForwardServerName
		rootCAs = po.forwardRootCAs
		next = &po.next
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
				return errors.New("no certificate")
			}
			cert := cs.PeerCertificates[0]
			if m, ok := be.pkiMap[hex.EncodeToString(cert.AuthorityKeyId)]; ok {
				if m.IsRevoked(cert.SerialNumber) {
					return errRevoked
				}
			} else if len(cert.OCSPServer) > 0 {
				if err := be.ocspCache.VerifyChains(cs.VerifiedChains, cs.OCSPResponse); err != nil {
					be.recordEvent(fmt.Sprintf("backend X509 %s [%s] (OCSP:%v)", idnaToUnicode(cs.ServerName), cert.Subject, err))
					return errRevoked
				}
			}
			return nil
		},
	}

	var max int
	for {
		be.mu.Lock()
		sz := len(addresses)
		if max == 0 {
			max = sz
		}
		addr := addresses[*next]
		*next = (*next + 1) % sz
		be.mu.Unlock()

		ctx, cancel := context.WithTimeout(ctx, timeout)
		conn, err := be.dialQUIC(ctx, addr, tc)
		cancel()
		if err != nil {
			if max--; max > 0 {
				log.Printf("ERR dialQUIC %q: %v", addr, err)
				continue
			}
			return nil, err
		}
		return conn, nil
	}
}

func (be *Backend) http3Transport() http.RoundTripper {
	return &http3.RoundTripper{
		DisableCompression: true,
		Dial: func(ctx context.Context, _ string, _ *tls.Config, _ *quic.Config) (quic.EarlyConnection, error) {
			conn, err := be.dialQUICBackend(ctx, "h3")
			if err != nil {
				return nil, err
			}
			if c, ok := ctx.Value(connCtxKey).(*netw.Conn); ok {
				c.SetAnnotation(internalConnKey, conn)
			}
			return conn, nil
		},
	}
}
