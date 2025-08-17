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
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/c2FmZQ/ech"
	"github.com/pires/go-proxyproto"

	"github.com/c2FmZQ/tlsproxy/proxy/internal/netw"
)

func (be *Backend) incInFlight(delta int) int {
	be.state.mu.Lock()
	defer be.state.mu.Unlock()
	be.state.inFlight += delta
	if be.state.inFlight == 0 && be.state.shutdown && be.httpServer != nil {
		close(be.httpConnChan)
		be.httpServer = nil
	}
	return be.state.inFlight
}

func (be *Backend) close(ctx context.Context) {
	be.state.mu.Lock()
	defer be.state.mu.Unlock()
	if be.httpServer == nil {
		return
	}
	if ctx == nil {
		close(be.httpConnChan)
		go be.httpServer.Close()
		be.httpServer = nil
		if h3 := be.http3Server; h3 != nil {
			be.http3Server = nil
			go h3.Close()
		}
		return
	}
	go be.httpServer.Shutdown(ctx)
	be.state.shutdown = true
	if be.state.inFlight == 0 {
		close(be.httpConnChan)
		be.httpServer = nil
		if h3 := be.http3Server; h3 != nil {
			be.http3Server = nil
			go h3.Close()
		}
	}
}

func setIfNotNil[T any](a, b *T) {
	if b != nil {
		*a = *b
	}
}

func (be *Backend) dial(ctx context.Context, protos ...string) (net.Conn, error) {
	var (
		addresses          = be.Addresses
		mode               = be.Mode
		timeout            = be.ForwardTimeout
		insecureSkipVerify = be.InsecureSkipVerify
		serverName         = be.ForwardServerName
		rootCAs            = be.forwardRootCAs
		proxyProtoVersion  = be.proxyProtocolVersion
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
		mode = po.Mode
		timeout = po.ForwardTimeout
		insecureSkipVerify = po.InsecureSkipVerify
		serverName = po.ForwardServerName
		rootCAs = po.forwardRootCAs
		proxyProtoVersion = po.proxyProtocolVersion
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
		NextProtos:           protos,
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

	dialer := ech.Dialer[net.Conn]{
		RequireECH: echRequired,
		Resolver:   be.resolver,
		PublicName: echPublicName,
		DialFunc: func(ctx context.Context, network, addr string, tc *tls.Config) (net.Conn, error) {
			if mode == ModeQUIC {
				return be.dialQUICStream(ctx, addr, tc)
			}
			if echRequired && mode != ModeTLS && mode != ModeHTTPS {
				return nil, errors.New("require ECH for non TLS connection")
			}
			netDialer := &net.Dialer{
				KeepAlive: 30 * time.Second,
				Resolver: &net.Resolver{
					Dial: func(context.Context, string, string) (net.Conn, error) {
						return nil, errors.New("not using go resolver")
					},
				},
			}
			c, err := netDialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			setKeepAlive(c)
			if proxyProtoVersion > 0 {
				if err := writeProxyHeader(proxyProtoVersion, c, ctx.Value(connCtxKey).(anyConn)); err != nil {
					c.Close()
					return nil, err
				}
			}
			if mode != ModeTLS && mode != ModeHTTPS {
				return c, nil
			}
			conn := tls.Client(c, tc)
			if err := conn.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, err
			}
			return conn, nil
		},
	}
	be.state.mu.Lock()
	addr := strings.Join(slices.Concat(addresses[*next:], addresses[:*next]), ",")
	*next = (*next + 1) % len(addresses)
	be.state.mu.Unlock()

	network := "tcp"
	if mode == ModeQUIC {
		network = "udp"
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	c, err := dialer.Dial(ctx, network, addr, tc)
	cancel()
	if err != nil {
		return nil, err
	}
	wc := netw.NewConn(c)
	wc.OnClose(func() {
		be.outConns.remove(wc)
	})
	be.outConns.add(wc)
	wc.SetAnnotation(startTimeKey, time.Now())
	wc.SetAnnotation(modeKey, mode)
	wc.SetAnnotation(protoKey, strings.Join(protos, ","))
	if cc, ok := ctx.Value(connCtxKey).(anyConn); ok {
		wc.SetAnnotation(serverNameKey, connServerName(cc))
		annotatedConn(cc).SetAnnotation(internalConnKey, wc)
		if proxyProtoVersion > 0 {
			wc.SetAnnotation(proxyProtoKey, cc.RemoteAddr().Network()+":"+cc.RemoteAddr().String())
		}
	}

	return wc, nil
}

func writeProxyHeader(v byte, out io.Writer, in anyConn) error {
	header := proxyproto.HeaderProxyFromAddrs(v, in.RemoteAddr(), in.LocalAddr())
	header.Command = proxyproto.PROXY
	var tlvs []proxyproto.TLV
	if sn := connServerName(in); sn != "" {
		tlvs = append(tlvs, proxyproto.TLV{
			Type:  proxyproto.PP2_TYPE_AUTHORITY,
			Value: []byte(sn),
		})
	}
	if proto := connProto(in); proto != "" {
		tlvs = append(tlvs, proxyproto.TLV{
			Type:  proxyproto.PP2_TYPE_ALPN,
			Value: []byte(proto),
		})
	}
	if err := header.SetTLVs(tlvs); err != nil {
		return err
	}
	if _, err := header.WriteTo(out); err != nil {
		return err
	}
	return nil
}

func (be *Backend) authorize(cert *x509.Certificate) error {
	if be.ClientAuth == nil || be.ClientAuth.ACL == nil {
		return nil
	}
	if slices.ContainsFunc(*be.ClientAuth.ACL, func(v string) bool { return be.aclMatcher.CertMatches(v, cert) }) {
		return nil
	}
	return tlsAccessDenied
}

func (be *Backend) checkIP(addr net.Addr) error {
	var ip net.IP
	switch a := addr.(type) {
	case *net.TCPAddr:
		ip = a.IP
	case *net.UDPAddr:
		ip = a.IP
	default:
		return fmt.Errorf("can't get IP address from %T", addr)
	}
	if be.denyIPs != nil {
		for _, n := range *be.denyIPs {
			if n.Contains(ip) {
				return errAccessDenied
			}
		}
	}
	if be.allowIPs != nil {
		for _, n := range *be.allowIPs {
			if n.Contains(ip) {
				return nil
			}
		}
		return errAccessDenied
	}
	return nil
}

func (be *Backend) bridgeConns(client, server net.Conn) error {
	serverClose := true
	if be.ServerCloseEndsConnection != nil {
		serverClose = *be.ServerCloseEndsConnection
	}
	clientClose := false
	if be.ClientCloseEndsConnection != nil {
		clientClose = *be.ClientCloseEndsConnection
	}
	timeout := time.Minute
	if be.HalfCloseTimeout != nil {
		timeout = *be.HalfCloseTimeout
	}
	ch := make(chan error)
	go func() {
		ch <- forward(client, server, serverClose, timeout)
	}()
	var retErr error
	if err := forward(server, client, clientClose, timeout); err != nil && !errors.Is(err, net.ErrClosed) {
		retErr = fmt.Errorf("[ext➔ int]: %w", unwrapErr(err))
	}
	if err := <-ch; err != nil && !errors.Is(err, net.ErrClosed) {
		retErr = fmt.Errorf("[int➔ ext]: %w", unwrapErr(err))
	}
	return retErr
}

func forward(out net.Conn, in net.Conn, closeWhenDone bool, halfClosedTimeout time.Duration) error {
	buf := make([]byte, 8192)
	var readErr, writeErr error
	for {
		var n int
		n, readErr = in.Read(buf)
		if n > 0 {
			if _, writeErr = out.Write(buf[:n]); writeErr != nil {
				break
			}
		}
		if readErr != nil {
			break
		}
	}
	writeCanceled, readCanceled := quicEndCopy(out, in, &writeErr, &readErr)
	closeAll := func() {
		if !writeCanceled {
			out.Close()
		}
		if !readCanceled {
			in.Close()
		}
	}
	err := writeErr
	if readErr != nil && readErr != io.EOF {
		err = readErr
	}
	if err != nil || closeWhenDone {
		closeAll()
		return err
	}
	if !writeCanceled {
		if err := closeWrite(out); err != nil {
			closeAll()
			return nil
		}
	}
	if !readCanceled {
		if err := closeRead(in); err != nil {
			closeAll()
			return nil
		}
	}
	// At this point, the connection is either half closed, or fully closed.
	// If it is half closed, the remote end will get an EOF on the next
	// read. It can still send data back in the other direction. There are
	// some broken clients or network devices that never close their end of
	// the connection. So, we need to set a deadline to avoid keeping
	// connections open forever.
	out.SetReadDeadline(time.Now().Add(halfClosedTimeout))
	return nil
}

func closeWrite(c net.Conn) error {
	type closeWriter interface {
		CloseWrite() error
	}
	if cc, ok := c.(closeWriter); ok {
		return cc.CloseWrite()
	}
	if cc, ok := c.(*netw.Conn); ok {
		return closeWrite(cc.Conn)
	}
	return fmt.Errorf("unexpected type: %T", c)
}

func closeRead(c net.Conn) error {
	type closeReader interface {
		CloseRead() error
	}
	if cc, ok := c.(closeReader); ok {
		return cc.CloseRead()
	}
	if cc, ok := c.(*netw.Conn); ok {
		return closeRead(cc.Conn)
	}
	return nil
}
