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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/pires/go-proxyproto"
	"golang.org/x/net/http2"

	"github.com/c2FmZQ/tlsproxy/proxy/internal/netw"
)

const (
	hstsHeader = "Strict-Transport-Security"
	hstsValue  = "max-age=2592000" // 30 days

	viaHeader           = "Via"
	hostHeader          = "Host"
	xForwardedForHeader = "X-Forwarded-For"
)

type ctxURLKeyType int

var (
	ctxURLKey        ctxURLKeyType = 1
	ctxOverrideIDKey ctxURLKeyType = 2

	commaRE = regexp.MustCompile(`, *`)
)

func (be *Backend) incInFlight(delta int) int {
	be.mu.Lock()
	defer be.mu.Unlock()
	be.inFlight += delta
	if be.inFlight == 0 && be.shutdown && be.httpServer != nil {
		close(be.httpConnChan)
		be.httpServer = nil
	}
	return be.inFlight
}

func (be *Backend) close(ctx context.Context) {
	be.mu.Lock()
	defer be.mu.Unlock()
	if be.httpServer == nil {
		return
	}
	if ctx == nil {
		be.httpServer.Close()
		close(be.httpConnChan)
		be.httpServer = nil
		return
	}
	go be.httpServer.Shutdown(ctx)
	be.shutdown = true
	if be.inFlight == 0 {
		close(be.httpConnChan)
		be.httpServer = nil
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
		next               = &be.next
	)
	if id, ok := ctx.Value(ctxOverrideIDKey).(int); ok && id >= 0 && id < len(be.PathOverrides) {
		po := be.PathOverrides[id]
		addresses = po.Addresses
		mode = po.Mode
		timeout = po.ForwardTimeout
		insecureSkipVerify = po.InsecureSkipVerify
		serverName = po.ForwardServerName
		rootCAs = po.forwardRootCAs
		proxyProtoVersion = po.proxyProtocolVersion
		next = &po.next
	}

	if len(addresses) == 0 {
		return nil, errors.New("no backend addresses")
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

		dialer := &net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}
		var c net.Conn
		var err error
		if mode == ModeTLS || mode == ModeHTTPS {
			tc := &tls.Config{
				InsecureSkipVerify: insecureSkipVerify,
				ServerName:         serverName,
				NextProtos:         protos,
				RootCAs:            rootCAs,
				VerifyConnection: func(cs tls.ConnectionState) error {
					if len(cs.PeerCertificates) == 0 {
						return errors.New("no certificate")
					}
					cert := cs.PeerCertificates[0]
					if m, ok := be.pkiMap[hex.EncodeToString(cert.AuthorityKeyId)]; ok && m.IsRevoked(cert.SerialNumber) {
						return errRevoked
					}
					return nil
				},
			}
			tlsDialer := &tls.Dialer{
				NetDialer: dialer,
				Config:    tc,
			}
			c, err = tlsDialer.DialContext(ctx, "tcp", addr)
		} else {
			c, err = dialer.DialContext(ctx, "tcp", addr)
		}
		if err != nil {
			max--
			if max > 0 {
				log.Printf("ERR dial %q: %v", addr, err)
				continue
			}
			return nil, err
		}
		if proxyProtoVersion > 0 {
			conn := ctx.Value(connCtxKey).(*tls.Conn)
			header := proxyproto.HeaderProxyFromAddrs(proxyProtoVersion, conn.RemoteAddr(), conn.LocalAddr())
			header.Command = proxyproto.PROXY
			var tlvs []proxyproto.TLV
			if sn := connServerName(conn); sn != "" {
				tlvs = append(tlvs, proxyproto.TLV{
					Type:  proxyproto.PP2_TYPE_AUTHORITY,
					Value: []byte(sn),
				})
			}
			if proto := connProto(conn); proto != "" {
				tlvs = append(tlvs, proxyproto.TLV{
					Type:  proxyproto.PP2_TYPE_ALPN,
					Value: []byte(proto),
				})
			}
			if err := header.SetTLVs(tlvs); err != nil {
				return nil, err
			}
			if _, err := header.WriteTo(c); err != nil {
				return nil, err
			}
		}
		return c, nil
	}
}

func (be *Backend) authorize(cert *x509.Certificate) error {
	if be.ClientAuth == nil || be.ClientAuth.ACL == nil {
		return nil
	}
	if subject := cert.Subject.String(); subject != "" && (slices.Contains(*be.ClientAuth.ACL, subject) || slices.Contains(*be.ClientAuth.ACL, "SUBJECT:"+subject)) {
		return nil
	}
	for _, v := range cert.DNSNames {
		if slices.Contains(*be.ClientAuth.ACL, "DNS:"+v) {
			return nil
		}
	}
	for _, v := range cert.EmailAddresses {
		if slices.Contains(*be.ClientAuth.ACL, "EMAIL:"+v) {
			return nil
		}
	}
	for _, v := range cert.URIs {
		if slices.Contains(*be.ClientAuth.ACL, "URI:"+v.String()) {
			return nil
		}
	}
	return errAccessDenied
}

func (be *Backend) checkIP(addr net.Addr) error {
	var ip net.IP
	switch a := addr.(type) {
	case *net.TCPAddr:
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

func (be *Backend) localHandlersAndAuthz(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		reqHost := hostFromReq(req)
		reqPath := req.URL.Path
		hi := slices.IndexFunc(be.localHandlers, func(h localHandler) bool {
			if h.host != "" && h.host != reqHost {
				return false
			}
			return h.path == reqPath || (h.matchPrefix && strings.HasPrefix(reqPath, h.path+"/"))
		})
		if hi >= 0 && be.localHandlers[hi].ssoBypass {
			be.localHandlers[hi].handler.ServeHTTP(w, req)
			return
		}
		if !be.enforceSSOPolicy(w, req) {
			return
		}
		if hi >= 0 && !be.localHandlers[hi].ssoBypass {
			be.localHandlers[hi].handler.ServeHTTP(w, req)
			return
		}
		if hi < 0 {
			pathSlash := reqPath + "/"
			if hi := slices.IndexFunc(be.localHandlers, func(h localHandler) bool {
				if h.host != "" && h.host != reqHost {
					return false
				}
				return pathSlash == h.path
			}); hi >= 0 {
				http.Redirect(w, req, pathSlash, http.StatusMovedPermanently)
				return
			}
		}
		if next == nil {
			http.NotFound(w, req)
			return
		}
		next.ServeHTTP(w, req)
	})
}

func (be *Backend) localHandler() http.Handler {
	return be.userAuthentication(be.localHandlersAndAuthz(nil))
}

func (be *Backend) reverseProxy() http.Handler {
	var rp http.Handler
	if len(be.Addresses) == 0 {
		rp = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			log.Printf("PRX %s ➔ %s %s ➔ status:%d (%q)", formatReqDesc(req), req.Method, req.URL, http.StatusNotFound, userAgent(req))
			http.NotFound(w, req)
		})
	} else {
		h1 := &httputil.ReverseProxy{
			Director: be.reverseProxyDirector,
			Transport: &cleanRoundTripper{
				serverNames: be.ServerNames,
				RoundTripper: &http.Transport{
					DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						return be.dial(ctx)
					},
					DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						return be.dial(ctx)
					},
					MaxIdleConns:          100,
					IdleConnTimeout:       30 * time.Second,
					ExpectContinueTimeout: 1 * time.Second,
				},
			},
			ModifyResponse: be.reverseProxyModifyResponse,
		}
		h2 := &httputil.ReverseProxy{
			Director: be.reverseProxyDirector,
			Transport: &cleanRoundTripper{
				serverNames: be.ServerNames,
				RoundTripper: &http2.Transport{
					DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
						return be.dial(ctx, "h2")
					},
					DisableCompression: true,
					AllowHTTP:          true,
					ReadIdleTimeout:    30 * time.Second,
					WriteByteTimeout:   30 * time.Second,
					CountError: func(errType string) {
						be.recordEvent("http2 client error: " + errType)
					},
				},
			},
			ModifyResponse: be.reverseProxyModifyResponse,
		}
		rp = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx := req.Context()
			host := req.Host
			if host == "" {
				host = connServerName(ctx.Value(connCtxKey).(*tls.Conn))
			}
			if !slices.Contains(be.ServerNames, host) {
				if req.Body != nil {
					req.Body.Close()
				}
				http.Error(w, "Misdirected Request", http.StatusMisdirectedRequest)
				return
			}

			req.URL.Scheme = "https"
			if be.Mode == ModeHTTP {
				req.URL.Scheme = "http"
			}
			req.URL.Host = host
			req.Header.Set(hostHeader, host)
			ctx = context.WithValue(ctx, ctxURLKey, req.URL.String())

			h := sha256.Sum256([]byte(req.URL.Hostname()))
			hh := hex.EncodeToString(h[:])
			req.URL.Host = hh
		L:
			for i, po := range be.PathOverrides {
				for _, prefix := range po.Paths {
					if !strings.HasPrefix(req.URL.Path, prefix) {
						continue
					}
					req.URL.Host = fmt.Sprintf("%s-%d", hh, i)
					ctx = context.WithValue(ctx, ctxOverrideIDKey, i)
					break L
				}
			}
			req = req.WithContext(ctx)

			if req.TLS != nil && req.TLS.NegotiatedProtocol == "h2" {
				h2.ServeHTTP(w, req)
			} else {
				h1.ServeHTTP(w, req)
			}
		})
	}
	return be.userAuthentication(be.localHandlersAndAuthz(rp))
}

func (be *Backend) reverseProxyDirector(req *http.Request) {
	req.Header.Del(xForwardedForHeader)
	req.Header.Del(xFCCHeader)

	var via []string
	if v := req.Header.Get(viaHeader); v != "" {
		via = commaRE.Split(req.Header.Get(viaHeader), -1)
	}
	via = append(via, req.Proto+" "+req.Context().Value(connCtxKey).(*tls.Conn).LocalAddr().String())
	req.Header.Set(viaHeader, strings.Join(via, ", "))

	if req.TLS != nil && len(req.TLS.PeerCertificates) > 0 && be.ClientAuth != nil && len(be.ClientAuth.AddClientCertHeader) > 0 {
		addXFCCHeader(req, be.ClientAuth.AddClientCertHeader)
	}
}

func (be *Backend) reverseProxyModifyResponse(resp *http.Response) error {
	req := resp.Request
	var cl string
	if resp.ContentLength != -1 {
		cl = fmt.Sprintf(" content-length:%d", resp.ContentLength)
	}
	url, _ := req.Context().Value(ctxURLKey).(string)
	log.Printf("PRX %s ➔ %s %s ➔ status:%d%s (%q)", formatReqDesc(req), req.Method, url, resp.StatusCode, cl, userAgent(req))

	if resp.StatusCode != http.StatusMisdirectedRequest && resp.Header.Get(hstsHeader) == "" {
		resp.Header.Set(hstsHeader, hstsValue)
	}
	return nil
}

// cleanRoundTripper detects loop with the via http header, and ensures that the
// request's Host value is valid before sending the request to the backend
// server. If the Host has an unexpected value, it returns a 421 immediately.
type cleanRoundTripper struct {
	serverNames []string
	http.RoundTripper
}

func (rt *cleanRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	hops := commaRE.Split(req.Header.Get(viaHeader), -1)
	_, me, _ := strings.Cut(hops[len(hops)-1], " ")
	hops = hops[:len(hops)-1]
	for _, via := range hops {
		_, via, _ = strings.Cut(via, " ")
		if via != me {
			continue
		}
		if req.Body != nil {
			req.Body.Close()
		}
		return makeResponse(req, http.StatusLoopDetected, nil, req.Header.Get(viaHeader)), nil
	}
	return rt.RoundTripper.RoundTrip(req)
}

func makeResponse(req *http.Request, statusCode int, header http.Header, body string) *http.Response {
	if header == nil {
		header = http.Header{}
	}
	header.Set("content-type", "text/plain")
	header.Set("content-length", fmt.Sprintf("%d", len(body)))
	return &http.Response{
		StatusCode:    statusCode,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}

func forward(out net.Conn, in net.Conn, closeWhenDone bool, halfClosedTimeout time.Duration) error {
	if _, err := io.Copy(out, in); err != nil || closeWhenDone {
		out.Close()
		in.Close()
		return err
	}
	if err := closeWrite(out); err != nil {
		out.Close()
		in.Close()
		return nil
	}
	if err := closeRead(in); err != nil {
		out.Close()
		in.Close()
		return nil
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
