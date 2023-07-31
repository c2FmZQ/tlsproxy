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
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"regexp"
	"strings"
	"time"

	"golang.org/x/exp/slices"

	"github.com/c2FmZQ/tlsproxy/proxy/internal/netw"
)

const (
	hstsHeader = "Strict-Transport-Security"
	hstsValue  = "max-age=2592000" // 30 days

	viaHeader           = "Via"
	hostHeader          = "Host"
	xForwardedForHeader = "X-Forwarded-For"
	clientCertHeader    = "Client-Cert"
)

var (
	commaRE = regexp.MustCompile(`, *`)
)

func (be *Backend) dial(proto string) (net.Conn, error) {
	if len(be.Addresses) == 0 {
		return nil, errors.New("no backend addresses")
	}
	var max int
	for {
		be.mu.Lock()
		sz := len(be.Addresses)
		if max == 0 {
			max = sz
		}
		addr := be.Addresses[be.next]
		be.next = (be.next + 1) % sz
		be.mu.Unlock()

		dialer := &net.Dialer{
			Timeout:   be.ForwardTimeout,
			KeepAlive: 30 * time.Second,
		}
		var c net.Conn
		var err error
		if be.Mode == ModeTLS || be.Mode == ModeHTTPS {
			var protos []string
			if proto != "" {
				protos = append(protos, proto)
			}
			tc := &tls.Config{
				InsecureSkipVerify: be.InsecureSkipVerify,
				ServerName:         be.ForwardServerName,
				NextProtos:         protos,
			}
			if be.forwardRootCAs != nil {
				tc.RootCAs = be.forwardRootCAs
			}
			c, err = tls.DialWithDialer(dialer, "tcp", addr, tc)
		} else {
			c, err = dialer.Dial("tcp", addr)
		}
		if err != nil {
			max--
			if max > 0 {
				log.Printf("ERR dial %q: %v", addr, err)
				continue
			}
			return nil, err
		}
		return c, nil
	}
}

func (be *Backend) authorize(subject string) error {
	if be.ClientACL == nil {
		return nil
	}
	if subject == "" || !slices.Contains(*be.ClientACL, subject) {
		return errAccessDenied
	}
	return nil
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

func (be *Backend) reverseProxy() *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Director: be.reverseProxyDirector,
		Transport: &cleanRoundTripper{
			serverNames: be.ServerNames,
			RoundTripper: &http.Transport{
				DialContext:           be.reverseProxyDial,
				DialTLSContext:        be.reverseProxyDial,
				MaxIdleConns:          100,
				IdleConnTimeout:       30 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
		},
		ModifyResponse: be.reverseProxyModifyResponse,
	}
}

func (be *Backend) reverseProxyDial(ctx context.Context, network, addr string) (net.Conn, error) {
	return be.dial("")
}

func (be *Backend) reverseProxyDirector(req *http.Request) {
	req.URL.Scheme = "https"
	if be.Mode == ModeHTTP {
		req.URL.Scheme = "http"
	}
	host := req.Host
	if host == "" {
		host = be.ServerNames[0]
	}
	req.URL.Host = host
	req.Host = host
	req.Header.Set(hostHeader, host)
	req.Header.Del(xForwardedForHeader)
	req.Header.Del(clientCertHeader)

	var via []string
	if v := req.Header.Get(viaHeader); v != "" {
		via = commaRE.Split(req.Header.Get(viaHeader), -1)
	}
	via = append(via, req.Proto+" "+req.Context().Value(connCtxKey).(*tls.Conn).LocalAddr().String())
	req.Header.Set(viaHeader, strings.Join(via, ", "))

	if req.TLS != nil && len(req.TLS.PeerCertificates) > 0 && be.AddClientCertHeader {
		req.Header.Set(clientCertHeader, base64.StdEncoding.EncodeToString(req.TLS.PeerCertificates[0].Raw))
	}
}

func (be *Backend) reverseProxyModifyResponse(resp *http.Response) error {
	req := resp.Request
	tlsConn := req.Context().Value(connCtxKey).(*tls.Conn)
	desc := formatConnDesc(tlsConn.NetConn().(*netw.Conn))
	var cl string
	if resp.ContentLength != -1 {
		cl = fmt.Sprintf(" content-length:%d", resp.ContentLength)
	}
	log.Printf("PRX %s ➔ %s %s ➔ status:%d%s", desc, req.Method, req.URL, resp.StatusCode, cl)

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
		msg := req.Header.Get(viaHeader)
		hdr := http.Header{}
		hdr.Set("content-type", "text/plain")
		hdr.Set("content-length", fmt.Sprintf("%d", len(msg)))
		return &http.Response{
			StatusCode:    http.StatusLoopDetected,
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        hdr,
			Body:          io.NopCloser(strings.NewReader(msg)),
			ContentLength: int64(len(msg)),
			Request:       req,
		}, nil
	}

	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if !slices.Contains(rt.serverNames, host) {
		if req.Body != nil {
			req.Body.Close()
		}
		msg := ""
		hdr := http.Header{}
		hdr.Set("content-type", "text/html")
		hdr.Set("content-length", fmt.Sprintf("%d", len(msg)))
		return &http.Response{
			StatusCode:    http.StatusMisdirectedRequest,
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        hdr,
			Body:          io.NopCloser(strings.NewReader(msg)),
			ContentLength: int64(len(msg)),
			Request:       req,
		}, nil
	}
	return rt.RoundTripper.RoundTrip(req)
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
