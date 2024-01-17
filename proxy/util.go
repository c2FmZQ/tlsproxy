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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"

	"github.com/pires/go-proxyproto"
	"golang.org/x/net/idna"

	"github.com/c2FmZQ/tlsproxy/proxy/internal/netw"
)

func netwConn(c anyConn) *netw.Conn {
	switch c := c.(type) {
	case *tls.Conn:
		return netwConn(c.NetConn())
	case *netw.Conn:
		return c
	default:
		panic(c)
	}
}

type anyConn interface {
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	io.Closer
}

type annotatedConnection interface {
	anyConn
	Annotation(key string, defaultValue any) any
	SetAnnotation(key string, value any)
	BytesSent() int64
	BytesReceived() int64
	ByteRateSent() float64
	ByteRateReceived() float64
}

func annotatedConn(c anyConn) annotatedConnection {
	switch c := c.(type) {
	case *tls.Conn:
		return netwConn(c.NetConn())
	case *netw.Conn:
		return c
	case *netw.QUICConn:
		return c
	default:
		panic(c)
	}
}

func connServerNameIsSet(c anyConn) bool {
	return annotatedConn(c).Annotation(serverNameKey, nil) != nil
}

func connServerName(c anyConn) string {
	if v, ok := annotatedConn(c).Annotation(serverNameKey, "").(string); ok {
		return v
	}
	return ""
}

func connProto(c anyConn) string {
	if v, ok := annotatedConn(c).Annotation(protoKey, "").(string); ok {
		return v
	}
	return ""
}

func connClientCert(c anyConn) *x509.Certificate {
	if v, ok := annotatedConn(c).Annotation(clientCertKey, (*x509.Certificate)(nil)).(*x509.Certificate); ok {
		return v
	}
	return nil
}

func connBackend(c anyConn) *Backend {
	if v, ok := annotatedConn(c).Annotation(backendKey, (*Backend)(nil)).(*Backend); ok {
		return v
	}
	return nil
}

func connMode(c anyConn) string {
	if v, ok := annotatedConn(c).Annotation(modeKey, "").(string); ok && v != "" {
		return v
	}
	if be := connBackend(c); be != nil {
		return be.Mode
	}
	return ""
}

func connIntConn(c anyConn) net.Conn {
	if v, ok := annotatedConn(c).Annotation(internalConnKey, nil).(net.Conn); ok {
		return v
	}
	return nil
}

func connProxyProto(c anyConn) string {
	if v, ok := annotatedConn(c).Annotation(proxyProtoKey, nil).(string); ok {
		return v
	}
	return ""
}

func idnaToASCII(h string) string {
	if n, err := idna.Lookup.ToASCII(h); err == nil {
		return n
	}
	return h
}

func idnaToUnicode(h string) string {
	if n, err := idna.Lookup.ToUnicode(h); err == nil {
		return n
	}
	return h
}

func formatSize10[T float64 | int64](n T) string {
	if n > 1000000000 {
		return fmt.Sprintf("%.1f GB", float64(n)/1000000000)
	}
	if n > 1000000 {
		return fmt.Sprintf("%.1f MB", float64(n)/1000000)
	}
	if n > 1000 {
		return fmt.Sprintf("%.1f KB", float64(n)/1000)
	}
	return fmt.Sprintf("%d \u00A0B", int64(n)) // \u00A0 is &nbsp;
}

func isProxyProtoConn(c anyConn) bool {
	switch cc := c.(type) {
	case *tls.Conn:
		return isProxyProtoConn(cc.NetConn())
	case *netw.Conn:
		return isProxyProtoConn(cc.Conn)
	case *proxyproto.Conn:
		return true
	default:
		return false
	}
}

func localNetConn(c anyConn) net.Conn {
	switch cc := c.(type) {
	case *tls.Conn:
		return localNetConn(cc.NetConn())
	case *netw.Conn:
		return localNetConn(cc.Conn)
	case *proxyproto.Conn:
		return cc.Raw()
	case net.Conn:
		return cc
	default:
		panic(cc)
	}
}
