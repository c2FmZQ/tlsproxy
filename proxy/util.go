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
	"net"

	"golang.org/x/net/idna"

	"github.com/c2FmZQ/tlsproxy/proxy/internal/netw"
)

func netwConn(c net.Conn) *netw.Conn {
	switch c := c.(type) {
	case *tls.Conn:
		return netwConn(c.NetConn())
	case *netw.Conn:
		return c
	default:
		panic(c)
	}
}

func connServerNameIsSet(c net.Conn) bool {
	return netwConn(c).Annotation(serverNameKey, nil) != nil
}

func connServerName(c net.Conn) string {
	if v, ok := netwConn(c).Annotation(serverNameKey, "").(string); ok {
		return v
	}
	return ""
}

func connProto(c net.Conn) string {
	if v, ok := netwConn(c).Annotation(protoKey, "").(string); ok {
		return v
	}
	return ""
}

func connClientCert(c net.Conn) *x509.Certificate {
	if v, ok := netwConn(c).Annotation(clientCertKey, (*x509.Certificate)(nil)).(*x509.Certificate); ok {
		return v
	}
	return nil
}

func connBackend(c net.Conn) *Backend {
	if v, ok := netwConn(c).Annotation(backendKey, (*Backend)(nil)).(*Backend); ok {
		return v
	}
	return nil
}

func connMode(c net.Conn) string {
	if be := connBackend(c); be != nil {
		return be.Mode
	}
	return ""
}

func connIntConn(c net.Conn) net.Conn {
	if v, ok := netwConn(c).Annotation(internalConnKey, nil).(net.Conn); ok {
		return v
	}
	return nil
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
