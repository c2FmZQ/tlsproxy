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

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/c2FmZQ/ech"
	"github.com/c2FmZQ/ech/quic"
	quicgo "github.com/quic-go/quic-go"
)

func generateCertAndPEM(t *testing.T, cn string) (tls.Certificate, *x509.Certificate, []byte, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	x509Cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return tlsCert, x509Cert, certPEM, keyPEM
}

func TestClientCertLoader(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")

	_, x509Cert1, certPEM1, keyPEM1 := generateCertAndPEM(t, "client1")
	if err := os.WriteFile(certFile, certPEM1, 0600); err != nil {
		t.Fatalf("WriteFile cert1: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM1, 0600); err != nil {
		t.Fatalf("WriteFile key1: %v", err)
	}
	t1 := time.Now().Add(-10 * time.Second).Truncate(time.Second)
	if err := os.Chtimes(certFile, t1, t1); err != nil {
		t.Fatalf("Chtimes cert1: %v", err)
	}
	if err := os.Chtimes(keyFile, t1, t1); err != nil {
		t.Fatalf("Chtimes key1: %v", err)
	}

	loader, err := clientCertLoader(certFile, keyFile)
	if err != nil {
		t.Fatalf("clientCertLoader: %v", err)
	}

	c1, err := loader(nil)
	if err != nil {
		t.Fatalf("loader(1): %v", err)
	}
	if !bytes.Equal(c1.Certificate[0], x509Cert1.Raw) {
		t.Fatalf("unexpected certificate 1")
	}

	// Second call without file modification returns the same cached pointer.
	c1Again, err := loader(nil)
	if err != nil {
		t.Fatalf("loader(1 again): %v", err)
	}
	if c1Again != c1 {
		t.Fatalf("expected cached certificate pointer to be reused")
	}

	// Update cert and key on disk with newer mtime.
	_, x509Cert2, certPEM2, keyPEM2 := generateCertAndPEM(t, "client2")
	if err := os.WriteFile(certFile, certPEM2, 0600); err != nil {
		t.Fatalf("WriteFile cert2: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM2, 0600); err != nil {
		t.Fatalf("WriteFile key2: %v", err)
	}
	t2 := t1.Add(5 * time.Second)
	if err := os.Chtimes(certFile, t2, t2); err != nil {
		t.Fatalf("Chtimes cert2: %v", err)
	}
	if err := os.Chtimes(keyFile, t2, t2); err != nil {
		t.Fatalf("Chtimes key2: %v", err)
	}

	c2, err := loader(nil)
	if err != nil {
		t.Fatalf("loader(2): %v", err)
	}
	if !bytes.Equal(c2.Certificate[0], x509Cert2.Raw) {
		t.Fatalf("expected reloaded certificate 2")
	}
}

func TestListenTLS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverTLSCert, serverX509Cert, _, _ := generateCertAndPEM(t, "localhost")
	pool := x509.NewCertPool()
	pool.AddCert(serverX509Cert)

	// Start a TLS echo server.
	serverLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
	})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer serverLn.Close()

	go func() {
		for {
			c, err := serverLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()

	dialer := ech.NewDialer()
	dialer.Resolver = ech.InsecureGoResolver()
	tc := &tls.Config{
		ServerName: "localhost",
		RootCAs:    pool,
	}
	dial := newTLSConnDialer(dialer, serverLn.Addr().String(), tc)

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer proxyLn.Close()
	go serveListener(ctx, proxyLn, dial)

	for i := range 3 {
		conn, err := net.Dial("tcp", proxyLn.Addr().String())
		if err != nil {
			t.Fatalf("net.Dial(%d): %v", i, err)
		}
		msg := []byte("hello over tls listen")
		if _, err := conn.Write(msg); err != nil {
			t.Fatalf("Write(%d): %v", i, err)
		}
		if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
			t.Fatalf("CloseWrite(%d): %v", i, err)
		}
		got, err := io.ReadAll(conn)
		if err != nil {
			t.Fatalf("ReadAll(%d): %v", i, err)
		}
		conn.Close()
		if !bytes.Equal(got, msg) {
			t.Fatalf("conn %d: got %q, want %q", i, got, msg)
		}
	}
}

func TestListenQUICStreamMultiplexing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverTLSCert, serverX509Cert, _, _ := generateCertAndPEM(t, "localhost")
	pool := x509.NewCertPool()
	pool.AddCert(serverX509Cert)

	// Start a QUIC echo server that counts connections and streams.
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer udpConn.Close()

	quicLn, err := quicgo.Listen(udpConn, &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
		NextProtos:   []string{"test"},
	}, nil)
	if err != nil {
		t.Fatalf("quic.Listen: %v", err)
	}
	defer quicLn.Close()

	var connCount atomic.Int32
	var streamCount atomic.Int32
	var lastServerConn atomic.Pointer[quicgo.Conn]

	go func() {
		for {
			qconn, err := quicLn.Accept(ctx)
			if err != nil {
				return
			}
			connCount.Add(1)
			lastServerConn.Store(qconn)
			go func() {
				for {
					s, err := qconn.AcceptStream(ctx)
					if err != nil {
						return
					}
					streamCount.Add(1)
					go func() {
						defer s.Close()
						io.Copy(s, s)
					}()
				}
			}()
		}
	}()

	dialer := quic.NewDialer(nil)
	dialer.Resolver = ech.InsecureGoResolver()
	tc := &tls.Config{
		ServerName: "localhost",
		NextProtos: []string{"test"},
		RootCAs:    pool,
	}
	dial, closeQUIC := newQUICStreamDialer(dialer, udpConn.LocalAddr().String(), tc)
	defer closeQUIC()

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer proxyLn.Close()
	go func() {
		if err := serveListener(ctx, proxyLn, dial); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("serveListener: %v", err)
		}
	}()

	// Send 3 TCP connections; all 3 should use 1 QUIC connection and 3 streams.
	for i := range 3 {
		conn, err := net.Dial("tcp", proxyLn.Addr().String())
		if err != nil {
			t.Fatalf("net.Dial(%d): %v", i, err)
		}
		msg := []byte("hello over quic stream")
		if _, err := conn.Write(msg); err != nil {
			t.Fatalf("Write(%d): %v", i, err)
		}
		if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
			t.Fatalf("CloseWrite(%d): %v", i, err)
		}
		got, err := io.ReadAll(conn)
		if err != nil {
			t.Fatalf("ReadAll(%d): %v", i, err)
		}
		conn.Close()
		if !bytes.Equal(got, msg) {
			t.Fatalf("conn %d: got %q, want %q", i, got, msg)
		}
	}

	if got := connCount.Load(); got != 1 {
		t.Fatalf("QUIC connCount = %d, want 1", got)
	}
	if got := streamCount.Load(); got != 3 {
		t.Fatalf("QUIC streamCount = %d, want 3", got)
	}

	// Close the QUIC connection from the server side and verify the next TCP connection reconnects.
	lastServerConn.Load().CloseWithError(0, "closing")
	// Wait briefly for the client to receive the CONNECTION_CLOSE frame.
	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("tcp", proxyLn.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial after close: %v", err)
	}
	msg := []byte("reconnected stream")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("Write after close: %v", err)
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("CloseWrite after close: %v", err)
	}
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("ReadAll after close: %v", err)
	}
	conn.Close()
	if !bytes.Equal(got, msg) {
		t.Fatalf("got %q, want %q", got, msg)
	}
	if got := connCount.Load(); got != 2 {
		t.Fatalf("QUIC connCount after reconnect = %d, want 2", got)
	}
	if got := streamCount.Load(); got != 4 {
		t.Fatalf("QUIC streamCount after reconnect = %d, want 4", got)
	}
}
