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

// Command tlsproxy establishes a TLS connection with a TLS server and redirects
// the stream to its stdin and stdout.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/c2FmZQ/ech"
	"github.com/c2FmZQ/ech/quic"
	quicgo "github.com/quic-go/quic-go"
	"golang.org/x/crypto/ocsp"
)

// Version is set with -ldflags="-X main.Version=${VERSION}"
var Version = "dev"

type streamConn interface {
	io.ReadWriteCloser
	CloseWrite() error
	SetReadDeadline(time.Time) error
}

type quicStream struct {
	*quicgo.Stream
}

func (s quicStream) CloseWrite() error {
	return s.Stream.Close()
}

func (s quicStream) Close() error {
	s.Stream.CancelRead(0)
	return s.Stream.Close()
}

func clientCertLoader(certFile, keyFile string) (func(*tls.CertificateRequestInfo) (*tls.Certificate, error), error) {
	if certFile == "" || keyFile == "" {
		return nil, nil
	}
	var (
		mu          sync.Mutex
		cachedCert  *tls.Certificate
		certModTime time.Time
		keyModTime  time.Time
	)
	getCert := func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		mu.Lock()
		defer mu.Unlock()
		certStat, err := os.Stat(certFile)
		if err != nil {
			return nil, err
		}
		keyStat, err := os.Stat(keyFile)
		if err != nil {
			return nil, err
		}
		if cachedCert == nil || !certStat.ModTime().Equal(certModTime) || !keyStat.ModTime().Equal(keyModTime) {
			c, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return nil, err
			}
			cachedCert = &c
			certModTime = certStat.ModTime()
			keyModTime = keyStat.ModTime()
		}
		return cachedCert, nil
	}
	if _, err := getCert(nil); err != nil {
		return nil, err
	}
	return getCert, nil
}

func handleConn(ctx context.Context, localConn net.Conn, dial func(context.Context) (streamConn, error)) {
	defer localConn.Close()
	remoteConn, err := dial(ctx)
	if err != nil {
		log.Printf("ERR Dial: %v", err)
		return
	}
	defer remoteConn.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := io.Copy(remoteConn, localConn); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Printf("ERR Local->Remote: %v", err)
			localConn.Close()
			remoteConn.Close()
			return
		}
		if err := remoteConn.CloseWrite(); err != nil {
			localConn.Close()
			remoteConn.Close()
			return
		}
		remoteConn.SetReadDeadline(time.Now().Add(time.Minute))
	}()
	if _, err := io.Copy(localConn, remoteConn); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Printf("ERR Remote->Local: %v", err)
		localConn.Close()
		remoteConn.Close()
	} else if c, ok := localConn.(interface{ CloseWrite() error }); ok {
		if err := c.CloseWrite(); err != nil {
			localConn.Close()
			remoteConn.Close()
		} else {
			localConn.SetReadDeadline(time.Now().Add(time.Minute))
		}
	}
	<-done
}

func main() {
	versionFlag := flag.Bool("v", false, "Show the version.")
	key := flag.String("key", "", "A file that contains the TLS key to use.")
	cert := flag.String("cert", "", "A file that contains the TLS certificate to use.")
	alpn := flag.String("alpn", "", "The ALPN proto to request.")
	echFlag := flag.String("ech", "", "Use this ECH ConfigList.")
	echPublicName := flag.String("publicname", "", "Use this ECH Public Name to retrieve the ECH ConfigList.")
	useQUIC := flag.Bool("quic", false, "Use QUIC.")
	verifyOCSP := flag.Bool("ocsp", false, "Require stapled OCSP response.")
	insecureDNS := flag.Bool("insecuredns", false, "Use insecure DNS.")
	serverName := flag.String("servername", "", "The expected server name.")
	listenAddr := flag.String("listen", "", "Listen for TCP connections on this address instead of using stdin/stdout.")
	flag.Parse()

	if *versionFlag {
		os.Stdout.WriteString(Version + " " + runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH + "\n")
		return
	}
	if flag.NArg() != 1 || (*key == "") != (*cert == "") {
		os.Stderr.WriteString("Usage: tlsclient [-key=<keyfile> -cert=<certfile>] [-alpn=<proto>] [-ech=<configlist>] [-publicname=<ECH publicname>] [-quic] [-listen=<addr>] host:port\n")
		os.Exit(1)
	}
	addr := flag.Arg(0)

	getClientCert, err := clientCertLoader(*cert, *key)
	if err != nil {
		log.Fatalf("ERR: %v", err)
	}

	var protos []string
	if *alpn != "" {
		protos = append(protos, *alpn)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		port = "443"
	}
	target := net.JoinHostPort(host, port)

	if *serverName == "" {
		*serverName = host
	}
	tc := &tls.Config{
		GetClientCertificate: getClientCert,
		NextProtos:           protos,
		ServerName:           *serverName,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if !*verifyOCSP {
				return nil
			}
			if len(cs.OCSPResponse) == 0 {
				return errors.New("no ocsp response")
			}
			// Use the verified chain, not the certs sent by the server.
			if len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
				return errors.New("no verified chain")
			}
			chain := cs.VerifiedChains[0]
			cert, issuer := chain[0], chain[0]
			if len(chain) > 1 {
				issuer = chain[1]
			}
			resp, err := ocsp.ParseResponseForCert(cs.OCSPResponse, cert, issuer)
			if err != nil {
				return err
			}
			now := time.Now()
			// The response must be signed by the issuer or by a
			// delegated responder (RFC 6960 section 4.2.2.2).
			if rc := resp.Certificate; rc != nil && !rc.Equal(issuer) {
				if err := rc.CheckSignatureFrom(issuer); err != nil {
					return fmt.Errorf("ocsp responder certificate signature: %w", err)
				}
				if !slices.Contains(rc.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning) {
					return errors.New("ocsp responder is not authorized")
				}
				if now.Before(rc.NotBefore) || now.After(rc.NotAfter) {
					return errors.New("ocsp responder certificate is expired or not yet valid")
				}
			}
			if !resp.NextUpdate.IsZero() {
				if now.After(resp.NextUpdate) {
					return errors.New("ocsp response is expired")
				}
			} else if now.Sub(resp.ThisUpdate) > 24*time.Hour {
				return errors.New("ocsp response without NextUpdate is too old")
			}
			if resp.ThisUpdate.After(now.Add(5 * time.Minute)) {
				return errors.New("ocsp response is not yet valid")
			}
			if resp.Status != ocsp.Good {
				return errors.New("ocsp response status is not good")
			}
			return nil
		},
	}
	if *echFlag != "" {
		configList, err := base64.StdEncoding.DecodeString(*echFlag)
		if err != nil {
			log.Fatalf("ERR: --ech decoding error: %v", err)
		}
		tc.EncryptedClientHelloConfigList = configList
	}

	resolver := ech.DefaultResolver
	if *insecureDNS {
		resolver = ech.InsecureGoResolver()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var dial func(context.Context) (streamConn, error)
	if *useQUIC {
		dialer := quic.NewDialer(nil)
		dialer.RequireECH = *echFlag != "" || *echPublicName != ""
		dialer.PublicName = *echPublicName
		dialer.Resolver = resolver
		var closeConn func()
		dial, closeConn = newQUICStreamDialer(dialer, target, tc)
		defer closeConn()
	} else {
		dialer := ech.NewDialer()
		dialer.RequireECH = *echFlag != "" || *echPublicName != ""
		dialer.PublicName = *echPublicName
		dialer.Resolver = resolver
		dial = newTLSConnDialer(dialer, target, tc)
	}

	if *listenAddr != "" {
		ln, err := net.Listen("tcp", *listenAddr)
		if err != nil {
			log.Fatalf("ERR Listen: %v", err)
		}
		defer ln.Close()
		fmt.Fprintf(os.Stderr, "Listening on %s\n", ln.Addr())
		if err := serveListener(ctx, ln, dial); err != nil {
			log.Fatalf("ERR Accept: %v", err)
		}
		return
	}

	conn, err := dial(ctx)
	if err != nil {
		log.Fatalf("ERR Dial: %v", err)
	}
	defer conn.Close()
	go func() {
		if _, err := io.Copy(conn, os.Stdin); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Printf("ERR Stdin: %v", err)
		}
		conn.CloseWrite()
	}()
	if _, err := io.Copy(os.Stdout, conn); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Printf("ERR Conn: %v", err)
	}
}

func newQUICStreamDialer(dialer *ech.Dialer[*quicgo.Conn], target string, tc *tls.Config) (func(context.Context) (streamConn, error), func()) {
	var (
		mu       sync.Mutex
		quicConn *quicgo.Conn
	)
	closeConn := func() {
		mu.Lock()
		defer mu.Unlock()
		if quicConn != nil {
			quicConn.CloseWithError(0, "")
			quicConn = nil
		}
	}
	getConn := func(ctx context.Context, failedConn *quicgo.Conn) (*quicgo.Conn, error) {
		mu.Lock()
		defer mu.Unlock()
		if failedConn != nil && quicConn == failedConn {
			quicConn.CloseWithError(0, "")
			quicConn = nil
		}
		if quicConn != nil && quicConn.Context().Err() == nil {
			return quicConn, nil
		}
		conn, err := dialer.Dial(ctx, "udp", target, tc)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(os.Stderr, "Connected to %s\n", target)
		quicConn = conn
		return quicConn, nil
	}
	dial := func(ctx context.Context) (streamConn, error) {
		conn, err := getConn(ctx, nil)
		if err != nil {
			return nil, err
		}
		stream, err := conn.OpenStreamSync(ctx)
		if err != nil {
			conn, err = getConn(ctx, conn)
			if err != nil {
				return nil, err
			}
			stream, err = conn.OpenStreamSync(ctx)
			if err != nil {
				return nil, err
			}
		}
		return quicStream{stream}, nil
	}
	return dial, closeConn
}

func newTLSConnDialer(dialer *ech.Dialer[*tls.Conn], target string, tc *tls.Config) func(context.Context) (streamConn, error) {
	return func(ctx context.Context) (streamConn, error) {
		conn, err := dialer.Dial(ctx, "tcp", target, tc)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(os.Stderr, "Connected to %s\n", target)
		return conn, nil
	}
}

func serveListener(ctx context.Context, ln net.Listener, dial func(context.Context) (streamConn, error)) error {
	for {
		localConn, err := ln.Accept()
		if err != nil {
			return err
		}
		go handleConn(ctx, localConn, dial)
	}
}
