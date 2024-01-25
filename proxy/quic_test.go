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
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/c2FmZQ/tlsproxy/certmanager"
	"github.com/c2FmZQ/tlsproxy/proxy/internal/netw"
)

func TestQUICConnections(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	extCA, err := certmanager.New("root-ca.example.com", t.Logf)
	if err != nil {
		t.Fatalf("certmanager.New: %v", err)
	}
	intCA, err := certmanager.New("internal-ca.example.com", t.Logf)
	if err != nil {
		t.Fatalf("certmanager.New: %v", err)
	}

	be1 := newTCPServer(t, ctx, "TCP Backend", nil)
	be2 := newQUICServer(t, ctx, "QUIC Backend", []string{"h3", "imap"}, intCA)

	cfg := &Config{
		HTTPAddr: "localhost:0",
		TLSAddr:  "localhost:0",
		CacheDir: t.TempDir(),
		MaxOpen:  1000,
		Backends: []*Backend{
			// TCP backend
			{
				ServerNames: []string{
					"tcp.example.com",
				},
				Mode: "TCP",
				Addresses: []string{
					be1.listener.Addr().String(),
				},
				ALPNProtos: &[]string{
					"h2",
					"http/1.1",
				},
				ForwardRateLimit: 1000,
			},
			// QUIC backend
			{
				ServerNames: []string{
					"quic.example.com",
				},
				Mode: "QUIC",
				Addresses: []string{
					be2.listener.Addr().String(),
				},
				ALPNProtos: &[]string{
					"h3",
					"imap",
				},
				ForwardRootCAs:    []string{intCA.RootCAPEM()},
				ForwardServerName: "quic-internal.example.com",
				ForwardRateLimit:  1000,
			},
		},
	}
	proxy := newTestProxy(cfg, extCA)
	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}

	for _, tc := range []struct {
		desc, host, want string
		protos           []string
		expError         bool
		quic             bool
		datagram         bool
	}{
		{desc: "Hit TCP backend with TLS", host: "tcp.example.com", want: "Hello from TCP Backend\n", protos: []string{"http/1.1"}},
		{desc: "Hit TCP backend with QUIC", host: "tcp.example.com", want: "Hello from TCP Backend\n", protos: []string{"http/1.1"}, quic: true},
		{desc: "Hit TCP backend with TLS", host: "tcp.example.com", want: "Hello from TCP Backend\n", protos: []string{"h2"}},
		{desc: "Hit TCP backend with QUIC", host: "tcp.example.com", want: "Hello from TCP Backend\n", protos: []string{"h2"}, quic: true},
		{desc: "Hit QUIC backend with TLS h3", host: "quic.example.com", want: "Hello from QUIC Backend\n", protos: []string{"h3"}, expError: true},
		{desc: "Hit QUIC backend with TLS imap", host: "quic.example.com", want: "Hello from QUIC Backend\n", protos: []string{"imap"}},
		{desc: "Hit QUIC backend with QUIC h3", host: "quic.example.com", want: "Hello from QUIC Backend\n", protos: []string{"h3"}, quic: true},
		{desc: "Hit QUIC backend with QUIC imap", host: "quic.example.com", want: "Hello from QUIC Backend\n", protos: []string{"imap"}, quic: true},
		{desc: "Hit QUIC backend with QUIC datagram", host: "quic.example.com", want: "Received 7-byte datagram", protos: []string{"h3"}, datagram: true},
	} {
		var got string
		var err error
		if tc.datagram {
			got, err = quicDatagram(tc.host, proxy.quicTransport.(*netw.QUICTransport).Addr().String(), "Hello!\n", extCA, tc.protos)
		} else if tc.quic {
			got, err = quicGet(tc.host, proxy.quicTransport.(*netw.QUICTransport).Addr().String(), "Hello!\n", extCA, tc.protos)
		} else {
			got, _, err = tlsGet(tc.host, proxy.listener.Addr().String(), "Hello!\n", extCA, nil, tc.protos)
		}
		if tc.expError != (err != nil) {
			t.Errorf("%s: Got error %v, want %v", tc.desc, (err != nil), tc.expError)
			t.Logf("Body: %q err: %v", got, err)
			continue
		}
		if err != nil {
			continue
		}
		if got != tc.want {
			t.Errorf("%s: Got %q, want %q", tc.desc, got, tc.want)
		}
	}
}

func TestQUICMultiStream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ca, err := certmanager.New("root-ca.example.com", t.Logf)
	if err != nil {
		t.Fatalf("certmanager.New: %v", err)
	}

	tc := ca.TLSConfig()
	tc.NextProtos = []string{"foo"}

	ln, err := quic.ListenAddr("localhost:0", tc, &quic.Config{})
	if err != nil {
		t.Fatalf("ListenAddr: %v", err)
	}
	defer ln.Close()
	t.Logf("QUIC LISTENER: %s", ln.Addr())

	server := &quicNode{t: t, name: "SERVER"}
	client := &quicNode{t: t, name: "CLIENT"}

	ch := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept(ctx)
			if err != nil {
				t.Logf("Accept: %v", err)
				return
			}
			t.Logf("Accepted connection")
			server.run(conn)
			ch <- struct{}{}
		}
	}()

	cfg := &Config{
		HTTPAddr: "localhost:0",
		TLSAddr:  "localhost:0",
		CacheDir: t.TempDir(),
		MaxOpen:  1000,
		Backends: []*Backend{
			{
				ServerNames: []string{
					"quic.example.com",
				},
				Mode: "QUIC",
				Addresses: []string{
					ln.Addr().String(),
				},
				ALPNProtos: &[]string{
					"foo",
				},
				ForwardRootCAs:    []string{ca.RootCAPEM()},
				ForwardServerName: "quic-internal.example.com",
				ForwardRateLimit:  1000,
			},
		},
	}
	proxy := newTestProxy(cfg, ca)
	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}

	clientTC := &tls.Config{
		ServerName: "quic.example.com",
		RootCAs:    ca.RootCACertPool(),
		NextProtos: []string{"foo"},
	}

	dests := []string{
		ln.Addr().String(),
		proxy.quicTransport.(*netw.QUICTransport).Addr().String(),
	}

	for _, dest := range dests {
		conn, err := quic.DialAddr(ctx, dest, clientTC, &quic.Config{})
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		t.Logf("Dialed connection to %s", dest)
		client.run(conn)
		<-ch
		conn.CloseWithError(0, "done")

		if got, want := client.received, server.sent; !reflect.DeepEqual(got, want) {
			t.Errorf("Client received = %#v, want %#v", got, want)
		}
		if got, want := server.received, client.sent; !reflect.DeepEqual(got, want) {
			t.Errorf("Server received = %#v, want %#v", got, want)
		}

		client.reset()
		server.reset()
	}
}

func quicGet(name, addr, msg string, rootCA *certmanager.CertManager, protos []string) (string, error) {
	ctx := context.Background()
	tc := &tls.Config{
		ServerName: name,
		RootCAs:    rootCA.RootCACertPool(),
		NextProtos: protos,
	}

	conn, err := quic.DialAddr(ctx, addr, tc, &quic.Config{})
	if err != nil {
		return "", err
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return "", err
	}
	defer stream.Close()
	defer stream.CancelRead(0)
	if _, err := stream.Write([]byte(msg)); err != nil {
		return "", err
	}
	b, err := io.ReadAll(stream)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func quicDatagram(name, addr, msg string, rootCA *certmanager.CertManager, protos []string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	tc := &tls.Config{
		ServerName: name,
		RootCAs:    rootCA.RootCACertPool(),
		NextProtos: protos,
	}

	conn, err := quic.DialAddr(ctx, addr, tc, &quic.Config{EnableDatagrams: true})
	if err != nil {
		return "", err
	}
	go func() {
		for {
			conn.SendDatagram([]byte(msg))
			select {
			case <-ctx.Done():
				return
			case <-time.After(50 * time.Millisecond):
			}
		}
	}()
	b, err := conn.ReceiveDatagram(ctx)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

type quicServer struct {
	t        *testing.T
	listener *quic.Listener
}

func newQUICServer(t *testing.T, ctx context.Context, name string, protos []string, ca tcProvider) *quicServer {
	tc := ca.TLSConfig()
	tc.NextProtos = protos
	ln, err := quic.ListenAddr("localhost:0", tc, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatalf("[%s] ListenAddr: %v", name, err)
	}
	go func() {
		for {
			conn, err := ln.Accept(ctx)
			if err != nil {
				if errors.Is(err, quic.ErrServerClosed) || errors.Is(err, context.Canceled) {
					break
				}
				t.Logf("[%s] Accept: %v", name, err)
				continue
			}
			t.Logf("[%s] Received connection from %s", name, conn.RemoteAddr())
			go func() {
				for {
					stream, err := conn.AcceptStream(ctx)
					if err != nil {
						conn.CloseWithError(0x11, err.Error())
						break
					}
					go func(s quic.Stream) {
						fmt.Fprintf(s, "Hello from %s\n", name)
						s.CancelRead(0)
						s.Close()
					}(stream)
				}
			}()
			go func() {
				for {
					stream, err := conn.AcceptUniStream(ctx)
					if err != nil {
						conn.CloseWithError(0x11, err.Error())
						break
					}
					go func(s quic.ReceiveStream) {
						if _, err := io.ReadAll(s); err != nil {
							t.Logf("[%s] ReadAll: %v", name, err)
						}
						s.CancelRead(0)
					}(stream)
				}
			}()
			go func() {
				for {
					b, err := conn.ReceiveDatagram(ctx)
					if err != nil {
						conn.CloseWithError(0x11, err.Error())
						break
					}
					if err := conn.SendDatagram([]byte(fmt.Sprintf("Received %d-byte datagram", len(b)))); err != nil {
						t.Logf("[%s] SendDatagram: %v", name, err)
					}
				}
			}()
		}
	}()
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	return &quicServer{
		t:        t,
		listener: ln,
	}
}

type quicNode struct {
	t        *testing.T
	name     string
	mu       sync.Mutex
	sent     []string
	received []string
}

func (n *quicNode) reset() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sent = nil
	n.received = nil
}

func (n *quicNode) send(stream quic.SendStream, format string, args ...any) error {
	m := fmt.Sprintf(format, args...)
	if _, err := stream.Write([]byte(m)); err != nil {
		n.t.Errorf("[%s] Write: %v", n.name, err)
		return err
	}
	if err := stream.Close(); err != nil {
		n.t.Errorf("[%s] Close: %v", n.name, err)
		return err
	}
	n.mu.Lock()
	n.sent = append(n.sent, m)
	n.mu.Unlock()
	return nil
}

func (n *quicNode) recv(stream quic.ReceiveStream) error {
	b, err := io.ReadAll(stream)
	if err != nil {
		n.t.Errorf("[%s] ReadAll: %v", n.name, err)
		return err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.received = append(n.received, string(b))
	return nil
}

func (n *quicNode) run(conn quic.Connection) {
	n.t.Logf("MultiStreamNode[%s]", n.name)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			stream, err := conn.AcceptStream(conn.Context())
			if err != nil {
				n.t.Logf("[%s] AcceptStream: %v", n.name, err)
				break
			}
			ch := make(chan error)
			go func() {
				ch <- n.recv(stream)
			}()
			n.send(stream, "Hello accept bidi stream %02d from %s", i+1, n.name)
			<-ch
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			stream, err := conn.AcceptUniStream(conn.Context())
			if err != nil {
				n.t.Logf("[%s] AcceptUniStream: %v", n.name, err)
				break
			}
			n.recv(stream)
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			stream, err := conn.OpenStreamSync(conn.Context())
			if err != nil {
				n.t.Errorf("[%s] OpenStream: %v", n.name, err)
				break
			}
			ch := make(chan error)
			go func() {
				ch <- n.recv(stream)
			}()
			n.send(stream, "Hello open bidi stream %02d from %s", i+1, n.name)
			<-ch
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			stream, err := conn.OpenUniStreamSync(conn.Context())
			if err != nil {
				n.t.Errorf("[%s] OpenUniStream: %v", n.name, err)
				break
			}
			n.send(stream, "Hello open uni stream %02d from %s", i+1, n.name)
		}
	}()
	wg.Wait()

	n.mu.Lock()
	defer n.mu.Unlock()
	sort.Strings(n.sent)
	sort.Strings(n.received)
	for _, e := range n.received {
		n.t.Logf("[%s] received: %s", n.name, e)
	}
}
