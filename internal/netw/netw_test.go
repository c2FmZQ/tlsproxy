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

package netw_test

import (
	"crypto/tls"
	"io"
	"testing"

	"github.com/c2FmZQ/tlsproxy/internal/certmanager"
	"github.com/c2FmZQ/tlsproxy/internal/netw"
)

func TestConnWrapper(t *testing.T) {
	ca, err := certmanager.New("root-ca.example.com", t.Logf)
	if err != nil {
		t.Fatalf("certmanager.New: %v", err)
	}

	tc := ca.TLSConfig()
	tc.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		netw.SetAnnotation(hello.Conn, "SNI", hello.ServerName)
		return nil, nil
	}
	nl, err := netw.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("netw.Listen: %v", err)
	}
	l := tls.NewListener(nl, tc)
	defer l.Close()

	ch := make(chan string)
	go func() {
		tc := ca.TLSConfig()
		tc.ServerName = "foo.example.com"
		tc.RootCAs = ca.RootCACertPool()
		conn, err := tls.Dial("tcp", l.Addr().String(), tc)
		if err != nil {
			t.Errorf("[CLIENT] tls.Dial: %v", err)
			return
		}
		defer conn.Close()
		if _, err := conn.Write([]byte("HELLO!\n")); err != nil {
			t.Errorf("[CLIENT] conn.Write: %v", err)
			return
		}
		if err := conn.CloseWrite(); err != nil {
			t.Errorf("[CLIENT] conn.CloseWrite: %v", err)
			return
		}
		b, err := io.ReadAll(conn)
		if err != nil {
			t.Errorf("[CLIENT] io.ReadAll: %v", err)
			return
		}
		ch <- string(b)
	}()
	conn, err := l.Accept()
	if err != nil {
		t.Fatalf("[SERVER] Accept: %v", err)
	}
	tconn := conn.(*tls.Conn)
	nwconn := tconn.NetConn().(*netw.Conn)
	if err := tconn.Handshake(); err != nil {
		t.Fatalf("[SERVER] Handshake: %v", err)
	}
	if got, want := nwconn.Annotation("SNI", "").(string), "foo.example.com"; got != want {
		t.Errorf("[SERVER] Annotation(SNI) = %q, want %q", got, want)
	}
	b, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("[SERVER] io.ReadAll: %v", err)
	}
	if got, want := string(b), "HELLO!\n"; got != want {
		t.Errorf("[SERVER] Received %q, want %q", got, want)
	}
	conn.Write([]byte("Hello, Bye\n"))
	if got, want := nwconn.BytesSent(), int64(100); got < want {
		t.Errorf("[SERVER] BytesSent: %d, want >= %d", got, want)
	}
	if got, want := nwconn.BytesReceived(), int64(100); got < want {
		t.Errorf("[SERVER] BytesReceived: %d, want >= %d", got, want)
	}
	conn.Close()

	if got, want := <-ch, "Hello, Bye\n"; got != want {
		t.Errorf("[CLIENT] Received %q, want %q", got, want)
	}
}
