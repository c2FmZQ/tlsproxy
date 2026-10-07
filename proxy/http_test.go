// MIT License
//
// Copyright (c) 2026 TTBT Enterprises LLC
// Copyright (c) 2026 Robin Thellend <rthellend@rthellend.com>
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
	"bufio"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestPlainHTTPServer(t *testing.T) {
	defer func(d time.Duration) { plainHTTPTimeout = d }(plainHTTPTimeout)
	plainHTTPTimeout = 500 * time.Millisecond

	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	s := startPlainHTTPServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("ok"))
	}), l, 2)
	defer s.Close()

	// Idle connections are closed by the server.
	idle := make([]net.Conn, 2)
	for i := range idle {
		if idle[i], err = net.Dial("tcp", l.Addr().String()); err != nil {
			t.Fatalf("net.Dial: %v", err)
		}
		defer idle[i].Close()
	}
	// The third connection is accepted after the idle ones time out.
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}

	for i, ic := range idle {
		ic.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadAll(ic); err != nil {
			t.Errorf("idle conn %d: ReadAll: %v", i, err)
		}
	}
}
