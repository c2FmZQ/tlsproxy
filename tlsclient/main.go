// MIT License
//
// Copyright (c) 2023 TTBT Enterprises LLC
// Copyright (c) 2023 Robin Thellend <rthellend@thellend.com>
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
	"crypto/tls"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"runtime"
)

// Version is set with -ldflags="-X main.Version=${VERSION}"
var Version = "dev"

func main() {
	versionFlag := flag.Bool("v", false, "Show the version.")
	key := flag.String("key", "", "A file that contains the TLS key to use.")
	cert := flag.String("cert", "", "A file that contains the TLS certificate to use.")
	alpn := flag.String("alpn", "", "The ALPN proto to request.")
	flag.Parse()

	if *versionFlag {
		os.Stdout.WriteString(Version + " " + runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH + "\n")
		return
	}
	if flag.NArg() != 1 || (*key == "") != (*cert == "") {
		os.Stderr.WriteString("Usage: tlsclient [-key=<keyfile> -cert=<certfile>] [-alpn=<proto>] host:port\n")
		os.Exit(1)
	}
	addr := flag.Arg(0)

	var certs []tls.Certificate
	if *key != "" && *cert != "" {
		c, err := tls.LoadX509KeyPair(*cert, *key)
		if err != nil {
			log.Fatalf("ERR: %v", err)
		}
		certs = append(certs, c)
	}

	var protos []string
	if *alpn != "" {
		protos = append(protos, *alpn)
	}
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		Certificates: certs,
		NextProtos:   protos,
	})
	if err != nil {
		log.Fatalf("ERR: %v", err)
	}
	go func() {
		if _, err := io.Copy(conn, os.Stdin); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Printf("ERR %v", err)
		}
		conn.CloseWrite()
	}()
	if _, err := io.Copy(os.Stdout, conn); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Printf("ERR %v", err)
	}
	conn.Close()
}
