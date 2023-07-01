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

// Proxy is a simple TLS terminating proxy that uses letsencrypt to provide TLS
// encryption for any TCP servers.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/c2FmZQ/tlsproxy/internal"
)

// Version is set with -ldflags="-X main.Version=${VERSION}"
var Version = "dev"

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	configFile := flag.String("config", "", "The config file name")
	versionFlag := flag.Bool("v", false, "Show the version")
	flag.Parse()

	if *versionFlag {
		os.Stdout.WriteString(Version + " " + runtime.Version() + "\n")
		return
	}
	if *configFile == "" {
		log.Fatal("--config must be set")
	}
	log.Printf("INFO tlsproxy %s %s", Version, runtime.Version())
	cfg, err := internal.ReadConfig(*configFile)
	if err != nil {
		log.Fatalf("ERR %v", err)
	}
	proxy, err := internal.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	if err := proxy.Start(ctx); err != nil {
		log.Fatal(err)
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(30 * time.Second):
			}
			cfg, err := internal.ReadConfig(*configFile)
			if err != nil {
				log.Printf("ERR %v", err)
				continue
			}
			if err := proxy.Reconfigure(cfg); err != nil {
				log.Printf("ERR %v", err)
			}
		}
	}()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT)
	signal.Notify(ch, syscall.SIGTERM)
	sig := <-ch
	log.Printf("INFO Received signal %d (%s)", sig, sig)
}
