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

// tlsproxy is a simple TLS terminating proxy that uses Let's Encrypt to provide
// TLS encryption for any TCP and HTTP servers.
//
// It can also act as a reverse HTTP proxy with optional user authentication
// with SAML, OpenID Connect, and/or passkeys.
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

	"github.com/c2FmZQ/tlsproxy/proxy"
)

// Version is set with -ldflags="-X main.Version=${VERSION}"
var Version = "dev"

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	configFile := flag.String("config", "", "The config file name.")
	versionFlag := flag.Bool("v", false, "Show the version.")
	passphraseFlag := flag.String("passphrase", os.Getenv("TLSPROXY_PASSPHRASE"), "The passphrase to encrypt the TLS keys on disk.")
	shutdownGraceFlag := flag.Duration("shutdown-grace-period", time.Minute, "The shutdown grace period.")
	testFlag := flag.Bool("use-ephemeral-certificate-manager", false, "Use an ephemeral certificate manager. This is for testing purposes only.")
	stdoutFlag := flag.Bool("stdout", false, "Log to STDOUT.")
	flag.Parse()

	if *versionFlag {
		os.Stdout.WriteString(Version + " " + runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH + "\n")
		return
	}
	if *stdoutFlag {
		log.SetOutput(os.Stdout)
	}
	if *configFile == "" {
		log.Fatal("--config must be set")
	}
	log.Printf("INF tlsproxy %s %s %s/%s", Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	cfg, err := proxy.ReadConfig(*configFile)
	if err != nil {
		log.Fatalf("ERR %v", err)
	}
	var p *proxy.Proxy
	if *testFlag {
		log.Print("WRN Using ephemeral certificate manager")
		p, err = proxy.NewTestProxy(cfg)
	} else {
		if *passphraseFlag == "" {
			log.Fatal("--passphrase or $TLSPROXY_PASSPHRASE must be set")
		}
		if !cfg.AcceptTOS {
			log.Fatal("acceptTOS must be set to true in the config file")
		}
		p, err = proxy.New(cfg, []byte(*passphraseFlag))
	}
	if err != nil {
		log.Fatalf("FATAL %v", err)
	}
	if err := p.Start(ctx); err != nil {
		log.Fatal(err)
	}
	go configLoop(ctx, p, *configFile)

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT)
	signal.Notify(ch, syscall.SIGTERM)
	sig := <-ch
	log.Printf("INF Received signal %d (%s)", sig, sig)

	ctx, canc := context.WithTimeout(ctx, *shutdownGraceFlag)
	defer canc()
	p.Shutdown(ctx)
}

func configLoop(ctx context.Context, p *proxy.Proxy, file string) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
		cfg, err := proxy.ReadConfig(file)
		if err != nil {
			log.Printf("ERR %v", err)
			continue
		}
		if err := p.Reconfigure(cfg); err != nil {
			log.Printf("ERR %v", err)
		}
	}
}
