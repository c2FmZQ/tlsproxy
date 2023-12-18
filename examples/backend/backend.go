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

// backend is an example of a backend service.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"flag"
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/blend/go-sdk/envoyutil"
	"github.com/c2FmZQ/tlsproxy/certmanager"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/quic-go/quic-go/http3"
)

type userIdentity struct {
	Name      string `json:"name"`
	FirstName string `json:"firstname"`
	LastName  string `json:"lastname"`
	Email     string `json:"email"`
	Picture   string `json:"picture"`
	jwt.RegisteredClaims
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr := flag.String("addr", "", "The address to listen on.")
	enableH3 := flag.Bool("http3", false, "Enable QUIC and HTTP/3.")
	clientAuth := flag.Bool("client-auth", false, "Enable TLS client authentication.")
	jwksURL := flag.String("jwks-url", "", "The URL of the JWKS.")
	flag.Parse()

	if *addr == "" {
		log.Fatal("--addr must be set")
	}
	if *jwksURL == "" {
		log.Fatal("--jwks-url must be set")
	}

	cm, err := certmanager.New("root-ca.example.com", func(fmt string, args ...interface{}) {
		log.Printf("DBG CertManager: "+fmt, args...)
	})
	if err != nil {
		log.Fatal(err)
	}

	handler := newService(ctx, *jwksURL)
	server := &http.Server{
		Addr: *addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if *enableH3 {
				_, port, _ := net.SplitHostPort(req.Host)
				if port == "" {
					port = "443"
				}
				w.Header().Set("Alt-Svc", `h3=":`+port+`"; ma=3600;`)
			}
			handler.ServeHTTP(w, req)
		}),
		TLSConfig: cm.TLSConfig(),
	}
	if *clientAuth {
		server.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}
	go server.ListenAndServeTLS("", "")

	var h3 *http3.Server
	if *enableH3 {
		tc := cm.TLSConfig()
		tc.NextProtos = []string{"h3"}
		if *clientAuth {
			tc.ClientAuth = tls.RequireAndVerifyClientCert
		}
		h3 = &http3.Server{
			Addr:      *addr,
			TLSConfig: tc,
			Handler:   handler,
		}
		go h3.ListenAndServe()
	}

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT)
	signal.Notify(ch, syscall.SIGTERM)
	sig := <-ch
	log.Printf("INF Received signal %d (%s)", sig, sig)
	server.Shutdown(ctx)
	if h3 != nil {
		h3.Close()
	}
}

type service struct {
	ctx     context.Context
	ar      *jwk.AutoRefresh
	jwksURL string
}

func newService(ctx context.Context, jwksURL string) *service {
	ar := jwk.NewAutoRefresh(ctx)
	ar.Configure(jwksURL, jwk.WithRefreshInterval(60*time.Minute))
	return &service{
		ctx:     ctx,
		ar:      ar,
		jwksURL: jwksURL,
	}
}

func (s *service) getKey(token *jwt.Token) (interface{}, error) {
	set, err := s.ar.Fetch(s.ctx, s.jwksURL)
	if err != nil {
		return nil, err
	}
	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("kid is %T", token.Header["kid"])
	}
	if key, ok := set.LookupKeyID(kid); ok {
		var pubKey ecdsa.PublicKey
		if err := key.Raw(&pubKey); err != nil {
			return nil, err
		}
		return &pubKey, nil
	}

	return nil, fmt.Errorf("%s not found", kid)
}

func (s *service) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	log.Printf("INF %s %s %s", req.Proto, req.Method, req.RequestURI)

	var xfcc envoyutil.XFCC
	var claims userIdentity

	if h := req.Header.Get("x-forwarded-client-cert"); h != "" {
		var err error
		if xfcc, err = envoyutil.ParseXFCC(h); err != nil {
			http.Error(w, "invalid x-forwarded-client-cert header", http.StatusForbidden)
			return
		}
	}
	cookie, err := req.Cookie("TLSPROXYIDTOKEN")
	if err != nil {
		log.Printf("INF TLSPROXYIDTOKEN: %v", err)
		http.Error(w, "TLSPROXYIDTOKEN cookie is not set", http.StatusForbidden)
		return
	}
	if _, err := jwt.ParseWithClaims(cookie.Value, &claims, s.getKey, jwt.WithAudience(audienceFromReq(req))); err != nil {
		log.Printf("INF jwt.Parse: %v", err)
		http.Error(w, "invalid token", http.StatusForbidden)
		return
	}

	w.Header().Set("content-type", "text/html; charset=utf-8")

	fmt.Fprintln(w, "token is valid<br>")

	if pic := claims.Picture; pic != "" {
		fmt.Fprintf(w, "<img src=\"%s\"><br>\n", html.EscapeString(pic))
	}
	if name := claims.Name; name != "" {
		fmt.Fprintf(w, "<h1>Hello, %s</h1>\n", html.EscapeString(name))
	} else {
		fmt.Fprintf(w, "<h1>Hello, %s</h1>\n", html.EscapeString(claims.Email))
	}

	fmt.Fprintf(w, "EMAIL: %s<br>\n", html.EscapeString(claims.Email))
	if name := claims.Name; name != "" {
		fmt.Fprintf(w, "NAME: %s<br>\n", html.EscapeString(name))
	}

	fmt.Fprintln(w, "CLAIMS:<pre>")
	fmt.Fprintf(w, "  Issuer: %s\n", html.EscapeString(claims.Issuer))
	fmt.Fprintf(w, "  Subject: %s\n", html.EscapeString(claims.Subject))
	fmt.Fprintf(w, "  Audience: %s\n", html.EscapeString(strings.Join(claims.Audience, ",")))
	if claims.ExpiresAt != nil {
		fmt.Fprintf(w, "  ExpiresAt: %s\n", html.EscapeString(claims.ExpiresAt.String()))
	}
	if claims.NotBefore != nil {
		fmt.Fprintf(w, "  NotBefore: %s\n", html.EscapeString(claims.NotBefore.String()))
	}
	if claims.IssuedAt != nil {
		fmt.Fprintf(w, "  IssuedAt: %s\n", html.EscapeString(claims.IssuedAt.String()))
	}
	fmt.Fprintln(w, "</pre>")

	for _, xe := range xfcc {
		fmt.Fprintln(w, "XFCC:<pre>")
		if xe.By != "" {
			fmt.Fprintf(w, "By: %s\n", html.EscapeString(xe.By))
		}
		if xe.Hash != "" {
			fmt.Fprintf(w, "Hash: %s\n", html.EscapeString(xe.Hash))
		}
		if xe.Cert != "" {
			cert, _ := url.QueryUnescape(xe.Cert)
			fmt.Fprintf(w, "Cert: %s\n", html.EscapeString(cert))
		}
		if xe.Chain != "" {
			chain, _ := url.QueryUnescape(xe.Chain)
			fmt.Fprintf(w, "Chain: %s\n", html.EscapeString(chain))
		}
		if xe.Subject != "" {
			fmt.Fprintf(w, "Subject: %s\n", html.EscapeString(xe.Subject))
		}
		if xe.URI != "" {
			fmt.Fprintf(w, "URI: %s\n", html.EscapeString(xe.URI))
		}
		if len(xe.DNS) > 0 {
			fmt.Fprintf(w, "DNS: %s\n", html.EscapeString(strings.Join(xe.DNS, ",")))
		}
		fmt.Fprintln(w, "</pre>")
	}

	if req.TLS != nil && len(req.TLS.PeerCertificates) > 0 {
		fmt.Fprintf(w, "Client Certificate: %s<br>\n", req.TLS.PeerCertificates[0].Subject)
	}
	fmt.Fprintf(w, "Proto: %s<br>\n", req.Proto)
	fmt.Fprintf(w, "Via: %s\n", html.EscapeString(req.Header.Get("via")))
}

func audienceFromReq(req *http.Request) string {
	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return "https://" + host + "/"
}
