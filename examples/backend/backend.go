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
	"flag"
	"fmt"
	"html"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/c2FmZQ/tlsproxy/certmanager"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/jwk"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr := flag.String("addr", "", "The TCP address to listen on.")
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

	server := &http.Server{
		Addr:      *addr,
		Handler:   newService(ctx, *jwksURL),
		TLSConfig: cm.TLSConfig(),
	}
	go server.ListenAndServeTLS("", "")

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT)
	signal.Notify(ch, syscall.SIGTERM)
	sig := <-ch
	log.Printf("INF Received signal %d (%s)", sig, sig)
	server.Shutdown(ctx)
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
	log.Printf("INF %s %s", req.Method, req.RequestURI)
	cookie, err := req.Cookie("TLSPROXYIDTOKEN")
	if err != nil {
		log.Printf("INF TLSPROXYIDTOKEN: %v", err)
		http.Error(w, "TLSPROXYIDTOKEN cookie is not set", http.StatusForbidden)
		return
	}

	var claims struct {
		Name      string `json:"name"`
		FirstName string `json:"firstname"`
		LastName  string `json:"lastname"`
		Picture   string `json:"picture"`
		jwt.RegisteredClaims
	}
	if _, err := jwt.ParseWithClaims(cookie.Value, &claims, s.getKey); err != nil {
		log.Printf("INF jwt.Parse: %v", err)
		http.Error(w, "invalid token", http.StatusForbidden)
		return
	}
	w.Header().Set("content-type", "text/html")
	fmt.Fprintln(w, "token is valid<br>")

	if fn := claims.FirstName; fn != "" {
		fmt.Fprintf(w, "<h1>Hello, %s</h1>\n", html.EscapeString(fn))
	}

	fmt.Fprintf(w, "EMAIL: %s<br>\n", html.EscapeString(claims.Subject))
	if name := claims.Name; name != "" {
		fmt.Fprintf(w, "NAME: %s<br>\n", html.EscapeString(name))
	}
	if pic := claims.Picture; pic != "" {
		fmt.Fprintf(w, "<img src=\"%s\"><br>\n", html.EscapeString(pic))
	}

	fmt.Fprintln(w, "<pre>TOKEN CLAIMS:")
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
}
