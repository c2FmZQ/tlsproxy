// This is an example of a server that uses OpenID / OAUTH2 with TLSPROXY
// to authenticate users.
package main

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/c2FmZQ/tlsproxy/jwks"
	jwt "github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

var (
	serverAddr   = flag.String("server-addr", ":18080", "The TCP address of the server")
	configURL    = flag.String("openid-config", "", "The URL of the proxy's openid configuration")
	clientID     = flag.String("client-id", "", "The OAUTH2 client id")
	clientSecret = flag.String("client-secret", "", "The client secret")
	scopes       = flag.String("scopes", "openid,email,profile", "The list of scopes to request, comma-separated")

	//go:embed root.html
	rootEmbed []byte
)

const (
	stateCookieName = "OAUTH2_EXAMPLE_STATE_COOKIE"
)

func main() {
	flag.Parse()
	var missingFlags bool
	if *configURL == "" {
		log.Print("--openid-config must be set")
		missingFlags = true
	}
	if *clientID == "" {
		log.Print("--client-id must be set")
		missingFlags = true
	}
	if *clientSecret == "" {
		log.Print("--client-secret must be set")
		missingFlags = true
	}
	if missingFlags {
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var scopeList []string
	if *scopes != "" {
		for _, s := range strings.Split(*scopes, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			scopeList = append(scopeList, s)
		}
	}

	server := &Server{
		Addr:            *serverAddr,
		OpenIDConfigURL: *configURL,
		ClientID:        *clientID,
		ClientSecret:    *clientSecret,
		Scopes:          scopeList,
	}
	if err := server.Run(ctx); err != nil {
		log.Fatalf("server: %v", err)
	}
}

type Server struct {
	Addr            string
	OpenIDConfigURL string
	ClientID        string
	ClientSecret    string
	Scopes          []string

	ctx          context.Context
	openIDConfig struct {
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		UserinfoEndpoint      string `json:"userinfo_endpoint"`
		JWKSURI               string `json:"jwks_uri"`
	}
	remote *jwks.Remote
}

func (s *Server) Run(ctx context.Context) error {
	s.ctx = ctx
	resp, err := http.Get(s.OpenIDConfigURL)
	if err != nil {
		return fmt.Errorf("%s: %w", s.OpenIDConfigURL, err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&s.openIDConfig); err != nil {
		return fmt.Errorf("openid config: %w", err)
	}

	s.remote = jwks.NewRemote(nil, nil)
	s.remote.SetIssuers([]jwks.Issuer{
		{
			Issuer:  "https://login.example.com", // This needs to match the issuer in the token
			JWKSURI: s.openIDConfig.JWKSURI,
		},
	})
	go func() {
		<-ctx.Done()
		s.remote.Stop()
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, req *http.Request) {
		log.Printf("%s %s", req.Method, req.RequestURI)
		w.Write(rootEmbed)
	})

	mux.HandleFunc("/authurl", func(w http.ResponseWriter, req *http.Request) {
		log.Printf("%s %s", req.Method, req.RequestURI)
		cfg := s.config(req.Host)
		b := make([]byte, 12)
		if _, err := io.ReadFull(rand.Reader, b); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		state := hex.EncodeToString(b)

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store, no-cache")
		http.SetCookie(w, &http.Cookie{
			Name:     stateCookieName,
			Value:    state,
			HttpOnly: true,
		})
		json.NewEncoder(w).Encode(map[string]any{
			"url": cfg.AuthCodeURL(state, oauth2.SetAuthURLParam("nonce", state)),
		})
	})

	mux.HandleFunc("/redirect", func(w http.ResponseWriter, req *http.Request) {
		log.Printf("%s %s", req.Method, req.RequestURI)
		req.ParseForm()
		code := req.Form.Get("code")
		state := req.Form.Get("state")

		cookie, err := req.Cookie(stateCookieName)
		if err != nil || cookie.Value != state {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			return
		}
		cfg := s.config(req.Host)

		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "no-store, no-cache")
		token, err := cfg.Exchange(req.Context(), code)
		if err != nil {
			fmt.Fprintf(w, "OAUTH2 Error: %v", err)
			return
		}

		claims := make(jwt.MapClaims)
		if _, err := jwt.ParseWithClaims(token.AccessToken, &claims, s.getKey); err != nil {
			log.Printf("INF jwt.Parse: %v", err)
			fmt.Fprintf(w, "AccessToken: %v", err)
		}
		fmt.Fprintf(w, "\nAccessToken claims:\n")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(claims)

		if claims["nonce"] != state {
			fmt.Fprintf(w, "nonce value mismatch: %v != %q\n", claims["nonce"], state)
		}

		fmt.Fprintf(w, "\nGET %s\n", s.openIDConfig.UserinfoEndpoint)
		fmt.Fprintf(w, "Authorization: Bearer <AccessToken>\n\n")

		r, err := http.NewRequestWithContext(req.Context(), http.MethodGet, s.openIDConfig.UserinfoEndpoint, nil)
		if err != nil {
			fmt.Fprintf(w, "http.NewRequestWithContext: %v", err)
			return
		}
		r.Header.Set("Authorization", "Bearer "+token.AccessToken)
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			fmt.Fprintf(w, "%s: %v", s.openIDConfig.UserinfoEndpoint, err)
			return
		}
		defer resp.Body.Close()
		fmt.Fprintf(w, "content-type: %s\n\n", resp.Header.Get("content-type"))
		io.Copy(w, resp.Body)
	})

	hs := &http.Server{
		Addr:         *serverAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	return hs.ListenAndServe()
}

func (s *Server) config(host string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     s.ClientID,
		ClientSecret: s.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  s.openIDConfig.AuthorizationEndpoint,
			TokenURL: s.openIDConfig.TokenEndpoint,
		},
		RedirectURL: "https://" + host + "/redirect",
		Scopes:      s.Scopes,
	}
}

func (s *Server) getKey(token *jwt.Token) (interface{}, error) {
	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("kid is %T", token.Header["kid"])
	}
	return s.remote.GetKey(kid)
}
