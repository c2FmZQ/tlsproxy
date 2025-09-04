// This is an example of a device authorization client.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/mdp/qrterminal/v3"
	"golang.org/x/oauth2"
)

var (
	key  = flag.String("key", "", "(optional) A file that contains a TLS key to use to authenticate with the server.")
	cert = flag.String("cert", "", "(optional) A file that contains a TLS certificate to use to authenticate with the server.")

	clientID      = flag.String("client-id", "", "The client ID")
	scopes        = flag.String("scopes", "", "The scopes to request (comma separated)")
	authEndpoint  = flag.String("auth-endpoint", "", "The authorization endpoint")
	tokenEndpoint = flag.String("token-endpoint", "", "The token endpoint")

	qrCode  = flag.Bool("qr", false, "Show a QR code of the verification URL")
	browser = flag.String("browser", os.Getenv("BROWSER"), "The command to use to open the verification URL")

	jsonOutput = flag.Bool("json", false, "Show the token in JSON format")
	run        = flag.String("run", "", "The command to run with $TOKEN set in its environment")
)

func main() {
	flag.Parse()
	var missingFlags bool
	if *clientID == "" {
		fmt.Fprintf(os.Stderr, "--client-id must be set\n")
		missingFlags = true
	}
	if *authEndpoint == "" {
		fmt.Fprintf(os.Stderr, "--auth-endpoint must be set\n")
		missingFlags = true
	}
	if *tokenEndpoint == "" {
		fmt.Fprintf(os.Stderr, "--token-endpoint must be set\n")
		missingFlags = true
	}
	if missingFlags {
		os.Exit(1)
	}

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
	c := &oauth2.Config{
		ClientID: *clientID,
		Endpoint: oauth2.Endpoint{
			DeviceAuthURL: *authEndpoint,
			TokenURL:      *tokenEndpoint,
		},
		Scopes: scopeList,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if *key != "" && *cert != "" {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				c, err := tls.LoadX509KeyPair(*cert, *key)
				if err != nil {
					return nil, err
				}
				return &c, nil
			},
		}
		ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{
			Transport: transport,
		})
	}

	resp, err := c.DeviceAuth(ctx)
	if err != nil {
		log.Fatalf("DeviceAuth: %v", err)
	}
	url := resp.VerificationURIComplete
	if url == "" {
		url = resp.VerificationURI
	}
	if *qrCode {
		qrterminal.GenerateHalfBlock(url, qrterminal.L, os.Stdout)
	}
	if len(scopeList) > 0 {
		fmt.Printf("Requesting access to: %s\n", strings.Join(scopeList, ","))
	}
	fmt.Printf("Open this URL and enter %s as User Code to authorize access:\n\n  %s\n\n", resp.UserCode, url)

	if *browser != "" {
		cmd := exec.Command(*browser, url)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			log.Printf("%s: %v", *browser, err)
		}
	}

	token, err := c.DeviceAccessToken(ctx, resp)
	if err != nil {
		log.Fatalf("DeviceAccessToken: %v", err)
	}
	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(token)
	}
	if *run != "" {
		os.Setenv("TOKEN", token.AccessToken)
		cmd := exec.Command("/bin/sh", "-c", *run)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			if ee, ok := err.(*exec.ExitError); ok && ee.ProcessState != nil {
				os.Exit(ee.ProcessState.ExitCode())
			} else {
				log.Printf("Run: %v", err)
			}
		}
	}
}
