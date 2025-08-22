// This is an example of a device authorization client.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"

	"github.com/mdp/qrterminal/v3"
	"golang.org/x/oauth2"
	"rsc.io/qr"
)

var (
	clientID      = flag.String("client-id", "", "The client ID")
	authEndpoint  = flag.String("auth-endpoint", "", "The authorization endpoint")
	tokenEndpoint = flag.String("token-endpoint", "", "The token endpoint")
	jsonOutput    = flag.Bool("json", false, "Show the token in JSON format")
	run           = flag.String("run", "", "The command to run with $TOKEN set in its environment")
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

	c := &oauth2.Config{
		ClientID: *clientID,
		Endpoint: oauth2.Endpoint{
			DeviceAuthURL: *authEndpoint,
			TokenURL:      *tokenEndpoint,
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	resp, err := c.DeviceAuth(ctx)
	if err != nil {
		log.Fatalf("DeviceAuth: %v", err)
	}
	url := resp.VerificationURIComplete
	if url == "" {
		url = resp.VerificationURI
	}
	qrterminal.GenerateHalfBlock(url, qr.L, os.Stdout)
	fmt.Printf("URL: %s\n", url)
	fmt.Printf("User Code: %s\n", resp.UserCode)

	token, err := c.DeviceAccessToken(ctx, resp)
	if err != nil {
		log.Fatalf("DeviceAccessToken: %v", err)
	}
	log.Print("Token received")

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
			log.Printf("Run: %v", err)
			if e, ok := err.(*exec.ExitError); ok && e.ProcessState != nil {
				os.Exit(e.ProcessState.ExitCode())
			}
		}
	}
}
