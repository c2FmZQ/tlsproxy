// MIT License
//
// Copyright (c) 2024 TTBT Enterprises LLC
// Copyright (c) 2024 Robin Thellend <rthellend@rthellend.com>
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
	"crypto/tls"
	"io"
	"testing"

	"github.com/c2FmZQ/ech"
	"github.com/c2FmZQ/tlsproxy/certmanager"
)

func TestECH(t *testing.T) {
	ctx := t.Context()

	extCA, err := certmanager.New("root-ca.example.com", t.Logf)
	if err != nil {
		t.Fatalf("certmanager.New: %v", err)
	}
	intCA, err := certmanager.New("internal-ca.example.com", t.Logf)
	if err != nil {
		t.Fatalf("certmanager.New: %v", err)
	}
	truev := true
	proxy := newTestProxy(
		&Config{
			HTTPAddr:          "localhost:0",
			TLSAddr:           "localhost:0",
			EnableECH:         &truev,
			CacheDir:          t.TempDir(),
			MaxOpen:           100,
			DefaultServerName: "https.example.com",
		},
		extCA,
	)
	var echConfs []ech.Config
	for _, k := range proxy.echKeys {
		echConfs = append(echConfs, k.Config)
	}
	echConfigList, err := ech.ConfigList(echConfs)
	if err != nil {
		t.Fatalf("echConfigList: %v", err)
	}

	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}

	// Backend with TLS enabled.
	be1 := newTCPServer(t, ctx, "backend1", intCA)

	cfg := &Config{
		EnableECH:         &truev,
		MaxOpen:           100,
		DefaultServerName: "https.example.com",
		Backends: []*Backend{
			{
				ServerNames: []string{
					"https.example.com",
				},
				Addresses: []string{
					be1.listener.Addr().String(),
				},
				Mode:              "TLS",
				ForwardServerName: "blah",
				ForwardRootCAs:    []string{intCA.RootCAPEM()},
			},
		},
	}
	if err := proxy.Reconfigure(cfg); err != nil {
		t.Fatalf("proxy.Reconfigure: %v", err)
	}

	get := func(host string) (string, error) {
		return echGet(host, proxy.listener.Addr().String(), "Hello!\n", extCA, echConfigList)
	}

	for _, tc := range []struct {
		desc, host, want string
		protos           []string
		expError         bool
	}{
		{desc: "Hit backend1", host: "https.example.com", want: "Hello from backend1\n"},
	} {
		got, err := get(tc.host)
		if tc.expError != (err != nil) {
			t.Fatalf("%s: Got error %v, want %v. Body: %q err: %#v", tc.desc, (err != nil), tc.expError, got, err)
			continue
		}
		if err != nil {
			continue
		}
		if got != tc.want {
			t.Errorf("%s: Got %q, want %q", tc.desc, got, tc.want)
		}
	}
}

func echGet(name, addr, msg string, rootCA *certmanager.CertManager, configList []byte) (string, error) {
	name = idnaToASCII(name)
	c, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName:                     name,
		InsecureSkipVerify:             name == "",
		RootCAs:                        rootCA.RootCACertPool(),
		EncryptedClientHelloConfigList: configList,
	})
	if err != nil {
		return "", err
	}
	defer c.Close()
	if _, err := c.Write([]byte(msg)); err != nil {
		return "", err
	}
	b, err := io.ReadAll(c)
	return string(b), err
}
