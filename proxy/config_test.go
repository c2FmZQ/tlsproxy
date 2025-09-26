// MIT License
//
// Copyright (c) 2023 TTBT Enterprises LLC
// Copyright (c) 2023 Robin Thellend <rthellend@rthellend.com>
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
	"testing"
	"time"

	"github.com/go-test/deep"
)

const demoCert = `-----BEGIN CERTIFICATE-----
MIIDHDCCAgSgAwIBAgIEM5G30zANBgkqhkiG9w0BAQsFADAeMRwwGgYDVQQDExNy
b290LWNhLmV4YW1wbGUuY29tMB4XDTIzMDYyNDAyNTIyMloXDTIzMDYyNDAzNTIy
MlowHjEcMBoGA1UEAxMTcm9vdC1jYS5leGFtcGxlLmNvbTCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAKJC2vmBdHwbzMIqWS6GIZOhk5FEtoIssLOUMwkS
zeLhDCrxsqiHxBOlzwZEgx6Knd9HhyuoHtuNl5AxL2btlgyk4dJ9MI2cOxrvZYeA
Bphh6OZx6hiMfz+cVcf7IpuXlc8juw3RVZ+JDtSq1w7JfjVe6NPhWxowr3v7XWSZ
00VB5ZAkGP1UXs5CjQAVFFfVPqn1hOdqoIzqW2BnKE6MORf4Kw9W4lr3WE4VW++Y
l/8W0yCKHzmURNLRCeGPAsgMlwwbs3eoyEWl1F7A7Hq0QCMpvSqA1HeCXj0fsTkS
zM/CBhPa5QtmWCzsmZJF7rB2gd75A725p0wQlHrxGxsTWIkCAwEAAaNiMGAwDgYD
VR0PAQH/BAQDAgIEMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFB5ey0fLDEXe
8kpdaCLMzehkrAYyMB4GA1UdEQQXMBWCE3Jvb3QtY2EuZXhhbXBsZS5jb20wDQYJ
KoZIhvcNAQELBQADggEBAGcuR8u4PiML7YZj7IhSkI4LBcglgARIXR6MLXAL4+sp
nF4rxqTI/rUGySJpo53IVYywjoRI5Xbe8nK+adYBOJn4PTs6E4a3mQt5lzQHqIPv
rjfaLLMkfP/nQXHkETpfFn8RXu0FJBXkN/MESttPVle6GObK8a7cvoiHTdfhXIIZ
XMHYmr+S/8GGos/Ps5Dpf7MlagwtQQmEXa0qjONu05GPEQXHMKGSK8mvJUMCWdFM
+aodrAnXId8L3GpKDr1jW/GSuyucebjTCVMazUkuIRA6ty/mAbm2KUv9UXniROj7
Au1hFufDZDNab/FH91MEj6hwIkT8blxhd2Kuj8r/+X8=
-----END CERTIFICATE-----
`

func TestReadConfig(t *testing.T) {
	got, err := ReadConfig("../examples/example-config.yaml")
	if err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}

	want := &Config{
		AcceptTOS: newPtr(true),
		Email:     newPtr("<your email address>"),
		HTTPAddr:  newPtr(":10080"),
		TLSAddr:   newPtr(":10443"),
		CacheDir:  got.CacheDir,
		MaxOpen:   got.MaxOpen,
		Backends: []*Backend{
			{
				ServerNames: Strings{
					"example.com",
					"www.example.com",
				},
				Addresses: Strings{
					"192.168.0.10:80",
					"192.168.0.11:80",
					"192.168.0.12:80",
				},
				ForwardRateLimit: 5,
				Mode:             "HTTP",
				ALPNProtos:       &Strings{"h2", "http/1.1"},
				ForwardTimeout:   30 * time.Second,
			},
			{
				ServerNames: Strings{
					"other.example.com",
				},
				Addresses: Strings{
					"192.168.1.100:443",
				},
				ForwardRateLimit:   5,
				Mode:               "HTTPS",
				ALPNProtos:         &Strings{"h2", "http/1.1"},
				InsecureSkipVerify: true,
				ForwardTimeout:     30 * time.Second,
			},
			{
				ServerNames: Strings{
					"secure.example.com",
				},
				Addresses: Strings{
					"192.168.2.200:443",
				},
				ForwardRateLimit: 5,
				Mode:             "TLS",
				ALPNProtos:       &Strings{"h2", "http/1.1"},
				ClientAuth: &ClientAuth{
					RootCAs: Strings{demoCert},
				},
				ForwardServerName: "secure-internal.example.com",
				ForwardRootCAs:    Strings{demoCert},
				ForwardTimeout:    30 * time.Second,
			},
			{
				ServerNames: Strings{
					"ssh.example.com",
				},
				Addresses: Strings{
					"192.168.8.20:22",
				},
				ForwardRateLimit: 5,
				Mode:             "TCP",
				ALPNProtos:       &Strings{"h2", "http/1.1"},
				ClientAuth: &ClientAuth{
					RootCAs: Strings{demoCert},
				},
				ForwardTimeout: 30 * time.Second,
			},
			{
				ServerNames: Strings{
					"c2fmzq-server.example.com",
				},
				Addresses: Strings{
					"192.168.3.30:5443",
				},
				ForwardRateLimit: 5,
				Mode:             "TLSPASSTHROUGH",
				ALPNProtos:       &Strings{"h2", "http/1.1"},
				ForwardTimeout:   30 * time.Second,
			},
			{
				ServerNames: Strings{
					"static.example.com",
				},
				ForwardRateLimit: 5,
				Mode:             "LOCAL",
				ALPNProtos:       &Strings{"h2", "http/1.1"},
				DocumentRoot:     "/var/www/htdocs",
				ForwardTimeout:   30 * time.Second,
			},
		},
	}
	adjustForQUIC(want)

	if diff := deep.Equal(want, got); diff != nil {
		t.Errorf("ReadConfig() = %#v, want %#v", got, want)
		for _, d := range diff {
			t.Logf("  %s", d)
		}
	}
}

func adjustForQUIC(cfg *Config) {
	cfg.EnableQUIC = newPtr(quicIsEnabled)
	if quicIsEnabled {
		for _, be := range cfg.Backends {
			if be.Mode == ModeHTTP || be.Mode == ModeHTTPS || be.Mode == ModeLocal {
				be.ALPNProtos = defaultALPNProtosPlusH3
			}
		}
	}
}

func TestReadPKIOIDCConfig(t *testing.T) {
	got, err := ReadConfig("../examples/example-pki-oidc-config.yaml")
	if err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}

	want := &Config{
		AcceptTOS: newPtr(true),
		Email:     newPtr("<your email address>"),
		HTTPAddr:  newPtr(":10080"),
		TLSAddr:   newPtr(":10443"),
		CacheDir:  got.CacheDir,
		MaxOpen:   got.MaxOpen,
		PKI: []*ConfigPKI{
			{
				Name:     "my-internal-ca",
				KeyType:  "rsa-2048",
				Endpoint: "https://pki.example.com/",
				Admins: Strings{
					"admin@example.com",
					"another-admin@example.com",
				},
				IssuingCertificateURLs: Strings{"https://pki.example.com/ca.crt"},
				CRLDistributionPoints:  Strings{"https://pki.example.com/ca.crl"},
				OCSPServer:             Strings{"https://pki.example.com/ocsp"},
			},
		},
		OIDCProviders: []*ConfigOIDC{
			{
				Name:         "google-oidc",
				DiscoveryURL: "https://accounts.google.com/.well-known/openid-configuration",
				RedirectURL:  "https://app.example.com/oauth2/callback",
				ClientID:     "YOUR_GOOGLE_CLIENT_ID",
				ClientSecret: "YOUR_GOOGLE_CLIENT_SECRET",
				Scopes:       Strings{"openid", "email", "profile"},
				Domain:       "example.com",
			},
		},
		Backends: []*Backend{
			{
				ServerNames: Strings{
					"secure.example.com",
				},
				Addresses: Strings{
					"192.168.2.200:443",
				},
				ForwardRateLimit: 5,
				Mode:             "TLS",
				ALPNProtos:       &Strings{"h2", "http/1.1"},
				ClientAuth: &ClientAuth{
					RootCAs: Strings{"my-internal-ca"},
					ACL:     &Strings{"SUBJECT:CN=client.example.com", "EMAIL:user@example.com"},
				},
				ForwardServerName: "secure-internal.example.com",
				ForwardRootCAs:    Strings{"my-internal-ca"},
				ForwardTimeout:    30 * time.Second,
			},
			{
				ServerNames: Strings{
					"app.example.com",
				},
				Addresses: Strings{
					"192.168.10.100:443",
				},
				ForwardRateLimit: 5,
				Mode:             "HTTPS",
				ALPNProtos:       &Strings{"h2", "http/1.1"},
				ClientAuth: &ClientAuth{
					RootCAs: Strings{"my-internal-ca"},
					ACL:     &Strings{"SUBJECT:CN=client.example.com", "EMAIL:user@example.com"},
				},
				SSO: &BackendSSO{
					Provider: "google-oidc",
					Rules: []*SSORule{
						{
							Paths: Strings{"/admin/"},
							ACL:   &Strings{"admin@example.com"},
						},
						{
							Paths:      Strings{"/"},
							ACL:        &Strings{"@example.com"},
							Exceptions: Strings{"/public/"},
						},
					},
					HTMLMessage: `<h1>Access Denied</h1>
<p>You do not have permission to access this resource.</p>
`,
				},
				ForwardTimeout: 30 * time.Second,
			},
			{
				ServerNames: Strings{
					"pki.example.com",
				},
				ForwardRateLimit: 5,
				Mode:             "LOCAL",
				ALPNProtos:       &Strings{"h2", "http/1.1"},
				SSO: &BackendSSO{
					Provider: "google-oidc",
					Rules: []*SSORule{
						{ACL: &Strings{"admin@example.com", "another-admin@example.com"}},
					},
				},
				ForwardTimeout: 30 * time.Second,
			},
		},
	}
	adjustForQUIC(want)

	if diff := deep.Equal(want, got); diff != nil {
		t.Errorf("ReadConfig() = %#v, want %#v", got, want)
		for _, d := range diff {
			t.Logf("  %s", d)
		}
	}
}

func TestReadPasskeyConfig(t *testing.T) {
	got, err := ReadConfig("../examples/example-passkey-config.yaml")
	if err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}

	want := &Config{
		AcceptTOS: newPtr(true),
		Email:     newPtr("<your email address>"),
		HTTPAddr:  newPtr(":10080"),
		TLSAddr:   newPtr(":10443"),
		CacheDir:  got.CacheDir,
		MaxOpen:   got.MaxOpen,
		OIDCProviders: []*ConfigOIDC{
			{
				Name:         "google-oidc-for-passkeys",
				DiscoveryURL: "https://accounts.google.com/.well-known/openid-configuration",
				RedirectURL:  "https://passkey-app.example.com/oauth2/callback",
				ClientID:     "YOUR_GOOGLE_CLIENT_ID",
				ClientSecret: "YOUR_GOOGLE_CLIENT_SECRET",
				Scopes:       Strings{"openid", "email", "profile"},
			},
		},
		PasskeyProviders: []*ConfigPasskey{
			{
				Name:             "my-passkey-provider",
				IdentityProvider: "google-oidc-for-passkeys",
				Endpoint:         "https://passkey-app.example.com/login",
				RefreshInterval:  24 * time.Hour,
			},
		},
		Backends: []*Backend{
			{
				ServerNames: Strings{
					"passkey-app.example.com",
				},
				Addresses: Strings{
					"192.168.10.101:443",
				},
				ForwardRateLimit: 5,
				Mode:             "HTTPS",
				ALPNProtos:       &Strings{"h2", "http/1.1"},
				SSO: &BackendSSO{
					Provider: "my-passkey-provider",
					Rules: []*SSORule{
						{ACL: &Strings{"@example.com"}},
					},
				},
				ForwardTimeout: 30 * time.Second,
			},
		},
	}
	adjustForQUIC(want)

	if diff := deep.Equal(want, got); diff != nil {
		t.Errorf("ReadConfig() = %#v, want %#v", got, want)
		for _, d := range diff {
			t.Logf("  %s", d)
		}
	}
}

func TestReadSSHCAConfig(t *testing.T) {
	got, err := ReadConfig("../examples/example-sshca-config.yaml")
	if err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}

	want := &Config{
		AcceptTOS: newPtr(true),
		Email:     newPtr("<your email address>"),
		HTTPAddr:  newPtr(":10080"),
		TLSAddr:   newPtr(":10443"),
		CacheDir:  got.CacheDir,
		MaxOpen:   got.MaxOpen,
		OIDCProviders: []*ConfigOIDC{
			{
				Name:         "google-oidc-for-sshca",
				DiscoveryURL: "https://accounts.google.com/.well-known/openid-configuration",
				RedirectURL:  "https://sshca.example.com/oauth2/callback",
				ClientID:     "YOUR_GOOGLE_CLIENT_ID",
				ClientSecret: "YOUR_GOOGLE_CLIENT_SECRET",
				Scopes:       Strings{"openid", "email"},
			},
		},
		SSHCertificateAuthorities: []*ConfigSSHCertificateAuthority{
			{
				Name:                       "my-ssh-ca",
				KeyType:                    "ed25519",
				PublicKeyEndpoint:          "https://sshca.example.com/ssh/ca.pub",
				CertificateEndpoint:        "https://sshca.example.com/ssh/issue",
				MaximumCertificateLifetime: 24 * time.Hour,
			},
		},
		Backends: []*Backend{
			{
				ServerNames: Strings{
					"sshca.example.com",
				},
				ForwardRateLimit: 5,
				Mode:             "LOCAL",
				ALPNProtos:       &Strings{"h2", "http/1.1"},
				SSO: &BackendSSO{
					Provider: "google-oidc-for-sshca",
					Rules: []*SSORule{
						{ACL: &Strings{"@example.com"}},
					},
				},
				DocumentRoot:   "/var/www/sshterm",
				ForwardTimeout: 30 * time.Second,
			},
		},
	}
	adjustForQUIC(want)

	if diff := deep.Equal(want, got); diff != nil {
		t.Errorf("ReadConfig() = %#v, want %#v", got, want)
		for _, d := range diff {
			t.Logf("  %s", d)
		}
	}
}

func TestReadSplitConfig(t *testing.T) {
	got, err := ReadConfig("testdata/testconfig.yaml")
	if err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}

	want := &Config{
		HTTPAddr: newPtr(":10080"),
		TLSAddr:  newPtr(":10443"),
		CacheDir: got.CacheDir,
		MaxOpen:  got.MaxOpen,
		Backends: []*Backend{
			{
				ServerNames: Strings{
					"example.com",
					"www.example.com",
				},
				Addresses: Strings{
					"192.168.0.10:80",
					"192.168.0.11:80",
					"192.168.0.12:80",
				},
				ForwardRateLimit: 5,
				Mode:             "HTTP",
				ALPNProtos:       &Strings{"h2", "http/1.1"},
				ForwardTimeout:   30 * time.Second,
			},
			{
				ServerNames: Strings{
					"other.example.com",
				},
				Addresses: Strings{
					"192.168.1.100:443",
				},
				ForwardRateLimit:   5,
				Mode:               "HTTPS",
				ALPNProtos:         &Strings{"h2", "http/1.1"},
				InsecureSkipVerify: true,
				ForwardTimeout:     30 * time.Second,
			},
		},
	}
	adjustForQUIC(want)

	if diff := deep.Equal(want, got); diff != nil {
		t.Errorf("ReadConfig() = %#v, want %#v", got, want)
		for _, d := range diff {
			t.Logf("  %s", d)
		}
	}
}
