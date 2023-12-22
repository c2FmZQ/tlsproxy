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
		HTTPAddr: ":10080",
		TLSAddr:  ":10443",
		CacheDir: got.CacheDir,
		MaxOpen:  got.MaxOpen,
		Backends: []*Backend{
			{
				ServerNames: []string{
					"example.com",
					"www.example.com",
				},
				Addresses: []string{
					"192.168.0.10:80",
					"192.168.0.11:80",
					"192.168.0.12:80",
				},
				ForwardRateLimit: 5,
				Mode:             "HTTP",
				ALPNProtos:       &[]string{"h2", "http/1.1"},
				ForwardTimeout:   30 * time.Second,
			},
			{
				ServerNames: []string{
					"other.example.com",
				},
				Addresses: []string{
					"192.168.1.100:443",
				},
				ForwardRateLimit:   5,
				Mode:               "HTTPS",
				ALPNProtos:         &[]string{"h2", "http/1.1"},
				InsecureSkipVerify: true,
				ForwardTimeout:     30 * time.Second,
			},
			{
				ServerNames: []string{
					"secure.example.com",
				},
				Addresses: []string{
					"192.168.2.200:443",
				},
				ForwardRateLimit: 5,
				Mode:             "TLS",
				ALPNProtos:       &[]string{"h2", "http/1.1"},
				ClientAuth: &ClientAuth{
					RootCAs: []string{demoCert},
				},
				ForwardServerName: "secure-internal.example.com",
				ForwardRootCAs:    []string{demoCert},
				ForwardTimeout:    30 * time.Second,
			},
			{
				ServerNames: []string{
					"ssh.example.com",
				},
				Addresses: []string{
					"192.168.8.20:22",
				},
				ForwardRateLimit: 5,
				Mode:             "TCP",
				ALPNProtos:       &[]string{"h2", "http/1.1"},
				ClientAuth: &ClientAuth{
					RootCAs: []string{demoCert},
				},
				ForwardTimeout: 30 * time.Second,
			},
			{
				ServerNames: []string{
					"c2fmzq-server.example.com",
				},
				Addresses: []string{
					"192.168.3.30:5443",
				},
				ForwardRateLimit: 5,
				Mode:             "TLSPASSTHROUGH",
				ALPNProtos:       &[]string{"h2", "http/1.1"},
				ForwardTimeout:   30 * time.Second,
			},
		},
	}
	v := quicIsEnabled
	want.EnableQUIC = &v
	if quicIsEnabled {
		for _, be := range want.Backends {
			if be.Mode == ModeHTTP || be.Mode == ModeHTTPS {
				be.ALPNProtos = defaultALPNProtosPlusH3
			}
		}
	}

	if diff := deep.Equal(want, got); diff != nil {
		t.Errorf("ReadConfig() = %#v, want %#v", got, want)
		for _, d := range diff {
			t.Logf("  %s", d)
		}
	}
}
