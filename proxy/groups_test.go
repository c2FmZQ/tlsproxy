// MIT License
//
// Copyright (c) 2025 TTBT Enterprises LLC
// Copyright (c) 2025 Robin Thellend <rthellend@rthellend.com>
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
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
)

func TestGroups(t *testing.T) {
	matcher := &ACLMatcher{
		groups: []*Group{
			{
				Name: "group1",
				Members: []*Member{
					{Email: "alice@example.com"},
					{X509: "SUBJECT:CN=alice"},
					{Group: "group2"},
					{Group: "group1"},
				},
			},
			{
				Name: "group2",
				Members: []*Member{
					{Email: "bob@example.com"},
					{X509: "EMAIL:bob@example.com"},
					{Group: "group2"},
				},
			},
			{
				Name: "group3",
				Members: []*Member{
					{Email: "alice@example.com"},
					{Email: "bob@example.com"},
					{Email: "carol@example.com"},
					{X509: "DNS:carol.example.com"},
				},
			},
			{
				Name: "group4",
				Members: []*Member{
					{Email: "@example.com"},
				},
			},
		},
	}

	certAlice := &x509.Certificate{
		Subject:        pkix.Name{CommonName: "alice"},
		EmailAddresses: []string{"alice@example.com"},
	}
	certBob := &x509.Certificate{
		Subject:        pkix.Name{CommonName: "bob"},
		EmailAddresses: []string{"bob@example.com"},
	}
	certCarol := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "carol"},
		DNSNames: []string{"carol.example.com"},
	}
	certMike := &x509.Certificate{
		Subject:        pkix.Name{CommonName: "mike"},
		EmailAddresses: []string{"mike@example.NET"},
	}

	for _, tc := range []struct {
		name     string
		group    string
		email    string
		cert     *x509.Certificate
		expected bool
	}{
		{name: "alice in group1", group: "group1", email: "alice@example.com", expected: true},
		{name: "alice not in group2", group: "group2", email: "alice@example.com", expected: false},
		{name: "alice in group3", group: "group3", email: "alice@example.com", expected: true},
		{name: "alice in group4", group: "group4", email: "alice@example.com", expected: true},
		{name: "bob in group1", group: "group1", email: "bob@example.com", expected: true},
		{name: "bob in group2", group: "group2", email: "bob@example.com", expected: true},
		{name: "bob in group3", group: "group3", email: "bob@example.com", expected: true},
		{name: "bob in group4", group: "group4", email: "bob@example.com", expected: true},
		{name: "carol not in group1", group: "group1", email: "carol@example.com", expected: false},
		{name: "carol not in group2", group: "group2", email: "carol@example.com", expected: false},
		{name: "carol in group3", group: "group3", email: "carol@example.com", expected: true},
		{name: "carol in group4", group: "group4", email: "carol@example.com", expected: true},
		{name: "malory not in group1", group: "group1", email: "malory@example.com", expected: false},
		{name: "malory not in group2", group: "group2", email: "malory@example.com", expected: false},
		{name: "malory not in group3", group: "group3", email: "malory@example.com", expected: false},
		{name: "malory in group4", group: "group4", email: "malory@example.com", expected: true},
		{name: "mike not in group1", group: "group1", email: "mike@example.NET", expected: false},
		{name: "mike not in group2", group: "group2", email: "mike@example.NET", expected: false},
		{name: "mike not in group3", group: "group3", email: "mike@example.NET", expected: false},
		{name: "mike not in group4", group: "group4", email: "mike@example.NET", expected: false},
		{name: "certAlice in group1", group: "group1", cert: certAlice, expected: true},
		{name: "certBob in group2", group: "group2", cert: certBob, expected: true},
		{name: "certAlice not in group2", group: "group2", cert: certAlice, expected: false},
		{name: "certCarol in group3", group: "group3", cert: certCarol, expected: true},
		{name: "certMike not in group1", group: "group1", cert: certMike, expected: false},
		{name: "certMike not in group2", group: "group2", cert: certMike, expected: false},
		{name: "certMike not in group3", group: "group3", cert: certMike, expected: false},
		{name: "certMike not in group4", group: "group4", cert: certMike, expected: false},
	} {
		if tc.email != "" {
			if got, want := matcher.EmailMatches([]string{tc.group}, tc.email), tc.expected; got != want {
				t.Errorf("[%s] EmailMatches(%q, %q) = %v, want %v", tc.name, tc.group, tc.email, got, want)
			}
		}
		if tc.cert != nil {
			if got, want := matcher.CertMatches([]string{tc.group}, tc.cert), tc.expected; got != want {
				t.Errorf("[%s] CertMatches(%q, %q) = %v, want %v", tc.name, tc.group, tc.cert.Subject, got, want)
			}
		}
	}
}
