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
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/c2FmZQ/tlsproxy/certmanager"
)

func TestStaticFiles(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ca, err := certmanager.New("root-ca.example.com", t.Logf)
	if err != nil {
		t.Fatalf("certmanager.New: %v", err)
	}

	docRoot := t.TempDir()
	type testType struct {
		host    string
		name    string
		content string
	}
	testFiles := []testType{
		{"www.example.com", "index.html", "hello"},
		{"www.example.com", "foo.html", "foo"},
		{"www.example.com", "foo/index.html", "hi"},
		{"www.example.com", "foo/bar.html", "bar"},
		{"www.example.com", "foo/bar/bar", "barbar"},
		{"xyz.example.com", "index.html", "XYZ"},
	}
	for _, f := range testFiles {
		fname := filepath.Join(docRoot, f.host, f.name)
		os.MkdirAll(filepath.Dir(fname), 0o755)
		if err := os.WriteFile(fname, []byte(f.content), 0o644); err != nil {
			t.Fatalf("os.WriteFile(%s): %v", f.name, err)
		}
	}
	os.MkdirAll(filepath.Join(docRoot, ".git"), 0o755)
	if err := os.WriteFile(filepath.Join(docRoot, ".git", "config"), []byte("..."), 0o644); err != nil {
		t.Fatalf("os.WriteFile(.git/config): %v", err)
	}

	proxy := newTestProxy(
		&Config{
			HTTPAddr: "localhost:0",
			TLSAddr:  "localhost:0",
			CacheDir: t.TempDir(),
			MaxOpen:  100,
			Backends: []*Backend{
				{
					ServerNames: []string{
						"www.example.com",
					},
					Mode:         "LOCAL",
					DocumentRoot: filepath.Join(docRoot, "www.example.com"),
				},
				{
					ServerNames: []string{
						"xyz.example.com",
					},
					Mode:         "HTTP",
					DocumentRoot: filepath.Join(docRoot, "xyz.example.com"),
					PathOverrides: []*PathOverride{
						{
							Paths: []string{
								"/abc/",
							},
							DocumentRoot: filepath.Join(docRoot, "www.example.com"),
						},
					},
				},
				{
					ServerNames: []string{
						"aaa.example.com",
					},
					Mode: "HTTP",
				},
			},
		},
		ca,
	)
	if err := proxy.Start(ctx); err != nil {
		t.Fatalf("proxy.Start: %v", err)
	}
	defer proxy.Stop()

	get := func(urlToGet string) (int, string) {
		u, err := url.Parse(urlToGet)
		if err != nil {
			t.Fatalf("%q: %v", urlToGet, err)
		}
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{
			RootCAs: ca.RootCACertPool(),
		}
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", proxy.listener.Addr().String())
		}
		client := http.Client{
			Transport: transport,
		}
		req := &http.Request{
			Method: "GET",
			URL:    u,
			Host:   u.Host,
			Header: make(http.Header),
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: get failed: %v", urlToGet, err)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("%s: body read: %v", urlToGet, err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Fatalf("%s: body close: %v", urlToGet, err)
		}
		return resp.StatusCode, string(body)
	}

	testFiles = append(testFiles,
		testType{"www.example.com", "", "hello"},
		testType{"www.example.com", "index.html/", "hello"},
		testType{"www.example.com", "index.html/.", "hello"},
		testType{"www.example.com", "/", "hello"},
		testType{"www.example.com", "////", "hello"},
		testType{"www.example.com", "foo", "hi"},
		testType{"www.example.com", "foo/", "hi"},
		testType{"www.example.com", "foo/.", "hi"},
		testType{"www.example.com", "./foo/.", "hi"},
		testType{"www.example.com", "foo/..", "hello"},
		testType{"www.example.com", "../xxx/../..", "hello"},
		testType{"www.example.com", "../xxx/../../", "hello"},
		testType{"xyz.example.com", "abc", "hello"},
		testType{"xyz.example.com", "/abc/", "hello"},
		testType{"xyz.example.com", "abc/", "hello"},
		testType{"xyz.example.com", "abc/foo", "hi"},
		testType{"xyz.example.com", "abc/foo/", "hi"},
		testType{"xyz.example.com", "abc/foo/index.html", "hi"},
		testType{"xyz.example.com", "abc//foo", "hi"},
	)

	for _, f := range testFiles {
		code, body := get("https://" + f.host + "/" + f.name)
		if got, want := code, 200; got != want {
			t.Errorf("Code = %v, want %v", got, want)
			continue
		}
		if got, want := body, f.content; got != want {
			t.Errorf("Body = %v, want %v", got, want)
		}
	}

	for _, f := range []struct {
		host string
		name string
		code int
	}{
		{"www.example.com", "blah", 404},
		{"www.example.com", "foo/bar", 403},
		{"www.example.com", "../../../../../../../../etc/passwd", 404},
		{"www.example.com", ".git/config", 404},
		{"www.example.com", "foo/.git/config", 404},
		{"www.example.com", `abc\foo`, 404},
		{"xyz.example.com", "abc/.git/config", 404},
		{"aaa.example.com", "", 404},
		{"aaa.example.com", "/", 404},
		{"aaa.example.com", "../../../../../../../../etc/passwd", 404},
		{"aaa.example.com", "proxy.go", 404},
	} {
		code, _ := get("https://" + f.host + "/" + f.name)
		if got, want := code, f.code; got != want {
			t.Errorf("Code = %v, want %v", got, want)
		}
	}
}

func TestPathClean(t *testing.T) {
	for _, tc := range []struct {
		in, out string
	}{
		{"", "/"},
		{"/", "/"},
		{"//", "/"},
		{"///", "/"},
		{"foo", "/foo"},
		{"foo/", "/foo/"},
		{"/foo", "/foo"},
		{"//foo", "/foo"},
		{"///foo", "/foo"},
		{".", "/"},
		{"./", "/"},
		{".//", "/"},
		{"..", "/"},
		{"/.", "/"},
		{"/..", "/"},
		{"/foo/.", "/foo"},
		{"/foo/..", "/"},
		{"/foo/../../../../bar", "/bar"},
		{"/foo/./bar", "/foo/bar"},
		{"/foo/./bar/", "/foo/bar/"},
		{"/foo/./../bar", "/bar"},
		{"/../../bar", "/bar"},
		{"///..//../bar", "/bar"},
		{"/././bar", "/bar"},
	} {
		if got, want := pathClean(tc.in), tc.out; got != want {
			t.Errorf("pathClean(%q) = %q, want %q", tc.in, got, want)
		}
	}
}
