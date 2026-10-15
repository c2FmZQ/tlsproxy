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
)

func TestEncodeXFCC(t *testing.T) {
	for _, tc := range []struct {
		input  string
		output string
	}{
		{input: `foo`, output: `foo`},
		{input: `foo&?!`, output: `foo&?!`},
		{input: `foo,bar`, output: `"foo,bar"`},
		{input: `foo;bar`, output: `"foo;bar"`},
		{input: `foo=bar`, output: `"foo=bar"`},
		{input: `"foo`, output: `\"foo`},
		{input: ``, output: ``},
	} {
		if got, want := encodeXFCC(tc.input), tc.output; got != want {
			t.Errorf("encodeXFCC(%q) = %q, want %q", tc.input, got, want)
		}
	}
}

func TestEncodeXFCCSubject(t *testing.T) {
	for _, tc := range []struct {
		input  string
		output string
	}{
		{input: `CN=foo`, output: `"/CN=foo"`},
		{input: `O=Org,CN=foo`, output: `"/O=Org/CN=foo"`},
		{input: `C=US,O=Org,CN=foo`, output: `"/C=US/O=Org/CN=foo"`},
		{input: `O=Org\,org=\,org=,CN=foo`, output: `"/O=Org\\,org=\\,org=/CN=foo"`},
		{input: `O=Org,org=,org=,CN=foo`, output: `"/O=Org/org=/org=/CN=foo"`},
		{input: ``, output: `/`},
	} {
		if got, want := encodeXFCCSubject(tc.input), tc.output; got != want {
			t.Errorf("encodeXFCCSubject(%q) = %q, want %q", tc.input, got, want)
		}
	}
}
