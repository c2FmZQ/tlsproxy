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

package oidc

import (
	"testing"

	jwt "github.com/golang-jwt/jwt/v5"
)

func TestRewriteRules(t *testing.T) {
	in := jwt.MapClaims{
		"email":       "jane@EXAMPLE.COM",
		"name":        "Jane Doe",
		"given_name":  "Jane",
		"family_name": "Doe",
	}
	out := jwt.MapClaims{}

	rr := []RewriteRule{
		{
			InputClaim:  "email",
			OutputClaim: "preferred_username",
			Regex:       "^([^@]+)@.*$",
			Value:       "$1",
		},
		{
			InputClaim:  "name",
			OutputClaim: "name_nospace",
			Regex:       " ",
			Value:       "",
		},
		{
			InputClaim:  "${name} <${email}>",
			OutputClaim: "name_and_email",
			Regex:       "^(.*)$",
			Value:       "$1",
		},
		{
			InputClaim:  "${given_name:lower}",
			OutputClaim: "username2",
			Regex:       "^(.).*$",
			Value:       "$1",
		},
		{
			InputClaim:  "${username2}${family_name:lower}",
			OutputClaim: "username2",
			Regex:       "^(.*)$",
			Value:       "$1",
		},
	}

	s := NewServer(ServerOptions{})
	s.applyRewriteRules(rr, in, out)

	if want, got := "jane", out["preferred_username"]; want != got {
		t.Errorf("preferred_username = %q, want %q", got, want)
	}
	if want, got := "JaneDoe", out["name_nospace"]; want != got {
		t.Errorf("name_nospace = %q, want %q", got, want)
	}
	if want, got := "Jane Doe <jane@EXAMPLE.COM>", out["name_and_email"]; want != got {
		t.Errorf("name_and_email = %q, want %q", got, want)
	}
	if want, got := "jdoe", out["username2"]; want != got {
		t.Errorf("username2 = %q, want %q", got, want)
	}
}
