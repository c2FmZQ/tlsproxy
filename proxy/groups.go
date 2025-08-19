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
	"iter"
	"slices"
	"sort"
	"strings"
)

type aclMatcher struct {
	groups []*Group
}

func (m *aclMatcher) groupsForEmail(email string) []string {
	var out []string
	for _, g := range m.groups {
		if m.emailMatches([]string{g.Name}, email) {
			out = append(out, g.Name)
		}
	}
	sort.Strings(out)
	return out
}

func (m *aclMatcher) emailMatches(acl []string, email string) bool {
	_, userDomain, ok := strings.Cut(email, "@")
	if slices.ContainsFunc(acl, func(group string) bool {
		return group == email || (ok && group == "@"+userDomain)
	}) {
		return true
	}

	for member := range m.walkGroups(acl) {
		if member.Email != "" && (member.Email == email || (ok && member.Email == "@"+userDomain)) {
			return true
		}
	}
	return false
}

func (m *aclMatcher) certMatches(acl []string, cert *x509.Certificate) bool {
	match := func(member string) bool {
		if subject := cert.Subject.String(); (member != "" && member == subject) || member == "SUBJECT:"+subject {
			return true
		}
		for _, v := range cert.DNSNames {
			if member == "DNS:"+v {
				return true
			}
		}
		for _, v := range cert.EmailAddresses {
			if member == "EMAIL:"+v {
				return true
			}
		}
		for _, v := range cert.URIs {
			if member == "URI:"+v.String() {
				return true
			}
		}
		return false
	}
	if slices.ContainsFunc(acl, func(group string) bool { return match(group) }) {
		return true
	}
	for member := range m.walkGroups(acl) {
		if match(member.X509) {
			return true
		}
	}
	return false
}

func (m *aclMatcher) findGroup(group string) *Group {
	if i := slices.IndexFunc(m.groups, func(g *Group) bool { return g.Name == group }); i >= 0 {
		return m.groups[i]
	}
	return nil
}

func (m *aclMatcher) walkGroups(groups []string) iter.Seq[*Member] {
	return func(yield func(*Member) bool) {
		var queue []string
		seen := make(map[string]bool)

		for _, group := range groups {
			if seen[group] {
				continue
			}
			seen[group] = true
			queue = append(queue, group)
		}

		for len(queue) > 0 {
			name := queue[0]
			queue = queue[1:]

			g := m.findGroup(name)
			if g == nil {
				continue
			}
			for _, member := range g.Members {
				if !yield(member) {
					return
				}
				if member.Group != "" && !seen[member.Group] {
					queue = append(queue, member.Group)
					seen[member.Group] = true
				}
			}
		}
	}
}
