// MIT License
//
// Copyright (c) 2026 TTBT Enterprises LLC
// Copyright (c) 2026 Robin Thellend <rthellend@rthellend.com>
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

package idp

import (
	"fmt"
	"testing"
	"time"
)

func TestPendingLogins(t *testing.T) {
	p := NewPendingLogins(5*time.Minute, func(t time.Time) time.Time { return t })

	now := time.Now()
	if !p.Add("fresh", now) {
		t.Fatal("Add(fresh) = false")
	}
	if !p.Add("old", now.Add(-10*time.Minute)) {
		t.Fatal("Add(old) = false")
	}
	if _, ok := p.Get("fresh"); !ok {
		t.Error("Get(fresh) = false")
	}
	if _, ok := p.Get("old"); ok {
		t.Error("Get(old) = true")
	}
	p.Delete("fresh")
	if _, ok := p.Get("fresh"); ok {
		t.Error("Get(fresh) after Delete = true")
	}

	// Expired entries are pruned when the limit is reached.
	for i := range MaxPendingLogins {
		if !p.Add(fmt.Sprintf("old-%d", i), now.Add(-10*time.Minute)) {
			t.Fatalf("Add(old-%d) = false", i)
		}
	}
	if !p.Add("new", now) {
		t.Fatal("Add(new) = false")
	}
	if got := len(p.m); got != 1 {
		t.Errorf("len = %d, want 1", got)
	}

	// Fresh entries are not.
	for i := 1; i < MaxPendingLogins; i++ {
		if !p.Add(fmt.Sprintf("new-%d", i), now) {
			t.Fatalf("Add(new-%d) = false", i)
		}
	}
	if p.Add("one-too-many", now) {
		t.Error("Add(one-too-many) = true")
	}
}
