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

// Inspired in large part by code from Vanadium.
// https://github.com/vanadium-archive/go.ref/blob/master/lib/stats/counter/timeseries.go
// https://github.com/vanadium-archive/go.ref/blob/master/LICENSE
//
// Copyright 2015 The Vanadium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package counter implements a counter that keeps some historical data to
// calculate rates.
package counter

import (
	"sync"
	"time"
)

var timeNow = time.Now

// New returns a new Counter.
func New(maxPeriod, resolution time.Duration) *Counter {
	size := int64(maxPeriod)/int64(resolution) + 1
	if size > 1000 {
		panic("counter resolution too small")
	}
	return &Counter{
		size:  int(size),
		rez:   resolution,
		time:  time.Now().Truncate(resolution),
		slots: make([]int64, int(size)),
	}
}

type Counter struct {
	size int
	rez  time.Duration

	mu    sync.Mutex
	steps int64
	head  int
	time  time.Time
	slots []int64
}

func (c *Counter) Value() int64 {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.slots[c.head]
}

func (c *Counter) Incr(delta int64) int64 {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.advance()
	c.slots[c.head] += delta
	return c.slots[c.head]
}

func (c *Counter) Rate(period time.Duration) float64 {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.advance()
	steps := min(int64(period/c.rez), c.steps, int64(c.size))
	if steps == 0 {
		return 0
	}
	delta := c.slots[c.head] - c.slots[(c.head+c.size-int(steps))%c.size]
	return float64(delta) / float64((time.Duration(steps) * c.rez).Seconds())
}

func (c *Counter) advance() {
	now := timeNow().Truncate(c.rez)
	if !now.After(c.time) {
		return
	}
	steps := int64(now.Sub(c.time)) / int64(c.rez)
	c.time = now
	c.steps += steps
	steps = min(steps, int64(c.size))
	v := c.slots[c.head]
	for steps > 0 {
		c.head = (c.head + 1) % c.size
		c.slots[c.head] = v
		steps--
	}
}
