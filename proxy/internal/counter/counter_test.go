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

package counter

import (
	"testing"
	"time"
)

func TestCounter(t *testing.T) {
	c := New(time.Minute, time.Second)
	now := c.time
	timeNow = func() time.Time { return now }

	for i, step := range []struct {
		timeIncr  time.Duration
		valueIncr int64
		expValue  int64
		expRate   float64
	}{
		{0, 0, 0, 0},
		{time.Millisecond, 10, 10, 0},
		{time.Second, 10, 20, 10},       // t=1s, r=(20-10)/1s
		{time.Second, 10, 30, 10},       // t=2s, r=(30-10)/2s
		{2 * time.Second, 0, 30, 5},     // t=4s, r=(30-10)/4s
		{16 * time.Second, 0, 30, 1},    // t=20s, r=(30-10)/20s
		{40 * time.Second, 10, 40, 0.5}, // t=60s, r=(40-10)/60s
		{time.Minute, 0, 40, 0},         // t=60s, r=(40-40)/60s
		{time.Minute, 0, 40, 0},         // t=120s, r=(40-40)/60s
		{time.Second, 60, 100, 1},       // t=121s, r=(100-40)/60s
		{time.Hour, 0, 100, 0},
	} {
		now = now.Add(step.timeIncr)
		c.Incr(step.valueIncr)
		if got, want := c.Value(), step.expValue; got != want {
			t.Fatalf("Step #%d: Value = %d, want %d", i, got, want)
		}
		if got, want := c.Rate(time.Minute), step.expRate; got != want {
			t.Fatalf("Step #%d: Rate = %f, want %f", i, got, want)
		}
	}
}
