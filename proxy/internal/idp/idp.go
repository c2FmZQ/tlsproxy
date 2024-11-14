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

package idp

type LoginOptions struct {
	loginHint     string
	selectAccount bool
}

func (o LoginOptions) LoginHint() string {
	return o.loginHint
}

func (o LoginOptions) SelectAccount() bool {
	return o.selectAccount
}

type Option func(*LoginOptions)

func WithLoginHint(v string) Option {
	return func(o *LoginOptions) {
		o.loginHint = v
	}
}

func WithSelectAccount(v bool) Option {
	return func(o *LoginOptions) {
		o.selectAccount = v
	}
}

func ApplyOptions(opts []Option) LoginOptions {
	var lo LoginOptions
	for _, opt := range opts {
		opt(&lo)
	}
	return lo
}
