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

//go:build noquic

package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
)

const quicIsEnabled = false

var errQUICNotEnabled = errors.New("QUIC is not enabled in this binary")

func (p *Proxy) startQUIC(context.Context) error {
	return errQUICNotEnabled
}

func (p *Proxy) startQUICListener(context.Context) error {
	return errQUICNotEnabled
}

func (be *Backend) dialQUICStream(context.Context, string, *tls.Config) (net.Conn, error) {
	return nil, errQUICNotEnabled
}

func (be *Backend) http3Transport() http.RoundTripper {
	return nil
}

func http3Server(http.Handler) io.Closer {
	return nil
}
