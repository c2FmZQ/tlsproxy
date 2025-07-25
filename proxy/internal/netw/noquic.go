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

package netw

import "net"

type QUICStream struct {
	Conn
}

func (*QUICStream) Dir() string {
	return ""
}
func (*QUICStream) BridgeAddr() string {
	return ""
}

func (*QUICStream) SetReliableBoundary() {
}

type QUICConn struct {
	net.Conn
}

func (*QUICConn) Streams() []*QUICStream {
	return nil
}

func (*QUICConn) Annotation(key string, defaultValue any) any {
	return nil
}

func (*QUICConn) SetAnnotation(key string, value any) {
}

func (*QUICConn) BytesSent() int64 {
	return 0
}

func (*QUICConn) BytesReceived() int64 {
	return 0
}

func (*QUICConn) ByteRateSent() float64 {
	return 0
}

func (*QUICConn) ByteRateReceived() float64 {
	return 0
}
