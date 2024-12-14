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
	"io"
)

func sendCloseNotify(w io.Writer) error {
	return sendAlert(w, 0x2 /* fatal */, 0x00 /* Close notify */)
}

func sendHandshakeFailure(w io.Writer) error {
	return sendAlert(w, 0x2 /* fatal */, 0x28 /* Handshake failure */)
}

func sendInternalError(w io.Writer) error {
	return sendAlert(w, 0x2 /* fatal */, 0x50 /* Internal error */)
}

func sendUnrecognizedName(w io.Writer) error {
	return sendAlert(w, 0x2 /* fatal */, 0x70 /* Unrecognized name */)
}

func sendAlert(w io.Writer, level, description uint8) error {
	// https://en.wikipedia.org/wiki/Transport_Layer_Security
	_, err := w.Write([]byte{
		0x15,       // alert
		0x03, 0x03, // version TLS 1.2
		0x00, 0x02, // length
		level, description,
	})
	return err
}
