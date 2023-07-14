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

package internal

import (
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/cryptobyte"

	"github.com/c2FmZQ/tlsproxy/internal/netw"
)

type ClientHello struct {
	ServerName string
	ALPNProtos []string
}

func peekClientHello(c *netw.Conn) (hello ClientHello, err error) {
	// Handshake packet header
	buf := make([]byte, 5)
	if _, err := c.Peek(buf); err != nil {
		return hello, fmt.Errorf("packet header: %v", err)
	}
	if buf[0] != 0x16 { // TLS Handshake
		return hello, fmt.Errorf("content type 0x%x != 0x16 (%q)", buf[0], buf)
	}
	s := cryptobyte.String(buf)
	if !s.Skip(3) { // type, version[2]
		return hello, errors.New("invalid format")
	}
	var length uint16
	if !s.ReadUint16(&length) || length > 16384 {
		return hello, fmt.Errorf("packet length %d > 16384", length)
	}
	buf = make([]byte, 5+length)
	if _, err := c.Peek(buf); err != nil {
		return hello, fmt.Errorf("read packet: %v", err)
	}
	buf = buf[5:]

	// https://datatracker.ietf.org/doc/html/rfc8446#section-4
	//
	// struct {
	//    HandshakeType msg_type;    /* handshake type */
	//    uint24 length;             /* remaining bytes in message */
	//      select (Handshake.msg_type) {
	//          case client_hello:          ClientHello;
	//          ...
	//      };
	// } Handshake;
	if buf[0] != 0x01 { // ClientHello
		return hello, fmt.Errorf("msg_type 0x%x != 0x01", buf[0])
	}
	s = cryptobyte.String(buf)
	if !s.Skip(4) { // msg_type(1), length(3)
		return hello, errors.New("invalid format")
	}

	// https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
	// ClientHello
	//   uint16 ProtocolVersion;
	//   opaque Random[32];
	//
	//   uint8 CipherSuite[2];    /* Cryptographic suite selector */
	//
	//   struct {
	//     ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
	//     Random random;
	//     opaque legacy_session_id<0..32>;
	//     CipherSuite cipher_suites<2..2^16-2>;
	//     opaque legacy_compression_methods<1..2^8-1>;
	//     Extension extensions<8..2^16-1>;
	//   } ClientHello;
	if !s.Skip(34) { // ProtocolVersion(2), Random(32)
		return hello, errors.New("invalid format")
	}

	var len8 uint8
	var len16 uint16
	if !s.ReadUint8(&len8) || !s.Skip(int(len8)) || // legacy_session_id
		!s.ReadUint16(&len16) || !s.Skip(int(len16)) || // cipher_suites
		!s.ReadUint8(&len8) || !s.Skip(int(len8)) { // legacy_compression_methods
		return hello, errors.New("invalid format")
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) {
		return hello, errors.New("invalid format")
	}

	// https://datatracker.ietf.org/doc/html/rfc8446#section-4.2
	// Extensions
	//
	// struct {
	//     ExtensionType extension_type;
	//     opaque extension_data<0..2^16-1>;
	// } Extension;
	//
	// enum {
	//     server_name(0),                             /* RFC 6066 */
	//     ...
	//     application_layer_protocol_negotiation(16), /* RFC 7301 */
	//     ...
	// } ExtensionType;

	for !extensions.Empty() {
		var extType uint16
		var data cryptobyte.String
		if !extensions.ReadUint16(&extType) || !extensions.ReadUint16LengthPrefixed(&data) {
			return hello, errors.New("invalid format")
		}
		switch extType {
		case 0:
			// https://datatracker.ietf.org/doc/html/rfc6066#section-3
			// Server Name Indication
			//
			// struct {
			//   NameType name_type;
			//   select (name_type) {
			//       case host_name: HostName;
			//   } name;
			// } ServerName;
			//
			// enum {
			//   host_name(0), (255)
			// } NameType;
			//
			// opaque HostName<1..2^16-1>;
			//
			// struct {
			//   ServerName server_name_list<1..2^16-1>
			// } ServerNameList;

			var serverNameList cryptobyte.String
			if !data.ReadUint16LengthPrefixed(&serverNameList) {
				return hello, errors.New("invalid format")
			}
			for !serverNameList.Empty() {
				var nameType uint8
				var hostName cryptobyte.String
				if !serverNameList.ReadUint8(&nameType) {
					return hello, errors.New("invalid format")
				}
				if nameType != 0 { // host name
					return hello, fmt.Errorf("invalid nametype 0x%x", nameType)
				}
				if !serverNameList.ReadUint16LengthPrefixed(&hostName) || hello.ServerName != "" {
					return hello, errors.New("invalid format")
				}
				hello.ServerName = string(hostName)
			}
		case 16:
			// https://datatracker.ietf.org/doc/html/rfc7301#section-3
			// Application-Layer Protocol Negotiation
			//
			//  enum {
			//      application_layer_protocol_negotiation(16), (65535)
			//  } ExtensionType;
			//
			//  The "extension_data" field of the
			//  ("application_layer_protocol_negotiation(16)") extension SHALL
			//  contain a "ProtocolNameList" value.
			//
			//  opaque ProtocolName<1..2^8-1>;
			//
			//  struct {
			//      ProtocolName protocol_name_list<2..2^16-1>
			//  } ProtocolNameList;
			var protocolNameList cryptobyte.String
			if !data.ReadUint16LengthPrefixed(&protocolNameList) {
				return hello, errors.New("invalid format")
			}
			for !protocolNameList.Empty() {
				var protocolName cryptobyte.String
				if !protocolNameList.ReadUint8LengthPrefixed(&protocolName) {
					return hello, errors.New("invalid format")
				}
				hello.ALPNProtos = append(hello.ALPNProtos, string(protocolName))
			}
		}
	}
	return hello, nil
}

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
