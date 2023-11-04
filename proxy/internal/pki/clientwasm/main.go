// MIT License
//
// Copyright (c) 2023 TTBT Enterprises LLC
// Copyright (c) 2023 Robin Thellend <rthellend@thellend.com>
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

//go:build wasm

// clientwasm implements TLS key generation and PKCS12 packaging in a browser
// so that the private key is never copied over the network.
package main

import (
	"fmt"
	"net/url"
	"syscall/js"

	"github.com/c2FmZQ/tlsproxy/proxy/internal/pki/clientwasm/impl"
)

var (
	jsUint8Array = js.Global().Get("Uint8Array")
	jsResponse   = js.Global().Get("Response")
)

func main() {
	pkiApp := js.Global().Get("pkiApp")
	if pkiApp.Type() != js.TypeObject {
		panic("pkiApp object not found")
	}
	ready := pkiApp.Get("pkiwasmIsReady")
	if ready.Type() != js.TypeFunction {
		panic("pkiApp.pkiwasmIsReady not found")
	}
	pkiApp.Set("makeCertificateRequest", js.FuncOf(makeCSR))
	pkiApp.Set("makeResponse", js.FuncOf(makeResponse))
	ready.Invoke()
	<-make(chan struct{})
}

func makeCSR(this js.Value, args []js.Value) any {
	// arg0: id  (a unique ID to match makeCSR with makeP12)
	// arg2: application/x-www-form-urlencoded arguments
	if len(args) != 2 || args[0].Type() != js.TypeNumber || args[1].Type() != js.TypeString {
		fmt.Println("makeCertificateRequest: unexpected arguments")
		return js.Undefined()
	}
	form, err := url.ParseQuery(args[1].String())
	if err != nil {
		fmt.Printf("ParseQuery(%q): %v\n", args[1].String(), err)
		return js.Undefined()
	}
	keyType := form.Get("keytype")
	if keyType == "" {
		keyType = "ecdsa-p256"
	}
	format := form.Get("format")
	if format == "" {
		format = "gpg"
	}
	password := form.Get("password")
	if password == "" {
		fmt.Println("password is missing")
		return js.Undefined()
	}
	resp, err := impl.MakeCSR(args[0].Int(), keyType, format, form.Get("label"), form.Get("dnsname"), password)
	if err != nil {
		fmt.Println(err)
		return js.Undefined()
	}
	return Uint8ArrayFromBytes(resp)
}

func makeResponse(this js.Value, args []js.Value) any {
	// arg0: id  (the same id used with makeCSR)
	// arg1: the pem-encoded cert
	if len(args) != 2 || args[0].Type() != js.TypeNumber || args[1].Type() != js.TypeString {
		fmt.Println("makeResponse: unexpected argument")
		return js.Undefined()
	}
	body, contentType, fileName, err := impl.MakeResponse(args[0].Int(), args[1].String())
	if err != nil {
		fmt.Println(err)
		return js.Undefined()
	}

	return jsResponse.New(
		Uint8ArrayFromBytes(body),
		js.ValueOf(map[string]any{
			"status":     200,
			"statusText": "OK",
			"headers": map[string]any{
				"content-type":        contentType,
				"content-disposition": `attachment; filename="` + fileName + `"`,
				"cache-control":       "private, no-store",
			},
		}),
	)
}

func Uint8ArrayFromBytes(in []byte) js.Value {
	out := jsUint8Array.New(js.ValueOf(len(in)))
	js.CopyBytesToJS(out, in)
	return out
}
