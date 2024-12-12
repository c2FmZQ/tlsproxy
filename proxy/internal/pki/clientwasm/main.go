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

//go:build wasm

// clientwasm implements TLS key generation and PKCS12 packaging in a browser
// so that the private key is never copied over the network.
package main

import (
	"fmt"
	"syscall/js"

	"github.com/c2FmZQ/tlsproxy/proxy/internal/pki/clientwasm/impl"
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
	pkiApp.Set("getCertificate", js.FuncOf(getCertificate))
	ready.Invoke()
	<-make(chan struct{})
}

func getCertificate(this js.Value, args []js.Value) (result any) {
	defer func() {
		switch v := result.(type) {
		case error:
			jsErr := js.Global().Get("Error").New(fmt.Sprintf("Start: %v", v))
			result = js.Global().Get("Promise").Call("reject", jsErr)
		default:
		}
	}()
	if len(args) != 1 || args[0].Type() != js.TypeObject {
		return fmt.Errorf("getCertificate: unexpected arguments")
	}
	arg := args[0]
	keyType := arg.Get("keytype").String()
	format := arg.Get("format").String()
	password := arg.Get("password").String()
	label := arg.Get("label").String()
	dnsName := arg.Get("dnsname").String()
	url := js.Global().Get("location").Get("pathname").String() + "?get=requestCert"

	return js.Global().Get("Promise").New(js.FuncOf(
		func(this js.Value, args []js.Value) any {
			resolve := args[0]
			reject := args[1]
			go func() {
				data, contentType, filename, err := impl.GetCertificate(url, keyType, format, label, dnsName, password)
				if err != nil {
					reject.Invoke(js.Global().Get("Error").New(err.Error()))
					return
				}
				opts := js.Global().Get("Object").New()
				opts.Set("type", contentType)
				blob := js.Global().Get("Blob").New(js.Global().Get("Array").New(Uint8ArrayFromBytes(data)), opts)

				a := js.Global().Get("document").Call("createElement", "a")
				a.Set("href", js.Global().Get("URL").Call("createObjectURL", blob))
				a.Call("setAttribute", "download", js.ValueOf(filename))
				el := js.Global().Get("document").Get("body")
				el.Call("appendChild", a)
				a.Call("click")
				el.Call("removeChild", a)
				resolve.Invoke()
			}()
			return nil
		},
	))
}

func Uint8ArrayFromBytes(in []byte) js.Value {
	out := js.Global().Get("Uint8Array").New(js.ValueOf(len(in)))
	js.CopyBytesToJS(out, in)
	return out
}
