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

'use strict';

self.importScripts('?get=static&file=wasm_exec.js');

self.pkiApp = {};
self.pkiApp.ready = new Promise(resolve => {
  pkiApp.pkiwasmIsReady = () => {
    console.log('PKI WASM is ready');
    resolve();
  };
});

const go = new Go();
WebAssembly.instantiateStreaming(fetch('?get=static&file=pki.wasm.bz2'), go.importObject)
  .then(r => go.run(r.instance));

self.addEventListener('activate', event => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', event => {
  if (event.request.method !== 'POST') {
    throw new Error('unexpected method');
  }
  event.respondWith(generateKeyAndCert(event.request.body));
});

let keyCount = 0;
async function generateKeyAndCert(body) {
  await self.pkiApp.ready;
  const count = ++keyCount;

  const reader = body.getReader();
  const buf = [];
  while (true) {
    let {done, value} = await reader.read();
    if (value) buf.push(...value);
    if (done) break;
  }
  const formdata = new TextDecoder().decode(new Uint8Array(buf));

  console.log('Making CSR');
  const csr = self.pkiApp.makeCertificateRequest(count, formdata);

  console.log('Fetching Cert');
  const resp = await fetch('?get=requestCert', {
    method: 'POST',
    headers: {
      'content-type': 'application/x-pem-file',
      'x-csrf-check': '1',
    },
    body: csr,
  });
  if (resp.status !== 200 || resp.headers.get('content-type') !== 'application/json') {
    console.log('response is not json', resp);
    throw new Error('unexpected server response');
  }
  const r = await resp.json();
  if (r.result !== 'ok') {
    throw new Error('unexpected server response');
  }

  console.log('Package key and cert');
  return self.pkiApp.makeResponse(count, r.cert);
}
