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

window.pkiApp = {};
pkiApp.ready = new Promise(resolve => {
  pkiApp.pkiwasmIsReady = () => {
    console.log('PKI WASM is ready');
    resolve();
  };
});

const go = new Go();
let wasmLoaded = false;

function requestCert(csr) {
  fetch('?get=requestCert', {
    method: 'POST',
    headers: {
      'content-type': 'application/x-pem-file',
      'x-csrf-check': '1',
    },
    body: csr,
  })
  .then(resp => {
    if (resp.status !== 200 || resp.headers.get('content-type') !== 'application/json') {
      console.log('Response is not json', resp);
      throw 'unexpected response from server';
    }
    return resp.json();
  })
  .then(r => {
    if (r.result === 'ok') {
      console.log('Success');
      document.getElementById('csrform').style.display = 'none';
      document.getElementById('viewcert').style.display = 'block';
      document.getElementById('certpem').textContent = r.cert;
    }
  })
  .catch(err => {
    console.log('Failure', err);
    alert(err);
  });
}
function revokeCert(sn) {
  if (!confirm('Revoke certificate with serial number '+sn+'?')) {
    return;
  }
  fetch('?get=revokeCert', {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      'x-csrf-check': '1',
    },
    body: 'sn='+encodeURIComponent(sn),
  })
  .then(resp => {
    if (resp.status !== 200 || resp.headers.get('content-type') !== 'application/json') {
      console.log('Response is not json', resp);
      throw 'unexpected response from server';
    }
    return resp.json();
  })
  .then(r => {
    if (r.result !== 'ok') {
      throw new Error(r.result);
    }
    console.log('Success');
    window.location.reload();
  })
  .catch(err => {
    console.log('Failure', err);
    alert(err);
  });
}
function downloadCert(sn) {
  window.location = '?get=downloadCert&sn='+encodeURIComponent(sn);
}
function showForm() {
  if (!wasmLoaded) {
    WebAssembly.instantiateStreaming(fetch('?get=static&file=pki.wasm.bz2'), go.importObject).then(r => go.run(r.instance));
    wasmLoaded = true;
  }
  document.getElementById('csrform').style.display = 'block';
}
function hideForm() {
  document.getElementById('csrform').style.display = 'none';
  window.location.reload();
}
function selectUsage(e) {
  const isServer = e.options[e.selectedIndex].value === 'server';
  for (const e of document.querySelectorAll('.dnsinput')) {
    if (isServer) e.classList.add('selected');
    else e.classList.remove('selected');
  }
}
function generateKeyAndCert(b) {
  let f = b.form;
  if (f.pw1.value.length < 6) {
    alert('Password must be at least 6 characters');
    return;
  }
  if (f.pw1.value !== f.pw2.value) {
    alert('Passwords don\'t match');
    return;
  }
  if (f.usage.options[f.usage.selectedIndex].value === 'server' && f.dnsname.value === '') {
    alert('DNS Name is required');
    return;
  }
  const pw = f.pw1.value;
  f.pw1.value = '';
  f.pw2.value = '';

  const oldb = b.textContent;
  b.disabled = true;
  b.textContent = 'working...';
  document.body.classList.add('waiting');
  pkiApp.ready
  .then(() => pkiApp.getCertificate({
    'keytype': f.keytype.value,
    'format': f.format.value,
    'password': pw,
    'label': f.label.value,
    'dnsname': f.dnsname.value,
  }))
  .then(() => window.location.reload())
  .catch(err => {
    b.disabled = false;
    b.textContent = oldb;
    document.body.classList.remove('waiting');
    console.error('getCertificate failed', err);
    alert('Request failed: '+err.message);
  });
}

function showView(sn) {
  fetch('?get=downloadCert&sn='+encodeURIComponent(sn))
  .then(resp => {
    if (resp.status !== 200 || resp.headers.get('content-type') !== 'application/x-pem-file') {
      console.log('Response is not pem', resp);
      throw 'unexpected response from server';
    }
    return resp.text();
  })
  .then(r => {
    document.getElementById('viewcert').style.display = 'block';
    document.getElementById('certpem').textContent = r
  })
  .catch(err => {
    console.log('Failure', err);
    alert(err);
  });
}
function hideView() {
  document.getElementById('viewcert').style.display = 'none';
}
