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
  document.getElementById('csrform').style.display = 'block';
}
function hideForm() {
  document.getElementById('csrform').style.display = 'none';
  window.location.reload();
}
function generateKeyAndCert(f) {
  if (f.pw1.value.length < 6) {
    alert('Password must be at least 6 characters');
    return;
  }
  if (f.pw1.value !== f.pw2.value) {
    alert('Passwords don\'t match');
    return;
  }
  const pw = f.pw1.value;
  const fmt = f.format.value;
  const kty = f.keytype.value;
  const label = f.label.value;
  const dns = f.dnsname.value;
  f.pw1.value = '';
  f.pw2.value = '';
  const path = window.location.pathname + '/generateKeyAndCert';
  navigator.serviceWorker.register('?get=static&file=sw.js', {scope: path})
    .then(r => r.update())
    .then(r => {
      console.log('Service worker ready');
      document.getElementById('csrform').style.display = 'none';
      const f = document.createElement('form');
      f.setAttribute('method', 'post');
      f.setAttribute('action', path);
      let p = document.createElement('input');
      p.setAttribute('type', 'hidden');
      p.setAttribute('name', 'password');
      p.setAttribute('value', pw);
      f.appendChild(p);
      p = document.createElement('input');
      p.setAttribute('type', 'hidden');
      p.setAttribute('name', 'format');
      p.setAttribute('value', fmt);
      f.appendChild(p);
      p = document.createElement('input');
      p.setAttribute('type', 'hidden');
      p.setAttribute('name', 'keytype');
      p.setAttribute('value', kty);
      f.appendChild(p);
      p = document.createElement('input');
      p.setAttribute('type', 'hidden');
      p.setAttribute('name', 'label');
      p.setAttribute('value', label);
      f.appendChild(p);
      p = document.createElement('input');
      p.setAttribute('type', 'hidden');
      p.setAttribute('name', 'dnsname');
      p.setAttribute('value', dns);
      f.appendChild(p);
      document.body.appendChild(f);
      f.submit();
    })
    .catch(err => console.error('Service worker update failed', err))
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
