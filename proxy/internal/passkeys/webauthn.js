/*
 * MIT License
 *
 * Copyright (c) 2023 TTBT Enterprises LLC
 * Copyright (c) 2023 Robin Thellend <rthellend@rthellend.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

const self = window.location.pathname;

function registerPasskey(redirectUrl) {
  if (!('PublicKeyCredential' in window)) {
    throw new Error('Browser doesn\'t support WebAuthn');
  }

  fetch(self+'?get=AttestationOptions')
  .then(resp => {
    if (resp.status !== 200) {
      throw resp.status;
    }
    return resp.json();
  })
  .then(options => {
    options.challenge = new Uint8Array(options.challenge);
    if (options.excludeCredentials) {
      for (let i = 0; i < options.excludeCredentials.length; i++) {
        options.excludeCredentials[i].id = new Uint8Array(options.excludeCredentials[i].id);
      }
    }
    options.user.id = new Uint8Array(options.user.id);
    return navigator.credentials.create({publicKey: options});
  })
  .then(pkc => {
    if (pkc.type !== 'public-key' || !(pkc.response instanceof window.AuthenticatorAttestationResponse)) {
      throw new Error('invalid credentials.create response');
    }
    const v = JSON.stringify({
      clientDataJSON: Array.from(new Uint8Array(pkc.response.clientDataJSON)),
      attestationObject: Array.from(new Uint8Array(pkc.response.attestationObject)),
      transports: pkc.response.getTransports(),
    });
    return fetch(self+'?get=AddKey', {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: 'args=' + encodeURIComponent(v),
    });
  })
  .then(resp => {
    if (resp.status !== 200) {
      throw resp.status;
    }
    return resp.json();
  })
  .then(r => {
    if (r.result === 'ok') {
      console.log('Success');
      if (redirectUrl) {
        window.location = redirectUrl;
      } else {
        window.location.reload();
      }
    }
  })
  .catch(err => {
    console.log('Failure', err);
    alert(err);
  });
}

function loginWithPasskey(redirectUrl) {
  if (!('PublicKeyCredential' in window)) {
    throw new Error('Browser doesn\'t support WebAuthn');
  }
  fetch(self+'?get=AssertionOptions')
  .then(resp => {
    if (resp.status !== 200) {
      throw resp.status;
    }
    return resp.json();
  })
  .then(options => {
    options.challenge = new Uint8Array(options.challenge);
    return navigator.credentials.get({publicKey: options})
  })
  .then(pkc => {
    if (pkc.type !== 'public-key' || !(pkc.response instanceof window.AuthenticatorAssertionResponse)) {
      throw new Error('invalid PublicKeyCredential value');
    }
    const v = JSON.stringify({
        id: pkc.id,
        clientDataJSON: Array.from(new Uint8Array(pkc.response.clientDataJSON)),
        authenticatorData: Array.from(new Uint8Array(pkc.response.authenticatorData)),
        signature: Array.from(new Uint8Array(pkc.response.signature)),
        userHandle: Array.from(new Uint8Array(pkc.response.userHandle)),
    });
    return fetch(self+'?get=Check', {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
      },
      credentials: 'same-origin',
      body: 'args=' + encodeURIComponent(v),
    });
  })
  .then(resp => {
    if (resp.status !== 200) {
      throw resp.status;
    }
    return resp.json();
  })
  .then(r => {
    if (r.result === 'ok') {
      console.log('Success');
      if (redirectUrl) {
        window.location = redirectUrl;
      } else {
        window.location.reload();
      }
    }
  })
  .catch(err => {
    console.log('Failure', err);
    alert(err);
  });
}

function deleteKey(id) {
  if (!window.confirm('Delete key ID ' + id + '?')) {
    return;
  }
  fetch(self+'?get=DeleteKey', {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
    },
      body: 'id=' + encodeURIComponent(id),
  })
  .then(resp => {
    if (resp.status !== 200) {
      throw resp.status;
    }
    return resp.json();
  })
  .then(r => {
    if (r.result === 'ok') {
      console.log('Success');
      window.location.reload();
    }
  })
  .catch(err => {
    console.log('Failure', err);
    alert(err);
  });
}

