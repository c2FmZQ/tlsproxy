// MIT License
//
// Copyright (c) 2025 TTBT Enterprises LLC
// Copyright (c) 2025 Robin Thellend <rthellend@rthellend.com>
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

window.tlsProxy = {
  lang: 'en', // default language
  langData: {},
};

(() => {
  function logout() {
    return fetch('/.sso/logout', {
      method: 'POST',
    })
    .then(() => window.location = '/.sso/logout');
  }
  tlsProxy.logout = logout;

  function sessionId() {
    const m = document.cookie.match(/__tlsproxySid=([^;]*)(;|$)/);
    if (m) return m[1];
    return '';
  }
  const ofetch = window.fetch;
  window.fetch = function(res, opt) {
    if (!opt) {
      opt = {};
    }
    if (!opt.headers) {
      opt.headers = {};
    }
    opt.headers['x-csrf-token'] = sessionId();
    return ofetch(res, opt);
  };

  function setLanguage(langs) {
    let opts = [...langs];
    for (let lang of langs) {
      const m = lang.split('-');
      if (m.length === 3) {
        opts.push(m[0]+'-'+m[2]);
        opts.push(m[0]+'-'+m[1]);
      }
      if (m.length > 1) {
        opts.push(m[0]);
      }
    }
    let sorted = [...new Set(opts)];
    sorted.sort();
    return fetch('/.sso/languages.json?lang='+encodeURIComponent(sorted.join(',')).replaceAll('%2C',','))
      .then(r => r.json())
      .then(data => {
        for (let opt of opts) {
          if (data[opt]) {
            window.tlsProxy.lang = opt;
            window.tlsProxy.langData = data;
            console.log(`translations: found ${opt} for ${langs}`);
            return
          }
        }
        throw new Error(`translations: no match for ${langs}`);
      });
  }

  function translate(key) {
    const value = tlsProxy.langData[tlsProxy.lang][key];
    if (!value) {
      return '###' + key + '###';
    }
    return value;
  }
  tlsProxy.translate = translate;

  async function applyTranslations(lang) {
    await setLanguage(lang?[lang]:navigator.languages);
    let changed = false;
    document.querySelectorAll('[tkey]').forEach(e => {
      const value = translate(e.getAttribute('tkey'));
      if (e.tagName === 'INPUT' && e.hasAttribute('placeholder')) {
        e.setAttribute('placeholder', value);
      } else {
        e.textContent = value;
      }
      changed = true;
    });
    if (changed) {
      const html = document.querySelector('HTML');
      html.setAttribute('lang', tlsProxy.lang);
      html.setAttribute('dir', translate('DIR') === 'rtl' ? 'rtl' : 'ltr');
    }
    if (changed && tlsProxy.lang !== 'en') {
      const b = document.createElement('a');
      b.setAttribute('lang', 'en');
      b.setAttribute('direction', 'ltr');
      b.textContent = 'Show in english';
      b.addEventListener('click', () => {
        applyTranslations('en');
        document.body.removeChild(b);
      });
      b.style.cursor = 'pointer';
      b.style.position = 'fixed';
      b.style.bottom = '0.25rem';
      b.style.left = '0.25rem';
      b.style.padding = '0.1rem';
      b.style.zIndex = 10;
      b.style.backgroundColor = 'white';
      document.body.appendChild(b);
    }
  }
  document.addEventListener('DOMContentLoaded', () => applyTranslations());
})();
