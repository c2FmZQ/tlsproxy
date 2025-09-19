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
    return fetch('/.sso/languages.json?lang='+encodeURIComponent(opts.join(',')).replaceAll('%2C',','))
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
        console.log(`translations: no match for ${langs}`);
        if (langs.length !== 1 || langs[0] !== 'en') {
          return setLanguage(['en']);
        }
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

  function cookieBanner() {
    const name='__tlsProxyCookieBannerDismissed';
    if (localStorage.getItem(name)) {
      return;
    }
    const div = document.createElement('div');
    div.style.position = 'fixed';
    div.style.left = '0.25rem';
    div.style.bottom = '0.25rem';
    div.style.width = '25vw';
    div.style.padding = '1rem';
    div.style.color = 'black';
    div.style.backgroundColor = 'white';
    div.style.border = '1px solid black';
    div.style.cursor = 'pointer';
    div.style.zIndex = '1';
    div.style.textAlign = 'center';
    div.style.boxShadow = '3px 3px 5px black';
    const x = document.createElement('div');
    x.style.position = 'absolute';
    x.style.right = '0.25rem';
    x.style.top = '0.25rem';
    x.textContent = '✖';
    div.appendChild(x);
    const m = document.createElement('div');
    m.setAttribute('tkey', 'cookie-banner');
    div.appendChild(m);
    div.addEventListener('click', () => {
      document.body.removeChild(div);
      localStorage.setItem(name, 'yes');
    });
    document.body.appendChild(div);
  }

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
    if (changed && !document.getElementById('lang-selector')) {
      const b = document.createElement('select');
      b.id = 'lang-selector';
      b.addEventListener('click', () => {
        const s = b.options[b.selectedIndex].value;
        if (s !== tlsProxy.lang) {
          applyTranslations(s);
        }
      });
      b.style.cursor = 'pointer';
      b.style.position = 'fixed';
      b.style.bottom = '0.25rem';
      b.style.right = '0.25rem';
      b.style.padding = '0.1rem';
      b.style.zIndex = 10;
      b.style.backgroundColor = 'white';
      document.body.appendChild(b);
      fetch('/.sso/languages.json').then(r => r.json()).then(r => {
        for (let key in r) {
          const o = document.createElement('option');
          o.value = key;
          o.setAttribute('lang', key);
          o.selected = key === tlsProxy.lang;
          o.textContent = r[key].lang;
          b.appendChild(o);
        }
      });
    }
  }
  document.addEventListener('DOMContentLoaded', () => {
    cookieBanner();
    applyTranslations();
  });
})();
