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

/**
 * Extracts the session ID from the '__tlsproxySid' cookie.
 * @returns {string} The session ID, or an empty string if not found.
 */
function sessionId() {
  const m = document.cookie.match(/__tlsproxySid=([^;]*)(;|$)/);
  return m ? m[1] : '';
}

/**
 * @summary Wraps the global fetch() function to automatically add an
 * x-csrf-token header to all requests.
 * @description This is a security measure to prevent Cross-Site Request Forgery (CSRF) attacks.
 */
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

/**
 * @summary Logs the user out.
 * @description Sends a POST request to the logout endpoint and then redirects the
 * browser to the same URL to complete the process.
 * @returns {Promise<void>}
 */
export function logout() {
  return fetch('/.sso/logout', {
    method: 'POST',
  })
  .then(() => window.location = '/.sso/logout');
}

/**
 * @summary Fetches information about the currently authenticated user.
 * @returns {Promise<Object>} A promise that resolves to a JSON object
 * containing user information.
 */
export function whoami() {
  return fetch('/.sso/', {
    method: 'POST',
  }).then(r => {
    if (!r.ok) {
      throw new Error(`HTTP error, status: ${r.status}`);
    }
    return r.json();
  });
}

/** @type {string} The currently active language code (e.g., 'en', 'fr-CA'). */
let currentLang = 'en';
/** @type {Object<string, string>} A map of translation keys to their string values for the current language. */
let langData = {};

/**
 * @summary Translates a given key into the current language.
 * @param {string} key The translation key to look up.
 * @returns {string} The translated string, or a placeholder '###key###' if the
 * key is not found.
 */
export function translate(key) {
  const value = langData[key];
  if (!value) {
    return '###' + key + '###';
  }
  return value;
}

/**
 * @summary Sets the active language by fetching translation data from the server.
 * @description It takes a list of preferred languages (e.g., from navigator.languages),
 * expands it to include variants (e.g., 'en-US' -> 'en'), and requests the
 * best matching translation file from the server. If no match is found, it
 * defaults to 'en'.
 * @param {string[]} langs An array of language codes.
 * @returns {Promise<void>}
 */
function setLanguage(langs) {
  let opts = [];
  for (let lang of langs) {
    opts.push(lang);
    const m = lang.split('-');
    if (m.length === 3) {
      opts.push(m[0]+'-'+m[2]);
      opts.push(m[0]+'-'+m[1]);
    }
    if (m.length > 1) {
      opts.push(m[0]);
    }
  }
  return fetch('/.sso/languages.json', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: 'lang='+opts.map(encodeURIComponent).join(','),
    })
    .then(r => r.json())
    .then(data => {
      for (let opt of opts) {
        if (data[opt]) {
          currentLang = opt;
          langData = data[opt];
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

/**
 * @summary Applies translations to the current document.
 * @description This async function performs several steps:
 * 1. Fetches the appropriate language data by calling setLanguage().
 * 2. Scans the DOM for all elements with a `tkey` attribute.
 * 3. Replaces the textContent (or placeholder) of each element with its translation.
 * 4. Sets the `lang` and `dir` (text direction) attributes on the <html> element.
 * 5. If any translations were applied and a language selector doesn't exist,
 *    it dynamically creates and adds a `<select>` element to the page to
 *    allow users to switch languages.
 * @param {string} [lang] - An optional language code to force a specific language.
 * If not provided, it defaults to the browser's `navigator.languages`.
 */
async function applyTranslations(lang) {
  await setLanguage(lang?[lang]:navigator.languages);
  let changed = false;
  // Find all elements with a `tkey` attribute and replace their content.
  document.querySelectorAll('[tkey]').forEach(e => {
    const value = translate(e.getAttribute('tkey'));
    if (e.tagName === 'INPUT' && e.hasAttribute('placeholder')) {
      e.setAttribute('placeholder', value);
    } else {
      e.textContent = value;
    }
    changed = true;
  });
  // If translations were applied, update the document's lang and dir.
  if (changed) {
    const html = document.querySelector('HTML');
    html.setAttribute('lang', currentLang);
    html.setAttribute('dir', translate('DIR') === 'rtl' ? 'rtl' : 'ltr');
  }
  // If translations were applied and no language selector exists, create one.
  if (changed && !document.getElementById('lang-selector')) {
    const b = document.createElement('select');
    b.id = 'lang-selector';
    b.addEventListener('change', () => {
      console.log('Language selector changed!');
      const s = b.options[b.selectedIndex].value;
      console.log(`Selected language: ${s}`);
      if (s !== currentLang) {
        console.log('Applying new translations...');
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
    // Populate the selector with available languages from the server.
    return fetch('/.sso/languages.json', {method: 'POST'}).then(r => r.json()).then(r => {
      for (let key in r) {
        const o = document.createElement('option');
        o.value = key;
        o.setAttribute('lang', key);
        o.selected = key === currentLang;
        o.textContent = r[key].lang;
        b.appendChild(o);
      }
    });
  }
}

/**
 * Kicks off the translation process once the initial HTML document has been
 * completely loaded and parsed.
 */
document.addEventListener('DOMContentLoaded', () => applyTranslations());
