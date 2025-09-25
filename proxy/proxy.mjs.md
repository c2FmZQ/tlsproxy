# `proxy.mjs` - Client-Side Proxy Helper

This JavaScript module provides essential client-side functionality for HTML pages served by `tlsproxy`. It handles CSRF protection, session management, and internationalization (i18n) dynamically in the user's browser.

## Features

### 1. Automatic CSRF Protection

The script automatically protects against Cross-Site Request Forgery (CSRF) attacks.

- It wraps the standard `window.fetch` function.
- Before any `fetch` request is sent, it reads the session ID from the `__tlsproxySid` cookie.
- It then adds the session ID to the request headers as `x-csrf-token`.

This process is automatic. Any page that includes this module will have its `fetch` requests protected.

### 2. Session Management

The module exports functions to manage the user's authentication session.

- **`logout()`**:
  - Sends a `POST` request to the `/.sso/logout` endpoint to terminate the session on the backend.
  - Upon success, it redirects the user to the logout page.

- **`whoami()`**:
  - Sends a `POST` request to the `/.sso/` endpoint.
  - Returns a promise that resolves with a JSON object containing information about the currently authenticated user.

### 3. Internationalization (i18n)

The script provides dynamic, client-side translation of web pages.

- **Language Detection**: On page load, it detects the user's preferred languages from `navigator.languages`.
- **Translation Loading**: It fetches the appropriate language file from `/.sso/languages.json` based on the detected language. It has a fallback mechanism to find the best-matching language or default to English (`en`).
- **Dynamic Translation**:
  - It scans the document for any HTML elements that have a `tkey` attribute.
  - It replaces the content (or placeholder text for inputs) of these elements with the translated string corresponding to the `tkey` value.
  - It sets the `lang` and `dir` (text direction, e.g., `ltr` or `rtl`) attributes on the `<html>` tag.
- **Language Selector**:
  - If a language selector element (with `id="lang-selector"`) does not already exist on the page, the script dynamically creates and appends one.
  - This `<select>` element allows the user to switch languages on the fly. It is populated with all available languages from the backend.

## Usage

This script is intended to be included as a module in HTML pages served by `tlsproxy`, such as the login, logout, or SSO status pages.

```html
<script type="module">
  import { logout, whoami } from './proxy.mjs';

  // Example: Add a logout button
  const logoutButton = document.getElementById('logout-btn');
  logoutButton.addEventListener('click', () => {
    logout();
  });

  // Example: Display user's name
  whoami().then(user => {
    document.getElementById('user-name').textContent = user.name;
  });
</script>

<!-- Example of an element that will be translated -->
<h1 tkey="welcome_message">Welcome</h1>
```
