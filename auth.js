/* Whisper Rose auth (client-side demo)
 *
 * There is no server in this project, so accounts live in the browser's
 * localStorage. Passwords are never stored in plain text: each one is salted and
 * run through PBKDF2 (SHA-256, 100k iterations) using the Web Crypto API.
 * That makes the flow behave like a real login, but it is NOT a substitute for a
 * backend. Anyone with access to this browser profile can read the stored data.
 *
 * Exposes a single global: window.Auth
 */
(function (global) {
  'use strict';

  var USERS_KEY = 'comerence.users';
  var SESSION_KEY = 'comerence.session';
  var ATTEMPTS_KEY = 'comerence.attempts';
  var MAX_ATTEMPTS = 5;
  var LOCK_MS = 30 * 1000;
  var REMEMBER_MS = 30 * 24 * 60 * 60 * 1000;
  var SESSION_MS = 12 * 60 * 60 * 1000;
  var PBKDF2_ITERATIONS = 100000;
  var DUMMY_SALT = 'AAAAAAAAAAAAAAAAAAAAAA==';

  /* ---------- storage helpers ---------- */

  function read(store, key, fallback) {
    try {
      var raw = store.getItem(key);
      return raw ? JSON.parse(raw) : fallback;
    } catch (e) {
      return fallback;
    }
  }

  function write(store, key, value) {
    try {
      store.setItem(key, JSON.stringify(value));
      return true;
    } catch (e) {
      return false;
    }
  }

  function getUsers() {
    var users = read(localStorage, USERS_KEY, []);
    return Array.isArray(users) ? users : [];
  }

  function saveUsers(users) {
    return write(localStorage, USERS_KEY, users);
  }

  /* ---------- crypto helpers ---------- */

  function toB64(buf) {
    var bytes = new Uint8Array(buf);
    var bin = '';
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }

  function fromB64(b64) {
    var bin = atob(b64);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  function randomId() {
    var bytes = global.crypto.getRandomValues(new Uint8Array(16));
    return Array.prototype.map.call(bytes, function (b) {
      return ('0' + b.toString(16)).slice(-2);
    }).join('');
  }

  async function derive(password, saltB64) {
    if (!global.crypto || !global.crypto.subtle) throw new Error('crypto-unavailable');
    var key = await global.crypto.subtle.importKey(
      'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']
    );
    var bits = await global.crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: fromB64(saltB64), iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
      key,
      256
    );
    return toB64(bits);
  }

  async function makeCredentials(password) {
    var salt = toB64(global.crypto.getRandomValues(new Uint8Array(16)));
    return { salt: salt, hash: await derive(password, salt) };
  }

  function safeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
  }

  /* ---------- verifying Google / Apple ID tokens (real crypto, no backend) ----------
   *
   * Google and Apple both hand back a signed JWT ("ID token") after the person signs
   * in. This site has no server, so instead of sending that token to a backend to
   * verify (the normal, more robust approach), we verify its RS256 signature right
   * here in the browser against the provider's own public keys, and check that it
   * hasn't expired and was actually issued for THIS app. That stops a page from
   * forging a token, but it's still a client-only trust model: someone with access to
   * this browser's devtools can still write directly to localStorage. For anything
   * where that matters (real payments, account recovery, admin access) put a real
   * backend in front of this before launch.
   */

  var jwksCache = {};

  async function fetchJwks(url) {
    if (jwksCache[url]) return jwksCache[url];
    var res = await fetch(url);
    if (!res.ok) throw new Error('jwks-fetch-failed');
    var data = await res.json();
    jwksCache[url] = data;
    return data;
  }

  function base64UrlToBytes(b64url) {
    var b64 = String(b64url).replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) b64 += '=';
    var bin = atob(b64);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  function decodeJwtPart(part) {
    return JSON.parse(new TextDecoder().decode(base64UrlToBytes(part)));
  }

  async function verifyIdToken(idToken, options) {
    var parts = String(idToken || '').split('.');
    if (parts.length !== 3) throw new Error('malformed-token');

    var header = decodeJwtPart(parts[0]);
    var payload = decodeJwtPart(parts[1]);
    var now = Math.floor(Date.now() / 1000);

    if (!payload.exp || payload.exp < now) throw new Error('token-expired');

    var issuers = Array.isArray(options.issuer) ? options.issuer : [options.issuer];
    if (issuers.indexOf(payload.iss) === -1) throw new Error('bad-issuer');

    var aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (aud.indexOf(options.audience) === -1) throw new Error('bad-audience');

    var jwks = await fetchJwks(options.jwksUrl);
    var jwk = (jwks.keys || []).find(function (k) { return k.kid === header.kid; });
    if (!jwk) throw new Error('unknown-signing-key');

    var key = await global.crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify']
    );
    var signedData = new TextEncoder().encode(parts[0] + '.' + parts[1]);
    var signature = base64UrlToBytes(parts[2]);
    var valid = await global.crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, key, signature, signedData);
    if (!valid) throw new Error('bad-signature');

    return payload;
  }

  // Google's iss claim can be either form; both are valid. See Google's OpenID config
  // at https://accounts.google.com/.well-known/openid-configuration
  function verifyGoogleIdToken(idToken, clientId) {
    return verifyIdToken(idToken, {
      jwksUrl: 'https://www.googleapis.com/oauth2/v3/certs',
      issuer: ['https://accounts.google.com', 'accounts.google.com'],
      audience: clientId,
    });
  }

  // Apple's OpenID config: https://appleid.apple.com/.well-known/openid-configuration
  function verifyAppleIdToken(idToken, clientId) {
    return verifyIdToken(idToken, {
      jwksUrl: 'https://appleid.apple.com/auth/keys',
      issuer: 'https://appleid.apple.com',
      audience: clientId,
    });
  }

  /* ---------- validation ---------- */

  // Accounts, sessions and the cart all live in this origin's localStorage, so they
  // only follow you between pages loaded from the exact same address. Useful for
  // showing people why "my saved login isn't there anymore" happens (file:// vs
  // http://localhost:8080, http vs https, or a different port, are all separate stores).
  function storageOrigin() {
    return global.location.protocol === 'file:'
      ? global.location.href.split('?')[0].split('#')[0]
      : global.location.origin;
  }

  function normalizeEmail(email) {
    return String(email || '').trim().toLowerCase();
  }

  function isValidEmail(value) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
  }

  function validatePassword(pw) {
    if (pw.length < 8) return 'Use at least 8 characters.';
    if (!/[A-Za-z]/.test(pw) || !/\d/.test(pw)) return 'Include at least one letter and one number.';
    return '';
  }

  function passwordStrength(pw) {
    if (!pw) return { score: 0, label: '' };
    if (pw.length < 8) return { score: 1, label: 'Too short' };
    var score = 1;
    if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
    if (/\d/.test(pw)) score++;
    if (/[^A-Za-z0-9]/.test(pw) || pw.length >= 14) score++;
    score = Math.min(score, 4);
    return { score: score, label: ['', 'Weak', 'Fair', 'Good', 'Strong'][score] };
  }

  /* ---------- lockout after repeated failures ---------- */

  function lockRemaining(email) {
    var all = read(localStorage, ATTEMPTS_KEY, {});
    var entry = all[email];
    if (!entry || !entry.until) return 0;
    return Math.max(0, entry.until - Date.now());
  }

  function registerFailure(email) {
    var all = read(localStorage, ATTEMPTS_KEY, {});
    var entry = all[email] || { count: 0, until: 0 };
    if (entry.until && entry.until <= Date.now()) entry = { count: 0, until: 0 };
    entry.count += 1;
    if (entry.count >= MAX_ATTEMPTS) {
      entry.until = Date.now() + LOCK_MS;
      entry.count = 0;
    }
    all[email] = entry;
    write(localStorage, ATTEMPTS_KEY, all);
    return entry;
  }

  function clearFailures(email) {
    var all = read(localStorage, ATTEMPTS_KEY, {});
    delete all[email];
    write(localStorage, ATTEMPTS_KEY, all);
  }

  /* ---------- sessions ---------- */

  function publicUser(user) {
    return { id: user.id, name: user.name, email: user.email, provider: user.provider };
  }

  function startSession(user, remember) {
    var session = {
      uid: user.id,
      token: randomId(),
      remember: !!remember,
      expires: Date.now() + (remember ? REMEMBER_MS : SESSION_MS)
    };
    endSession();
    write(remember ? localStorage : sessionStorage, SESSION_KEY, session);
    return session;
  }

  function endSession() {
    try { localStorage.removeItem(SESSION_KEY); } catch (e) {}
    try { sessionStorage.removeItem(SESSION_KEY); } catch (e) {}
  }

  function currentUser() {
    var session = read(sessionStorage, SESSION_KEY, null) || read(localStorage, SESSION_KEY, null);
    if (!session || !session.uid) return null;
    if (session.expires && session.expires < Date.now()) {
      endSession();
      return null;
    }
    var user = getUsers().find(function (u) { return u.id === session.uid; });
    if (!user) {
      endSession();
      return null;
    }
    return publicUser(user);
  }

  /* ---------- account actions ---------- */

  async function signUp(input) {
    var name = String(input.name || '').trim();
    var email = normalizeEmail(input.email);
    var users = getUsers();

    if (users.some(function (u) { return u.email === email; })) {
      return { ok: false, code: 'exists', field: 'email', message: 'An account with this email already exists.' };
    }

    var cred = await makeCredentials(input.password);
    var user = {
      id: randomId(),
      name: name,
      email: email,
      salt: cred.salt,
      hash: cred.hash,
      provider: 'password',
      createdAt: Date.now()
    };
    users.push(user);
    if (!saveUsers(users)) {
      return { ok: false, code: 'storage', message: 'Your browser blocked saving the account. Check that storage is enabled.' };
    }
    startSession(user, true);
    return { ok: true, user: publicUser(user) };
  }

  async function logIn(input) {
    var email = normalizeEmail(input.email);

    var wait = lockRemaining(email);
    if (wait > 0) {
      return { ok: false, code: 'locked', retryIn: wait, message: 'Too many failed attempts.' };
    }

    var allUsers = getUsers();
    var user = allUsers.find(function (u) { return u.email === email; });
    var good = false;

    if (user && user.hash) {
      good = safeEqual(await derive(input.password, user.salt), user.hash);
    } else {
      // Do the same amount of work so timing doesn't reveal whether the account exists.
      await derive(input.password, DUMMY_SALT);
    }

    if (!good) {
      var entry = registerFailure(email);
      if (entry.until && entry.until > Date.now()) {
        return { ok: false, code: 'locked', retryIn: entry.until - Date.now(), message: 'Too many failed attempts.' };
      }
      // accountsHere doesn't say whether THIS email exists (that would leak account
      // existence) — it only flags that there are zero accounts stored under the
      // current origin at all, which is the #1 cause of "my saved login stopped
      // working": localStorage is scoped per-origin, so file:// and
      // http://localhost:8080 (or two different ports) each have their own, empty store.
      return {
        ok: false,
        code: 'invalid',
        message: 'Incorrect email or password.',
        accountsHere: allUsers.length,
      };
    }

    clearFailures(email);
    startSession(user, input.remember);
    return { ok: true, user: publicUser(user) };
  }

  function logOut() {
    endSession();
  }

  function accountExists(email) {
    email = normalizeEmail(email);
    return getUsers().some(function (u) { return u.email === email; });
  }

  async function resetPassword(email, newPassword) {
    email = normalizeEmail(email);
    var users = getUsers();
    var user = users.find(function (u) { return u.email === email; });
    if (!user) return { ok: false, code: 'not-found', message: "We couldn't find an account with that email." };
    var cred = await makeCredentials(newPassword);
    user.salt = cred.salt;
    user.hash = cred.hash;
    saveUsers(users);
    clearFailures(email);
    return { ok: true };
  }

  function continueWithProvider(provider, input) {
    var email = normalizeEmail(input.email);
    var users = getUsers();
    var user = users.find(function (u) { return u.email === email; });
    var isNew = false;
    if (!user) {
      user = {
        id: randomId(),
        name: String(input.name || '').trim() || email.split('@')[0],
        email: email,
        provider: provider.toLowerCase(),
        createdAt: Date.now()
      };
      users.push(user);
      saveUsers(users);
      isNew = true;
    }
    startSession(user, true);
    return { ok: true, user: publicUser(user), isNew: isNew };
  }

  // Verifies a real Google or Apple ID token (see the verify* helpers above) and
  // signs the person in, creating an account on first sign-in. This is what the
  // "Continue with Google / Apple" buttons call once real credentials are configured;
  // until then the pages fall back to the socialSignIn() demo below.
  async function federatedSignIn(provider, params) {
    var key = String(provider || '').toLowerCase();
    try {
      var payload;
      if (key === 'google') {
        payload = await verifyGoogleIdToken(params.idToken, params.clientId);
      } else if (key === 'apple') {
        payload = await verifyAppleIdToken(params.idToken, params.clientId);
      } else {
        return { ok: false, message: 'Unsupported sign-in provider.' };
      }

      var email = normalizeEmail(payload.email);
      if (!email) {
        return { ok: false, message: 'That account has no email address to sign in with.' };
      }

      var name = (params.fallbackName && String(params.fallbackName).trim()) ||
        (payload.name ? String(payload.name).trim() : '');
      return continueWithProvider(key, { name: name, email: email });
    } catch (err) {
      return {
        ok: false,
        message: 'We couldn\u2019t verify that ' + provider + ' sign-in. Please try again.',
        error: err && err.message
      };
    }
  }

  /* ---------- navigation helpers ---------- */

  function nextUrl(fallback) {
    var next = new URLSearchParams(global.location.search).get('next');
    // Only allow plain local page names, never external URLs.
    return next && /^[\w-]+\.html$/.test(next) ? next : (fallback || 'comerence.html');
  }

  function requireAuth() {
    if (currentUser()) return true;
    var page = global.location.pathname.split('/').pop() || 'comerence.html';
    global.location.replace('login.html?next=' + encodeURIComponent(page));
    return false;
  }

  function onChange(callback) {
    global.addEventListener('storage', function (e) {
      if (e.key === SESSION_KEY || e.key === USERS_KEY) callback(currentUser());
    });
  }

  /* ---------- UI: toast ---------- */

  function toast(message, kind) {
    var region = document.getElementById('toastRegion');
    if (!region) {
      region = document.createElement('div');
      region.id = 'toastRegion';
      region.className = 'toast-region';
      region.setAttribute('aria-live', 'polite');
      document.body.appendChild(region);
    }
    var node = document.createElement('div');
    node.className = 'toast' + (kind ? ' toast-' + kind : '');
    node.textContent = message;
    region.appendChild(node);
    setTimeout(function () {
      node.classList.add('is-leaving');
      setTimeout(function () { node.remove(); }, 250);
    }, 3200);
  }

  /* ---------- UI: modal form ---------- */

  function escapeHtml(text) {
    return String(text).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  // Resolves with the submitted values, or null if the person cancels.
  // onSubmit(values) may return { field, message } to show an error, or nothing to accept.
  function modal(config) {
    return new Promise(function (resolve) {
      var opener = document.activeElement;
      var backdrop = document.createElement('div');
      backdrop.className = 'modal-backdrop';

      var fieldsHtml = (config.fields || []).map(function (f) {
        return '<label class="field"><span>' + escapeHtml(f.label) + '</span>' +
          '<input type="' + escapeHtml(f.type || 'text') + '" name="' + escapeHtml(f.name) + '"' +
          ' placeholder="' + escapeHtml(f.placeholder || '') + '"' +
          ' autocomplete="' + escapeHtml(f.autocomplete || 'off') + '" />' +
          '<span class="field-error" data-error-for="' + escapeHtml(f.name) + '"></span></label>';
      }).join('');

      backdrop.innerHTML =
        '<div class="modal" role="dialog" aria-modal="true" aria-labelledby="modalTitle">' +
          '<h2 id="modalTitle"></h2>' +
          '<p class="modal-intro"></p>' +
          '<form novalidate>' + fieldsHtml +
            '<span class="field-error" data-error-for="_form"></span>' +
            '<div class="modal-actions">' +
              '<button type="button" class="secondary-btn" data-cancel>Cancel</button>' +
              '<button type="submit" class="primary-btn"></button>' +
            '</div>' +
          '</form>' +
        '</div>';

      backdrop.querySelector('#modalTitle').textContent = config.title;
      backdrop.querySelector('.modal-intro').textContent = config.intro || '';
      var submitBtn = backdrop.querySelector('button[type="submit"]');
      submitBtn.textContent = config.submitLabel || 'Continue';

      var form = backdrop.querySelector('form');
      document.body.appendChild(backdrop);
      var firstInput = form.querySelector('input');
      if (firstInput) firstInput.focus();

      function close(result) {
        document.removeEventListener('keydown', onKey);
        backdrop.remove();
        if (opener && opener.focus) opener.focus();
        resolve(result);
      }

      function onKey(e) {
        if (e.key === 'Escape') close(null);
      }
      document.addEventListener('keydown', onKey);

      backdrop.addEventListener('mousedown', function (e) {
        if (e.target === backdrop) close(null);
      });
      form.querySelector('[data-cancel]').addEventListener('click', function () { close(null); });

      form.addEventListener('submit', async function (e) {
        e.preventDefault();
        var values = {};
        (config.fields || []).forEach(function (f) {
          values[f.name] = form.elements[f.name].value;
        });
        form.querySelectorAll('[data-error-for]').forEach(function (n) { n.textContent = ''; });
        form.querySelectorAll('input').forEach(function (n) { n.classList.remove('has-error'); });

        submitBtn.disabled = true;
        var result;
        try {
          result = config.onSubmit ? await config.onSubmit(values) : null;
        } catch (err) {
          result = { message: 'Something went wrong. Please try again.' };
        }
        submitBtn.disabled = false;

        if (result && result.message) {
          var target = form.querySelector('[data-error-for="' + (result.field || '_form') + '"]') ||
            form.querySelector('[data-error-for="_form"]');
          target.textContent = result.message;
          if (result.field && form.elements[result.field]) {
            form.elements[result.field].classList.add('has-error');
            form.elements[result.field].focus();
          }
          return;
        }
        close(values);
      });
    });
  }

  // Simulated "Continue with Google / Apple". No request is made to either provider.
  async function socialSignIn(provider) {
    var values = await modal({
      title: 'Continue with ' + provider,
      intro: 'Demo storefront: nothing is sent to ' + provider + '. Enter the account you want to use.',
      submitLabel: 'Continue',
      fields: [
        { name: 'name', label: 'Name', placeholder: 'Jordan Taylor', autocomplete: 'name' },
        { name: 'email', label: 'Email address', type: 'email', placeholder: 'you@example.com', autocomplete: 'email' }
      ],
      onSubmit: function (v) {
        if (!isValidEmail(normalizeEmail(v.email))) {
          return { field: 'email', message: 'Enter a valid email address.' };
        }
      }
    });
    if (!values) return null;
    return continueWithProvider(provider, values);
  }

  /* ---------- UI: account menu in the storefront header ---------- */

  function mountNavAccount(slot) {
    if (!slot) return;

    function render() {
      var user = currentUser();
      slot.innerHTML = '';

      if (!user) {
        var link = document.createElement('a');
        link.href = 'login.html';
        link.className = 'icon-btn';
        link.setAttribute('aria-label', 'Log in');
        link.textContent = '\uD83D\uDC64';
        slot.appendChild(link);
        return;
      }

      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'avatar-btn';
      btn.setAttribute('aria-haspopup', 'true');
      btn.setAttribute('aria-expanded', 'false');
      btn.setAttribute('aria-label', 'Account menu for ' + user.name);
      btn.textContent = (user.name || user.email).trim().charAt(0).toUpperCase();

      var menu = document.createElement('div');
      menu.className = 'user-menu';
      menu.hidden = true;
      menu.innerHTML =
        '<div class="user-menu-head"><strong></strong><span></span></div>' +
        '<button type="button" class="user-menu-item" data-logout>Log out</button>';
      menu.querySelector('strong').textContent = user.name;
      menu.querySelector('span').textContent = user.email;

      function setOpen(open) {
        menu.hidden = !open;
        btn.setAttribute('aria-expanded', String(open));
      }

      btn.addEventListener('click', function (e) {
        e.stopPropagation();
        setOpen(menu.hidden);
      });
      menu.addEventListener('click', function (e) { e.stopPropagation(); });
      menu.querySelector('[data-logout]').addEventListener('click', function () {
        logOut();
        render();
        toast('You have been logged out.');
      });
      document.addEventListener('click', function () { setOpen(false); });
      document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') setOpen(false);
      });

      slot.appendChild(btn);
      slot.appendChild(menu);
    }

    render();
    onChange(render);
  }

  global.Auth = {
    currentUser: currentUser,
    signUp: signUp,
    logIn: logIn,
    logOut: logOut,
    accountExists: accountExists,
    resetPassword: resetPassword,
    socialSignIn: socialSignIn,
    federatedSignIn: federatedSignIn,
    requireAuth: requireAuth,
    nextUrl: nextUrl,
    onChange: onChange,
    storageOrigin: storageOrigin,
    normalizeEmail: normalizeEmail,
    isValidEmail: isValidEmail,
    validatePassword: validatePassword,
    passwordStrength: passwordStrength,
    modal: modal,
    toast: toast,
    mountNavAccount: mountNavAccount
  };
})(window);