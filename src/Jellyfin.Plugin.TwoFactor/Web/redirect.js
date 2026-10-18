// Injected into jellyfin-web's index.html by the TwoFactor plugin.
// It sends the browser to the two-factor login page instead of the web client's own login page.
// The page lives at [BaseUrl]/TwoFactor/Login, next to this script.
(function () {
  'use strict';

  var script = document.currentScript;
  if (!script || !script.src) { return; }
  var loginUrl = script.src.replace(/redirect\.js(\?.*)?$/i, 'Login');

  // The "Administrar verificación en dos pasos" entry that the server adds to the menu (config.json) is the same for every
  // user, because config.json is requested without any identity. Hide it by default and show it only if the signed-in user
  // is an administrator (GET Users/Me). Cosmetic only: Admin/Reset checks the administrator policy on the server.
  // If anything fails the entry stays hidden; the page is still reachable at [BaseUrl]/TwoFactor/Admin.
  try {
    var hideAdminLink = document.createElement('style');
    hideAdminLink.textContent = 'a[href$="TwoFactor/Admin"]{display:none !important}';
    (document.head || document.documentElement).appendChild(hideAdminLink);
    var savedServers = (JSON.parse(localStorage.getItem('jellyfin_credentials') || '{}').Servers || [])
      .filter(function (server) { return server && server.AccessToken; })
      .sort(function (a, b) { return (b.DateLastAccessed || 0) - (a.DateLastAccessed || 0); });
    var deviceId = localStorage.getItem('_deviceId2');
    if (savedServers.length && deviceId) {
      var auth = 'MediaBrowser Client="Jellyfin Web", Device="Web Browser", DeviceId="' + deviceId.replace(/"/g, '') +
        '", Version="1", Token="' + String(savedServers[0].AccessToken).replace(/"/g, '') + '"';
      fetch(script.src.replace(/TwoFactor\/redirect\.js(\?.*)?$/i, 'Users/Me'), { headers: { Authorization: auth }, cache: 'no-store' })
        .then(function (response) { return response.ok ? response.json() : null; })
        .then(function (me) {
          var policy = me && (me.Policy || me.policy);
          if (policy && (policy.IsAdministrator === true || policy.isAdministrator === true)) { hideAdminLink.remove(); }
        })
        .catch(function () { /* stays hidden */ });
    }
  } catch (e) { /* ignore */ }

  // Sign-in without "Remember me": the login page marks the session as browser-session-only (localStorage flag plus a
  // sessionStorage flag). If the sessionStorage flag is gone, the browser was closed since then, so the token is dropped.
  try {
    if (localStorage.getItem('tf-session-only') && !sessionStorage.getItem('tf-session-only')) {
      var stored = JSON.parse(localStorage.getItem('jellyfin_credentials') || '{}');
      if (stored && Array.isArray(stored.Servers)) {
        stored.Servers.forEach(function (server) { if (server) { delete server.AccessToken; delete server.UserId; } });
        localStorage.setItem('jellyfin_credentials', JSON.stringify(stored));
      }
      localStorage.removeItem('tf-session-only');
    }
  } catch (e) { /* ignore */ }
  // Escape hatch to the original login page: open /web/?nativelogin=1. It is one-shot: it only lasts for this
  // page load (kept in memory, not in storage). The parameter is removed from the address bar, so reloading
  // or opening /web/ again goes back to the two-factor page.
  try { sessionStorage.removeItem('tf-native-login'); } catch (e) { /* flag left by an older version */ }
  var params = new URLSearchParams(location.search);
  if (params.get('nativelogin') === '1') {
    params.delete('nativelogin');
    var rest = params.toString();
    try { history.replaceState(history.state, '', location.pathname + (rest ? '?' + rest : '') + location.hash); } catch (e) { /* ignore */ }
    return;
  }

  // Routes that work without a session and must not be redirected.
  var PUBLIC_ROUTES = /^#\/(wizard|addserver|selectserver)(\/|\?|$)/i;
  var redirected = false;

  function isLoginRoute() {
    // jellyfin-web uses a hash router: /web/#/login?serverid=...
    return /^#\/login(\.html)?(\?|\/|$)/i.test(location.hash);
  }

  function hasSavedSession() {
    try {
      var credentials = JSON.parse(localStorage.getItem('jellyfin_credentials') || '{}');
      return !!(credentials && Array.isArray(credentials.Servers) &&
        credentials.Servers.some(function (server) { return server && server.AccessToken; }));
    } catch (e) {
      return true; // unknown: let the web client decide
    }
  }

  function hide() {
    // Hide everything, with the same background as the login page, so that nothing of the web client is painted.
    document.documentElement.style.cssText = 'background:#101010;visibility:hidden';
  }

  function leave() {
    if (redirected) { return; }
    redirected = true;
    hide();
    location.replace(loginUrl);
  }

  // The Jellyfin Android app registers window.NativeInterface in its WebView. It only treats the page as loaded
  // once the WebView has requested the web client's main bundle (JellyfinWebViewClient.shouldInterceptRequest);
  // without that request it shows a spinner and, after 10 seconds, goes back to the server list. Redirecting
  // before the bundle is requested would trigger that, so in the app we request it first. The app answers that
  // request itself, from its own assets, so the real bundle is not downloaded.
  function leaveAfterAppConnects() {
    if (redirected) { return; }
    hide();
    var proceeded = false;
    function proceed() {
      if (proceeded) { return; }
      proceeded = true;
      leave();
    }
    setTimeout(proceed, 1500); // never wait longer than this, whatever happens to the request
    try {
      var bundle = script.getAttribute('data-bundle') || 'main.jellyfin.bundle.js';
      fetch(new URL(bundle, location.href).href, { cache: 'no-store' }).then(proceed, proceed);
    } catch (e) {
      proceed();
    }
  }

  // Without a saved session the web client always ends at its login page, so go now, before it renders anything.
  if (isLoginRoute() || (!hasSavedSession() && !PUBLIC_ROUTES.test(location.hash))) {
    if (typeof window.NativeInterface !== 'undefined') { leaveAfterAppConnects(); } else { leave(); }
    return;
  }

  // With a saved session that turns out to be invalid, the web client navigates to its login route later.
  function check() {
    if (isLoginRoute()) { leave(); }
  }

  window.addEventListener('hashchange', check);
  window.addEventListener('popstate', check);

  // The router navigates with history.pushState/replaceState, which do not fire hashchange.
  ['pushState', 'replaceState'].forEach(function (name) {
    var original = history[name];
    history[name] = function () {
      var result = original.apply(this, arguments);
      check();
      return result;
    };
  });
})();
