// Applies the saved theme before first paint. Loaded as a same-origin file because the CSP forbids inline scripts.
// The only value read is the non-secret UI preference written by src/lib/prefs.ts.
(function () {
  try {
    var pref = window.localStorage.getItem('dranzo.theme');
    var dark = pref === 'dark' || (pref !== 'light' && window.matchMedia('(prefers-color-scheme: dark)').matches);
    if (dark) document.documentElement.classList.add('dark');
  } catch (e) {
    /* storage unavailable: stay on the light default */
  }
})();
