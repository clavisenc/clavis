/*
 * Cookieless counts for encrypt.html and open.html: one visit, and one event per file
 * encrypted or opened. Each count is a single image request to the site's GoatCounter carrying
 * only a fixed name ("encrypt-file"), the page title and the referring site's address (origin
 * only). No file names, sizes, contents or passwords. The pages' security policy allows this
 * one image host and still refuses every connection (connect-src 'none').
 * Nothing is counted on a local copy (file://, localhost), so tests and previews never count.
 */
(function () {
  "use strict";
  const ENDPOINT = "https://clavis.goatcounter.com/count";
  const live = /^https?:$/.test(location.protocol)
    && !/^(localhost|127\.|\[?::1\]?|0\.0\.0\.0)/.test(location.hostname);

  function ping(params) {
    if (!live) return;
    try {
      const q = new URLSearchParams(params);
      q.set("rnd", Math.random().toString(36).slice(2));
      const img = new Image();
      img.referrerPolicy = "no-referrer";
      img.src = ENDPOINT + "?" + q.toString();
    } catch (e) { /* counting must never break the page */ }
  }

  function referrerOrigin() {
    try { return document.referrer ? new URL(document.referrer).origin : ""; } catch (e) { return ""; }
  }

  window.ClavisCount = {
    /** The visit: the page's own path, title and where the visitor came from (site only). */
    page() {
      const ref = new URLSearchParams(location.search).get("ref");
      ping({ p: location.pathname, t: document.title, r: ref ? "ref:" + ref : referrerOrigin() });
    },
    /** A named event, e.g. "encrypt-file". Only the name is sent. */
    event(name) { ping({ p: name, t: name, e: "true" }); },
  };
  window.ClavisCount.page();
})();
