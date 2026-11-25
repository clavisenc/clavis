/* Runs in the <head> of encrypt.html and open.html, whose security policy allows no inline script:
   the same two lines the other pages carry inline. site.js adds the launch-offer bar later, so its
   height is reserved now and the page doesn't shift down after the first paint. */
(function (d) {
  d.classList.add("js");
  try { if (Date.now() <= new Date("2026-11-30T23:59:59").getTime() && sessionStorage.getItem("offer-closed") !== "1") d.classList.add("has-offer"); } catch (e) {}
})(document.documentElement);
