/* Free 7-day trial keys (trial.html). Sends This PC's code and the plan to our trial service, which
   answers with a key for that PC, or says the PC has already had its trial. Only if the visitor ticks
   the tips box does it also send their email address (3 trial emails; privacy.html#trial-emails). */
(function () {
  "use strict";
  const form = document.getElementById("trial-form");
  if (!form) return;
  const API = "https://api.clavisenc.com/trial";
  const $ = id => document.getElementById(id);
  const code = $("trial-code"), msg = $("trial-msg"), done = $("trial-done"), used = $("trial-used");
  const button = form.querySelector("button[type=submit]");
  const label = button.textContent;

  // The app can open this page with the code filled in: trial.html?code=K7Q2-M9XD. site.js takes it off the
  // address bar before analytics loads and hands it over here; location.search is read only if site.js didn't run.
  const params = new URLSearchParams(location.search);
  const given = typeof window.clavisTrialCode === "string" ? window.clavisTrialCode : params.get("code");
  if (given && /^[0-9A-Za-z-]{8,12}$/.test(given)) code.value = given.toUpperCase();

  // The pricing cards say which plan: trial.html?plan=pro or ?plan=premium (Premium stays the default)
  const wanted = (params.get("plan") || "").toLowerCase();
  if (wanted === "pro" || wanted === "premium") {
    const radio = form.querySelector('input[name=plan][value="' + wanted + '"]');
    if (radio) radio.checked = true;
  }

  const planName = p => (p === "premium" ? "Premium" : "Pro");
  const day = iso => new Date(iso + "T12:00:00").toLocaleDateString(undefined, { year: "numeric", month: "long", day: "numeric" });
  const say = text => { msg.textContent = text; msg.hidden = !text; };
  const count = (path, title) => {
    const gc = window.goatcounter;
    if (gc && typeof gc.count === "function") gc.count({ path, title, event: true });
  };
  const fill = (box, plan, expires, again) => {
    box.querySelectorAll("[data-again]").forEach(el => (el.hidden = !again));
    box.querySelectorAll("[data-plan]").forEach(el => (el.textContent = planName(plan)));
    box.querySelectorAll("[data-expires]").forEach(el => (el.textContent = day(expires)));
    box.hidden = false;
    box.focus({ preventScroll: true });
    box.scrollIntoView({ behavior: "smooth", block: "nearest" });
  };
  code.addEventListener("input", () => say(""));

  // Optional trial emails. The box ships hidden until they go live; #tips-preview shows it for a test.
  // Unticked (or hidden), the request is exactly {code, plan}, whatever is typed in the field.
  const tips = form.querySelector("[data-trial-tips]"), tick = $("trial-tips"), more = $("trial-tips-more"), email = $("trial-email");
  const note = done.querySelector("[data-tips-note]");
  const EMAIL = /^[^\s@]+@[^\s@.]+(\.[^\s@.]+)+$/;            // the trial service checks the same
  const TIPS = {
    confirm: "Almost done: if this address isn't signed up yet, we've emailed it a link to confirm the tips. Nothing there in a few minutes? Check Junk.",
    failed: "We couldn't sign you up for the tips just now. Your key is fine.",
    off: "The tips emails aren't available right now. Your key is fine.",
  };
  const asking = () => !!(tips && !tips.hidden && tick && tick.checked);
  if (tips && tick && more && email) {
    if (location.hash === "#tips-preview") tips.hidden = false;
    const sync = () => { more.hidden = !tick.checked; tick.setAttribute("aria-expanded", String(tick.checked)); };
    tick.addEventListener("change", () => { sync(); say(""); });
    email.addEventListener("input", () => say(""));
    sync();                                     // a ticked box the browser restored keeps its field
  }
  // Brevo sends people back here after they click the confirm link
  const confirmed = $("trial-confirmed");
  if (confirmed && location.hash === "#tips-confirmed") {
    confirmed.hidden = false;
    confirmed.scrollIntoView({ block: "center" });
  }

  form.addEventListener("submit", async ev => {
    ev.preventDefault();
    say("");
    const plan = (form.querySelector("input[name=plan]:checked") || {}).value;
    const value = code.value.trim();
    if (value.replace(/[^0-9A-Za-z]/g, "").length !== 8) {
      say("Paste This PC's code from Clavis → Settings → License. It's 8 characters, like K7Q2-M9XD.");
      code.focus();
      return;
    }
    if (!plan) { say("Choose Pro or Premium."); return; }
    const withTips = asking();
    const address = withTips ? email.value.trim() : "";
    if (withTips && (!address || address.length > 254 || !EMAIL.test(address))) {
      say("Enter your email address, or untick the box.");
      email.focus();
      return;
    }
    button.disabled = true;
    button.textContent = "Making your key…";
    try {
      const body = withTips ? { code: value, plan, email: address } : { code: value, plan };
      if (withTips) count("trial-tips-asked", "Trial tips asked");   // a count only, never the address
      const r = await fetch(API, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      const d = await r.json().catch(() => ({}));
      if (r.ok && d.key) {
        $("trial-key").value = d.key;
        form.hidden = true;
        if (note) {                               // the service only ever answers confirm, failed or off
          note.textContent = !withTips ? "" : ["confirm", "failed", "off"].includes(d.tips) ? TIPS[d.tips] : TIPS.off;
          note.hidden = !withTips;
        }
        fill(done, d.plan, d.expires, !!d.again);
        count(d.again ? "trial-shown-again" : "trial-started", d.again ? "Trial key shown again" : "Trial started");
        if (!d.again && window.clavisFirmEvent) window.clavisFirmEvent("trial", d.plan);   // email-link visits only (site.js)
      } else if (r.status === 409 && d.used) {
        form.hidden = true;
        fill(used, d.used.plan, d.used.expires);
        count("trial-already-used", "Trial already used");
      } else {
        say(d.error || "Something went wrong. Please try again, or email hello@clavisenc.com.");
      }
    } catch (e) {
      say("We couldn't reach the trial service. Check your connection and try again, or email hello@clavisenc.com.");
    } finally {
      button.disabled = false;
      button.textContent = label;
    }
  });

  $("trial-copy").addEventListener("click", () => {
    const area = $("trial-key"), btn = $("trial-copy");
    const ok = () => { btn.textContent = "Copied"; setTimeout(() => (btn.textContent = "Copy key"), 2000); };
    const pick = () => { area.focus(); area.select(); };
    if (navigator.clipboard) navigator.clipboard.writeText(area.value).then(ok, () => { pick(); });
    else pick();
  });
})();
