/* Free 7-day trial keys (trial.html). Sends only This PC's code and the plan to our trial service,
   which answers with a key for that PC, or says the PC has already had its trial. */
(function () {
  "use strict";
  const form = document.getElementById("trial-form");
  if (!form) return;
  const API = "https://api.clavisenc.com/trial";
  const $ = id => document.getElementById(id);
  const code = $("trial-code"), msg = $("trial-msg"), done = $("trial-done"), used = $("trial-used");
  const button = form.querySelector("button[type=submit]");
  const label = button.textContent;

  // The app can open this page with the code filled in: trial.html?code=K7Q2-M9XD
  const given = new URLSearchParams(location.search).get("code");
  if (given && /^[0-9A-Za-z-]{8,12}$/.test(given)) code.value = given.toUpperCase();

  const planName = p => (p === "premium" ? "Premium" : "Pro");
  const day = iso => new Date(iso + "T12:00:00").toLocaleDateString(undefined, { year: "numeric", month: "long", day: "numeric" });
  const say = text => { msg.textContent = text; msg.hidden = !text; };
  const count = (path, title) => {
    const gc = window.goatcounter;
    if (gc && typeof gc.count === "function") gc.count({ path, title, event: true });
  };
  const fill = (box, plan, expires) => {
    box.querySelectorAll("[data-plan]").forEach(el => (el.textContent = planName(plan)));
    box.querySelectorAll("[data-expires]").forEach(el => (el.textContent = day(expires)));
    box.hidden = false;
    box.focus({ preventScroll: true });
    box.scrollIntoView({ behavior: "smooth", block: "nearest" });
  };
  code.addEventListener("input", () => say(""));

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
    button.disabled = true;
    button.textContent = "Making your key…";
    try {
      const r = await fetch(API, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ code: value, plan }) });
      const d = await r.json().catch(() => ({}));
      if (r.ok && d.key) {
        $("trial-key").value = d.key;
        form.hidden = true;
        fill(done, d.plan, d.expires);
        count(d.again ? "trial-shown-again" : "trial-started", d.again ? "Trial key shown again" : "Trial started");
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
