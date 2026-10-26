"use strict";
(function () {
  const $ = id => document.getElementById(id);
  const form = $("encForm"), files = $("plainFiles"), drop = $("drop"), list = $("results"), btn = $("encBtn");
  const pw = $("pw"), pw2 = $("pw2"), msg = $("formMsg"), done = $("done");
  const urls = [];
  // The password the files were actually locked with (Copy password), and whether a batch is running:
  // while it runs, nothing on the form can change, so every file gets the password that was checked.
  let usedPassword = "", busy = false;
  const LOCKED = ["pw", "pw2", "plainFiles", "showPw", "suggest", "clearBtn", "encBtn"];
  function lock(on) {
    busy = on;
    LOCKED.forEach(id => { const el = $(id); if (el) el.disabled = on; });
    drop.classList.toggle("is-busy", on);
  }
  ["dragenter", "dragover", "drop"].forEach(t => drop.addEventListener(t, e => {
    if (busy) { e.preventDefault(); e.stopImmediatePropagation(); }
  }, true));
  const size = n => n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(1) + " KB" : n < 1073741824 ? (n / 1048576).toFixed(1) + " MB" : (n / 1073741824).toFixed(2) + " GB";
  const GB = 1024 * 1024 * 1024;
  // Phones keep the encrypted result in memory until it's saved, so they get a lower limit.
  const PHONE = navigator.userAgentData && typeof navigator.userAgentData.mobile === "boolean"
    ? navigator.userAgentData.mobile
    : /Android|iPhone|iPad|iPod|Mobile/i.test(navigator.userAgent) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
  const LIMIT = PHONE ? 1 * GB : 2 * GB;
  const MIN_LENGTH = 10;                       // as the app's "Send with a password"
  const ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";   // the app's one-time passwords: no 0/O, 1/I/L

  if (!window.ClavisEncrypt || !ClavisEncrypt.supported()) {
    $("unsupported").hidden = false;
    btn.disabled = true;
  }

  function say(text) { msg.textContent = text; msg.hidden = !text; }

  function showChosen() {
    const n = files.files.length;
    $("chosen").textContent = n ? (n === 1 ? files.files[0].name : n + " files") + " · " + size([...files.files].reduce((s, f) => s + f.size, 0)) : "No file chosen";
    say("");
  }
  files.addEventListener("change", showChosen);
  ["dragenter", "dragover"].forEach(t => drop.addEventListener(t, e => { e.preventDefault(); drop.classList.add("hot"); }));
  ["dragleave", "drop"].forEach(t => drop.addEventListener(t, e => { e.preventDefault(); drop.classList.remove("hot"); }));
  drop.addEventListener("drop", e => { if (e.dataTransfer.files.length) { files.files = e.dataTransfer.files; showChosen(); } });

  // ── Password: strength, show, suggest ───────────────────────────────────────
  const strength = $("strength"), meter = $("meter");
  function rate() {
    const v = pw.value;
    if (!v) { strength.textContent = ""; meter.style.width = "0"; meter.className = ""; return null; }
    const r = ClavisStrength.estimate(v);
    strength.textContent = "Strength: " + r.label + " · " + r.crackTime + (r.warning ? ". " + r.warning : "");
    meter.style.width = (r.score + 1) * 20 + "%";
    meter.className = "s" + r.score;
    return r;
  }
  pw.addEventListener("input", () => { rate(); say(""); });
  pw2.addEventListener("input", () => say(""));

  $("showPw").addEventListener("click", () => {
    const show = pw.type === "password";
    pw.type = pw2.type = show ? "text" : "password";
    $("showPw").textContent = show ? "Hide" : "Show";
    $("showPw").setAttribute("aria-pressed", String(show));
  });

  function generate() {                        // 4 groups of 5, about 99 bits
    const out = [];
    for (let g = 0; g < 4; g++) {
      let group = "";
      while (group.length < 5) {
        const b = crypto.getRandomValues(new Uint8Array(1))[0];
        if (b < 248) group += ALPHABET[b % ALPHABET.length];   // 248 = 8 * 31: no bias
      }
      out.push(group);
    }
    return out.join("-");
  }
  $("suggest").addEventListener("click", () => {
    pw.value = pw2.value = generate();
    if (pw.type === "password") $("showPw").click();
    rate(); say("");
    $("suggestNote").hidden = false;
  });

  // ── Results ──────────────────────────────────────────────────────────────────
  function row(file) {
    const li = document.createElement("li");
    li.className = "res";
    li.innerHTML = '<div class="res-top"><b class="res-name"></b><span class="res-state">Waiting…</span></div><div class="bar"><i></i></div><div class="res-act"></div>';
    li.querySelector(".res-name").textContent = file.name;
    list.appendChild(li);
    return {
      state: (t, cls) => { const s = li.querySelector(".res-state"); s.textContent = t; s.className = "res-state " + (cls || ""); },
      bar: f => { li.querySelector(".bar i").style.width = Math.round(f * 100) + "%"; },
      done: (name, blob) => {
        li.querySelector(".res-name").textContent = name;
        const url = URL.createObjectURL(blob); urls.push(url);
        const a = document.createElement("a"); a.className = "btn btn-primary small"; a.href = url; a.download = name; a.textContent = "Save " + name;
        li.querySelector(".res-act").appendChild(a);
        li.classList.add("ok");
      },
    };
  }

  function check() {
    if (!files.files.length) return "Choose a file first.";
    const total = [...files.files].reduce((s, f) => s + f.size, 0);
    if (total > LIMIT) return "That's " + size(total) + ". " + (PHONE
      ? "On a phone, this page can encrypt up to 1 GB at a time. Use a computer for bigger files, or the free Clavis Encrypt app."
      : "This page can encrypt up to 2 GB at a time. For bigger files, use the free Clavis Encrypt app.");
    if (pw.value.replace(/\s/g, "").length < MIN_LENGTH) return "Use at least " + MIN_LENGTH + " characters, or press Suggest a password for a strong one.";
    const r = rate();
    if (r && r.score < 2) return "This password is too easy to guess. Make it longer, or press Suggest a password.";
    if (pw.value !== pw2.value) return "The two passwords don't match.";
    return "";
  }

  form.addEventListener("submit", async e => {
    e.preventDefault();
    const problem = check();
    if (problem) { say(problem); return; }
    say("");
    const password = pw.value, batch = [...files.files];
    lock(true);
    const made = [];
    try {
    for (const f of batch) {
      const r = row(f);
      try {
        const out = await ClavisEncrypt.encryptFile(f, password, (frac, text) => { r.bar(frac); r.state(text); });
        r.bar(1); r.state("Encrypted · " + size(out.blob.size), "good"); r.done(out.name, out.blob);
        made.push(out.name);
      } catch (err) {
        r.bar(0);
        if (err && /memory|allocation/i.test(err.message || "") || err instanceof RangeError) r.state("Not enough memory on this device for that file. Try a computer.", "bad");
        else if (err && err.name === "NotReadableError") r.state("Couldn't read this file. Choose it again.", "bad");
        else r.state(err && err.message ? err.message : "Couldn't encrypt this file", "bad");
      }
    }
    if (made.length) {
      usedPassword = password;
      const where = new URL("open.html", location.href).href;
      $("message").value = "I've sent you " + (made.length === 1 ? made[0] : made.length + " files") + ", locked with a password.\n"
        + "Open it at " + where + " (on a phone or computer; nothing is uploaded), or in Clavis Encrypt.\n"
        + "I'll send you the password separately.";
      done.hidden = false;
    }
    } finally {
      lock(false);
    }
  });

  function copy(text, button) {
    const label = button.textContent;
    const ok = () => { button.textContent = "Copied"; setTimeout(() => { button.textContent = label; }, 1600); };
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(ok, () => {});
  }
  $("copyMessage").addEventListener("click", e => copy($("message").value, e.currentTarget));
  $("copyPassword").addEventListener("click", e => { if (usedPassword) copy(usedPassword, e.currentTarget); });

  $("clearBtn").addEventListener("click", () => {
    if (busy) return;
    usedPassword = "";
    urls.splice(0).forEach(u => URL.revokeObjectURL(u));
    list.innerHTML = ""; form.reset(); showChosen(); rate();
    done.hidden = true; $("suggestNote").hidden = true;
    if (pw.type === "text") $("showPw").click();
  });
  window.addEventListener("pagehide", () => urls.forEach(u => URL.revokeObjectURL(u)));
})();
