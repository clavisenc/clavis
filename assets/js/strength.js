/*
 * Password strength, the same estimate as the Clavis Encrypt app's meter
 * (core/src/main/java/EncryptPack/PasswordStrength.java, ported line by line;
 * tools/test_encrypt_page.mjs checks both give the same scores).
 * In the style of zxcvbn: it looks for what attackers try first (common passwords,
 * also reversed and with l33t swaps, sequences, repeats, keyboard runs, years and
 * dates) and finds the cheapest way to build the password from those pieces plus
 * brute force. Runs only on this device. Needs vendor/common-passwords.js.
 */
"use strict";
(function () {
  const LOG10_GUESSES_PER_SECOND = 5;            // offline attacker with serious GPUs against Argon2id
  const THRESHOLDS = [6, 9, 11, 14];             // log10(guesses) where the score steps up
  const MAX_LEN = 100;
  const BRUTE = 0, DICT = 1, REVERSED = 2, L33T = 3, SEQUENCE = 4, REPEAT = 5, SPATIAL = 6, DATE = 7;
  const log10 = Math.log10;

  const WORDS = String(window.ClavisCommonPasswords || "").split("\n")
    .map(w => w.trim()).filter(w => w && w[0] !== "#").map(w => w.toLowerCase());
  const INDEX = new Map();
  let MAX_WORD = 0;
  WORDS.forEach((w, i) => { if (!INDEX.has(w)) INDEX.set(w, i); MAX_WORD = Math.max(MAX_WORD, w.length); });

  const isUpper = c => /\p{Lu}/u.test(c), isLower = c => /\p{Ll}/u.test(c), isDigit = c => /\p{Nd}/u.test(c);
  const lower = c => { const l = c.toLowerCase(); return l.length === 1 ? l : c; };

  function analyze(pw, depth) {
    const n = pw.length;
    let lc = "";
    for (let i = 0; i < n; i++) lc += lower(pw[i]);
    const seg = [], type = [], rank = [];
    for (let i = 0; i < n; i++) { seg.push(new Float64Array(n + 1)); type.push(new Int8Array(n + 1)); rank.push(new Int32Array(n + 1)); }
    for (let i = 0; i < n; i++)
      for (let j = i + 1; j <= n; j++) seg[i][j] = (j - i) * log10(Math.max(10, cardinality(pw, i, j)));

    dictionary(pw, lc, lc, DICT, seg, type, rank);
    reversed(pw, lc, seg, type, rank);
    l33t(pw, lc, seg, type, rank);
    sequences(lc, seg, type);
    if (depth === 0) repeats(pw, lc, seg, type);
    spatial(pw, seg, type);
    dates(pw, seg, type);

    for (let i = 0; i < n; i++)                  // minimum guesses for a piece that isn't the whole password
      for (let j = i + 1; j <= n; j++)
        if (j - i < n) seg[i][j] = Math.max(seg[i][j], j - i === 1 ? 1 : log10(50));

    const best = [], from = [];                  // best[k][j]: cheapest cover of pw[0..j) with k pieces
    for (let k = 0; k <= n; k++) { best.push(new Float64Array(n + 1).fill(Infinity)); from.push(new Int32Array(n + 1)); }
    best[0][0] = 0;
    for (let k = 1; k <= n; k++)
      for (let j = 1; j <= n; j++)
        for (let i = k - 1; i < j; i++) {
          const v = best[k - 1][i] + seg[i][j];
          if (v < best[k][j]) { best[k][j] = v; from[k][j] = i; }
        }
    const a = { log10: Infinity, path: [] };
    let bestK = 1;
    for (let k = 1; k <= n; k++) {
      if (best[k][n] === Infinity) continue;
      const total = logAdd(logFactorial(k) + best[k][n], 4.0 * (k - 1));
      if (total < a.log10) { a.log10 = total; bestK = k; }
    }
    for (let k = bestK, j = n; k > 0; k--) {
      const i = from[k][j];
      a.path.unshift([i, j, type[i][j], rank[i][j]]);
      j = i;
    }
    return a;
  }

  function offer(seg, type, i, j, log, t) { if (log < seg[i][j]) { seg[i][j] = log; type[i][j] = t; } }

  // ── Common passwords ───────────────────────────────────────────────────────
  function lookup(s, i, j) { const idx = INDEX.get(s.substring(i, j)); return idx === undefined ? 0 : idx + 1; }

  function dictionary(pw, lc, probe, t, seg, type, rank) {
    const n = probe.length;
    for (let i = 0; i < n; i++)
      for (let j = i + 3; j <= n && j - i <= MAX_WORD; j++) {
        const r = lookup(probe, i, j);
        if (!r) continue;
        let log = log10(r) + log10(upperVariations(pw, i, j));
        if (t === L33T) {
          const v = l33tVariations(lc, probe, i, j);
          if (v === 0) continue;                 // no swap inside this slice
          log += log10(v);
        }
        if (log < seg[i][j]) { seg[i][j] = log; type[i][j] = t; rank[i][j] = r; }
      }
  }

  function reversed(pw, lc, seg, type, rank) {
    const n = lc.length;
    const rev = lc.split("").reverse().join("");
    for (let i = 0; i < n; i++)
      for (let j = i + 3; j <= n && j - i <= MAX_WORD; j++) {
        const r = lookup(rev, i, j);
        if (!r) continue;
        const a = n - j, b = n - i;
        if (isPalindrome(lc, a, b)) continue;    // already found forwards
        const log = log10(r) + log10(upperVariations(pw, a, b)) + log10(2);
        if (log < seg[a][b]) { seg[a][b] = log; type[a][b] = REVERSED; rank[a][b] = r; }
      }
  }

  function isPalindrome(s, a, b) {
    for (let x = a, y = b - 1; x < y; x++, y--) if (s[x] !== s[y]) return false;
    return true;
  }

  const L33T_FROM = "4@8(361|0!$572+", L33T_TO_I = "aabcegiioisstzt", L33T_TO_L = "aabceglloisstzt";

  function l33t(pw, lc, seg, type, rank) {
    const ambiguous = lc.includes("1") || lc.includes("|");
    for (const to of ambiguous ? [L33T_TO_I, L33T_TO_L] : [L33T_TO_I]) {
      let un = "", changed = false;
      for (let k = 0; k < lc.length; k++) {
        const x = L33T_FROM.indexOf(lc[k]);
        if (x >= 0) { un += to[x]; changed = true; } else un += lc[k];
      }
      if (changed) dictionary(pw, lc, un, L33T, seg, type, rank);
    }
  }

  function l33tVariations(lc, un, i, j) {
    let v = 1, any = false;
    const seen = new Array(L33T_FROM.length).fill(false);
    for (let k = i; k < j; k++) {
      const x = L33T_FROM.indexOf(lc[k]);
      if (x < 0 || lc[k] === un[k] || seen[x]) continue;
      seen[x] = true; any = true;
      let subbed = 0, plain = 0;
      for (let m = i; m < j; m++) {
        if (lc[m] === lc[k]) subbed++;
        else if (lc[m] === un[k]) plain++;
      }
      if (plain === 0) v *= 2;
      else { let s = 0; for (let c = 1; c <= Math.min(subbed, plain); c++) s += nCk(subbed + plain, c); v *= s; }
    }
    return any ? v : 0;
  }

  function upperVariations(pw, i, j) {
    let up = 0, low = 0;
    for (let k = i; k < j; k++) { if (isUpper(pw[k])) up++; else if (isLower(pw[k])) low++; }
    if (up === 0) return 1;
    if (low === 0) return 2;                     // ALL CAPS
    if (up === 1 && (isUpper(pw[i]) || isUpper(pw[j - 1]))) return 2;
    let s = 0;
    for (let c = 1; c <= Math.min(up, low); c++) s += nCk(up + low, c);
    return s;
  }

  // ── Sequences, repeats, keyboard runs, dates ───────────────────────────────
  function sequences(lc, seg, type) {
    const n = lc.length, code = k => lc.charCodeAt(k);
    let i = 0;
    while (i < n - 2) {
      const d = code(i + 1) - code(i);
      if ((Math.abs(d) === 1 || Math.abs(d) === 2) && sameClass(lc[i], lc[i + 1])) {
        let j = i + 1;
        while (j + 1 < n && code(j + 1) - code(j) === d && sameClass(lc[j], lc[j + 1])) j++;
        if (j - i + 1 >= 3) {
          const f = lc[i];
          const base = "az019".indexOf(f) >= 0 ? 4 : isDigit(f) ? 10 : 26;
          offer(seg, type, i, j + 1, log10(base * (j - i + 1) * (d < 0 ? 2 : 1)), SEQUENCE);
          i = j;
          continue;
        }
      }
      i++;
    }
  }

  function sameClass(a, b) {
    return (isDigit(a) && isDigit(b)) || (a >= "a" && a <= "z" && b >= "a" && b <= "z");
  }

  function repeats(pw, lc, seg, type) {
    const n = lc.length;
    let coveredTo = 0, coveredBlock = 0;
    for (let i = 0; i < n; i++) {
      let bestB = 0, bestK = 0;
      for (let b = 1; i + 2 * b <= n; b++) {
        let k = 1;
        while (i + (k + 1) * b <= n && regionEquals(lc, i, i + k * b, b)) k++;
        if ((b === 1 && k >= 3 || b > 1 && k >= 2) && b * k > bestB * bestK) { bestB = b; bestK = k; }
      }
      if (bestB === 0) continue;
      if (i < coveredTo && bestB === coveredBlock) continue;
      coveredTo = i + bestB * bestK;
      coveredBlock = bestB;
      const baseLog = bestB === 1 ? log10(Math.max(10, cardinality(pw, i, i + 1)))
                                  : analyze(pw.substring(i, i + bestB), 1).log10;
      offer(seg, type, i, i + bestB * bestK, baseLog + log10(bestK), REPEAT);
    }
  }

  function regionEquals(s, a, b, len) {
    for (let k = 0; k < len; k++) if (s[a + k] !== s[b + k]) return false;
    return true;
  }

  const ROWS = ["`1234567890-=", "qwertyuiop[]\\", "asdfghjkl;'", "zxcvbnm,./"];
  const SHIFT = ["~!@#$%^&*()_+", "QWERTYUIOP{}|", "ASDFGHJKL:\"", "ZXCVBNM<>?"];
  const KEY_STARTS = 94, KEY_DEGREE = 4.595;

  function key(c) {
    for (let r = 0; r < ROWS.length; r++) {
      const off = r === 0 ? 0 : 1;
      let x = ROWS[r].indexOf(c);
      if (x >= 0) return [r, x + off, 0];
      x = SHIFT[r].indexOf(c);
      if (x >= 0) return [r, x + off, 1];
    }
    return null;
  }

  function spatial(pw, seg, type) {
    const n = pw.length;
    let i = 0;
    while (i < n - 2) {
      let j = i, turns = 0, shifted = 0, lastDir = -1;
      let a = key(pw[i]);
      if (a && a[2] === 1) shifted++;
      while (j + 1 < n && a) {
        const b = key(pw[j + 1]);
        const dir = b ? direction(a, b) : -1;
        if (dir < 0) break;
        if (dir !== lastDir) { turns++; lastDir = dir; }
        if (b[2] === 1) shifted++;
        a = b;
        j++;
      }
      const len = j - i + 1;
      if (len >= 3) {
        let g = 0;
        for (let L = 2; L <= len; L++)
          for (let t = 1; t <= Math.min(turns, L - 1); t++) g += nCk(L - 1, t - 1) * KEY_STARTS * Math.pow(KEY_DEGREE, t);
        const unshifted = len - shifted;
        if (shifted > 0) {
          if (unshifted === 0) g *= 2;
          else { let s = 0; for (let c = 1; c <= Math.min(shifted, unshifted); c++) s += nCk(len, c); g *= s; }
        }
        offer(seg, type, i, j + 1, log10(g), SPATIAL);
        i = j;
      } else i++;
    }
  }

  function direction(a, b) {
    const dr = b[0] - a[0], dc = b[1] - a[1];
    if (dr === 0 && dc === -1) return 0;
    if (dr === 0 && dc === 1) return 1;
    if (dr === -1 && dc === 0) return 2;
    if (dr === -1 && dc === 1) return 3;
    if (dr === 1 && dc === -1) return 4;
    if (dr === 1 && dc === 0) return 5;
    return -1;
  }

  const REFERENCE_YEAR = 2026;

  function dates(pw, seg, type) {
    const n = pw.length;
    for (let i = 0; i + 4 <= n; i++) {
      const y = digits(pw, i, 4);
      if (y >= 1900 && y <= 2039) offer(seg, type, i, i + 4, log10(yearSpace(y)), DATE);
    }
    for (let i = 0; i < n; i++)
      for (let len = 6; len <= 10 && i + len <= n; len++) {
        const y = dateYear(pw, i, i + len);
        if (y < 0) continue;
        const sep = !isDigit(pw[i + 1]) || !isDigit(pw[i + 2]);
        offer(seg, type, i, i + len, log10(365.0 * yearSpace(y) * (sep ? 4 : 1)), DATE);
      }
  }

  const yearSpace = y => Math.max(Math.abs(y - REFERENCE_YEAR), 20);

  function digits(s, i, count) {
    let v = 0;
    for (let k = i; k < i + count; k++) {
      if (s[k] < "0" || s[k] > "9") return -1;
      v = v * 10 + (s.charCodeAt(k) - 48);
    }
    return v;
  }

  function dateYear(s, a, b) {
    const parts = [], widths = [];
    let sep = "", k = a;
    while (k < b) {
      const st = k;
      while (k < b && isDigit(s[k])) k++;
      if (k === st) return -1;
      parts.push(digits(s, st, k - st));
      widths.push(k - st);
      if (k < b) {
        const c = s[k];
        if ("/-._ \\".indexOf(c) < 0 || (sep && c !== sep)) return -1;
        sep = c;
        k++;
        if (k === b) return -1;
      }
    }
    if (parts.length === 3) {
      if (widths[0] > 4 || widths[1] > 2 || widths[2] > 4) return -1;
      return ymd(parts[0], widths[0], parts[1], parts[2], widths[2]);
    }
    if (parts.length === 1 && (widths[0] === 6 || widths[0] === 8)) {
      const w = widths[0], yw = w === 8 ? 4 : 2;
      const y = ymd(digits(s, a, 2), 2, digits(s, a + 2, 2), digits(s, a + 4, yw), yw);
      if (y >= 0) return y;
      return ymd(digits(s, a, yw), yw, digits(s, a + yw, 2), digits(s, a + yw + 2, 2), 2);
    }
    return -1;
  }

  function ymd(p1, w1, p2, p3, w3) {
    if (w1 === 4 || w1 === 2 && p1 > 31) {
      const y = fullYear(p1, w1);
      return y > 0 && p2 >= 1 && p2 <= 12 && p3 >= 1 && p3 <= 31 ? y : -1;
    }
    const y = fullYear(p3, w3);
    if (y < 0) return -1;
    const dm = p1 >= 1 && p1 <= 31 && p2 >= 1 && p2 <= 12;
    const md = p1 >= 1 && p1 <= 12 && p2 >= 1 && p2 <= 31;
    return dm || md ? y : -1;
  }

  function fullYear(v, width) {
    if (width === 4) return v >= 1900 && v <= 2039 ? v : -1;
    if (width === 2) return v > 50 ? 1900 + v : 2000 + v;
    return -1;
  }

  // ── Helpers ────────────────────────────────────────────────────────────────
  function cardinality(s, i, j) {
    let lo = false, up = false, dig = false, sym = false, other = false;
    for (let k = i; k < j; k++) {
      const c = s[k];
      if (c >= "a" && c <= "z") lo = true;
      else if (c >= "A" && c <= "Z") up = true;
      else if (c >= "0" && c <= "9") dig = true;
      else if (c >= " " && c <= "~") sym = true;
      else other = true;
    }
    return (lo ? 26 : 0) + (up ? 26 : 0) + (dig ? 10 : 0) + (sym ? 33 : 0) + (other ? 100 : 0);
  }

  function nCk(n, k) {
    if (k < 0 || k > n) return 0;
    let r = 1;
    for (let i = 1; i <= k; i++) r = r * (n - k + i) / i;
    return r;
  }

  function logFactorial(k) { let s = 0; for (let i = 2; i <= k; i++) s += log10(i); return s; }

  function logAdd(a, b) { const hi = Math.max(a, b), lo = Math.min(a, b); return hi + log10(1 + Math.pow(10, lo - hi)); }

  // ── Result ─────────────────────────────────────────────────────────────────
  const WARN = {
    short: "Short passwords are easy to guess. Make it longer.",
    addWords: "Add another word or two. Uncommon words are better.",
    top10: "This is one of the 10 most common passwords.",
    top100: "This is one of the 100 most common passwords.",
    common: "This is a very common password.",
    words: "Common words and passwords are easy to guess.",
    reversed: "Reversed common words are no harder to guess.",
    l33t: "Swapping letters for symbols (like @ for a) doesn't help much.",
    sequence: "Sequences like abc or 123 are easy to guess.",
    repeat: "Repeats like aaa or abcabc are easy to guess.",
    keyboard: "Keyboard patterns like qwerty are easy to guess.",
    dates: "Dates and years are easy to guess.",
  };

  function warning(a, length) {
    let worst = null;
    for (const m of a.path)
      if (m[2] !== BRUTE && (!worst || m[1] - m[0] > worst[1] - worst[0])) worst = m;
    if (!worst) return length < 12 ? WARN.short : WARN.addWords;
    const whole = a.path.length === 1;
    switch (worst[2]) {
      case DICT:
        if (whole && worst[3] <= 10) return WARN.top10;
        if (whole && worst[3] <= 100) return WARN.top100;
        return whole ? WARN.common : WARN.words;
      case REVERSED: return WARN.reversed;
      case L33T: return WARN.l33t;
      case SEQUENCE: return WARN.sequence;
      case REPEAT: return WARN.repeat;
      case SPATIAL: return WARN.keyboard;
      case DATE: return WARN.dates;
      default: return "";
    }
  }

  const UNITS = ["second", "minute", "hour", "day", "month", "year"];

  function crackTime(log) {
    const s = Math.pow(10, log - LOG10_GUESSES_PER_SECOND);
    if (s < 1) return "cracked instantly";
    const unit = [60, 3600, 86400, 86400 * 30.44, 86400 * 365.25, 86400 * 365.25 * 100];
    let div = 1;
    for (let i = 0; i < unit.length; i++) {
      if (s < unit[i]) { const v = Math.max(1, Math.round(s / div)); return "about " + v + " " + UNITS[i] + (v === 1 ? "" : "s") + " to crack"; }
      div = unit[i];
    }
    return "centuries to crack";
  }

  const LABELS = ["Very weak", "Weak", "Fair", "Good", "Strong"];

  /** {score 0..4, label, log10Guesses, crackTime, warning} for a password string. */
  function estimate(pw) {
    if (!pw.length) return { score: 0, label: LABELS[0], log10Guesses: 0, crackTime: crackTime(0), warning: "" };
    const n = Math.min(pw.length, MAX_LEN);
    const a = analyze(pw.substring(0, n), 0);
    let log = a.log10;
    if (pw.length > n) log += (pw.length - n) * log10(Math.max(10, cardinality(pw, n, pw.length)));
    let score = 0;
    while (score < THRESHOLDS.length && log >= THRESHOLDS[score]) score++;
    return { score, label: LABELS[score], log10Guesses: log, crackTime: crackTime(log), warning: score >= 3 ? "" : warning(a, pw.length) };
  }

  window.ClavisStrength = { estimate, commonCount: WORDS.length };
})();
