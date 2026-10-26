/*
 * Encrypts files with a password in the browser, entirely on this device, into the
 * public Clavis Encrypt .enc format (format.html, version 3): the same file the app
 * makes with "Send with a password". The result opens in Clavis Encrypt, on open.html
 * and with tools/clavis_decrypt.py. Nothing is uploaded: the page's
 * Content-Security-Policy forbids network requests.
 *
 *   header  = "FENC" | 0x03 | salt(16) | Argon2 memory KiB (u32 BE) | passes (u8) |
 *             lanes (u8) | chunk size (u32 BE) | nonce prefix (7)
 *   key     = Argon2id(password UTF-8, salt) -> 32 bytes, AES-256-GCM
 *   stream  = [name length u16 BE][name UTF-8][gzip(content)], cut into chunks of
 *             `chunk size` bytes, each sealed with nonce = prefix | counter (u32 BE) |
 *             last (0/1) and the header as associated data.
 *
 * Needs: WebCrypto (AES-GCM), CompressionStream('gzip'), File.stream() and
 * hash-wasm's Argon2id (assets/js/vendor/argon2.umd.min.js, MIT).
 */
"use strict";
(function () {
  const MAGIC = [0x46, 0x45, 0x4e, 0x43];        // "FENC"
  const STREAM = 0x03, HEADER = 38;
  const CHUNK = 64 * 1024;                        // plaintext bytes per chunk, as the app writes
  // Argon2id: 64 MiB and 2 passes, a step of the app's own ladder (19-128 MiB, 2-3 passes)
  // and over three times the memory of its default; about 0.6 s on a desktop browser and a
  // few seconds on a phone. If a device can't spare 64 MiB, the app's default and minimum
  // (19 MiB, 2 passes; OWASP's recommended setting) is used instead.
  const KDF = { memory: 65536, iterations: 2, parallelism: 1 };
  const KDF_SMALL = { memory: 19456, iterations: 2, parallelism: 1 };
  const BLOB_PART = 32 * 1024 * 1024;             // hand sealed data to a Blob in 32 MB pieces
  const enc = new TextEncoder(), subtle = crypto.subtle;

  const random = n => crypto.getRandomValues(new Uint8Array(n));

  function header(salt, kdf, chunk, prefix) {
    const h = new Uint8Array(HEADER), dv = new DataView(h.buffer);
    h.set(MAGIC, 0);
    h[4] = STREAM;
    h.set(salt, 5);
    dv.setUint32(21, kdf.memory);
    h[25] = kdf.iterations;
    h[26] = kdf.parallelism;
    dv.setUint32(27, chunk);
    h.set(prefix, 31);
    return h;
  }

  async function deriveKey(pw, salt, kdf) {
    const raw = await hashwasm.argon2id({ password: pw, salt, parallelism: kdf.parallelism, iterations: kdf.iterations,
                                          memorySize: kdf.memory, hashLength: 32, outputType: "binary" });
    try { return await subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt"]); }
    finally { raw.fill(0); }
  }

  const outOfMemory = e => e instanceof RangeError || /memory|allocat/i.test((e && e.message) || "");

  /** Seals the plaintext stream chunk by chunk (STREAM construction, as the app's StreamAead). */
  class Sealer {
    constructor(key, prefix, head, chunk) {
      this.key = key; this.prefix = prefix; this.aad = head;
      this.buf = new Uint8Array(chunk); this.len = 0; this.counter = 0;
      this.parts = [head]; this.partBytes = head.length; this.blobs = [];
    }

    async write(data) {
      let off = 0;
      while (off < data.length) {
        // A full chunk is sealed only once more data arrives, so the final chunk is
        // always the one sealed by finish() with last = 1.
        if (this.len === this.buf.length) await this.seal(false);
        const k = Math.min(data.length - off, this.buf.length - this.len);
        this.buf.set(data.subarray(off, off + k), this.len);
        this.len += k; off += k;
      }
    }

    async seal(last) {
      const n = this.counter;
      if (n > 0xFFFFFFFF) throw new Error("This file is too large.");
      const iv = new Uint8Array(12);
      iv.set(this.prefix);
      iv[7] = n >>> 24; iv[8] = (n >>> 16) & 255; iv[9] = (n >>> 8) & 255; iv[10] = n & 255; iv[11] = last ? 1 : 0;
      const plain = this.buf.slice(0, this.len);
      const sealed = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv, additionalData: this.aad, tagLength: 128 }, this.key, plain));
      plain.fill(0);
      this.parts.push(sealed);
      this.partBytes += sealed.length;
      this.counter++; this.len = 0;
      if (this.partBytes >= BLOB_PART) this.flushParts();
    }

    flushParts() {
      if (this.parts.length) this.blobs.push(new Blob(this.parts));
      this.parts = []; this.partBytes = 0;
    }

    async finish() {
      await this.seal(true);
      this.buf.fill(0);
      this.flushParts();
      return new Blob(this.blobs, { type: "application/octet-stream" });
    }

    abort() { this.buf.fill(0); this.parts = []; this.blobs = []; }
  }

  /**
   * Encrypt one File with a password. Returns {name: "<original name>.enc", blob, kdf}.
   * progress(fraction, message) is called as it goes. options (tests only): {kdf, chunkSize, name}.
   */
  async function encryptFile(file, password, progress, options) {
    progress = progress || function () {};
    options = options || {};
    const original = options.name != null ? options.name : file.name;
    const name = enc.encode(original);
    if (!name.length || name.length > 0xFFFF) throw new Error("This file's name can't be stored.");
    const chunk = options.chunkSize || CHUNK;
    const salt = random(16), prefix = random(7), pw = enc.encode(password);

    progress(0, "Locking (this takes a few seconds)…");
    let kdf = options.kdf || KDF, key;
    try {
      try { key = await deriveKey(pw, salt, kdf); }
      catch (e) {
        if (options.kdf || !outOfMemory(e)) throw e;
        kdf = KDF_SMALL;
        key = await deriveKey(pw, salt, kdf);
      }
    } finally { pw.fill(0); }

    const head = header(salt, kdf, chunk, prefix);
    const sealer = new Sealer(key, prefix, head, chunk);
    try {
      await sealer.write(new Uint8Array([name.length >> 8, name.length & 255]));
      await sealer.write(name);
      let read = 0, shown = -1;
      const counted = file.stream().pipeThrough(new TransformStream({
        transform(c, ctl) {
          read += c.length;
          const f = file.size ? read / file.size : 1, pct = Math.floor(f * 100);
          if (pct !== shown) { shown = pct; progress(f, "Encrypting…"); }
          ctl.enqueue(c);
        },
      }));
      const reader = counted.pipeThrough(new CompressionStream("gzip")).getReader();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        await sealer.write(value);
      }
      return { name: original + ".enc", blob: await sealer.finish(), kdf };
    } catch (e) {
      sealer.abort();
      throw e;
    }
  }

  /** True when this browser has everything encryptFile needs. */
  function supported() {
    return !!(window.crypto && crypto.subtle && crypto.getRandomValues && window.CompressionStream && window.TransformStream
              && window.WebAssembly && window.Blob && Blob.prototype.stream && window.hashwasm);
  }

  window.ClavisEncrypt = { encryptFile, supported, CHUNK, KDF, KDF_SMALL };
})();
