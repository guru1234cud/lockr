/**
 * Lockr Node.js client example using Ed25519 challenge-response auth.
 * Requires: npm install node-fetch
 * Node 20+ has built-in crypto.sign for Ed25519.
 */
const { createPrivateKey, sign } = require("crypto");
const { readFileSync } = require("fs");

class LockrClient {
  constructor({ addr, keyPath, caPath }) {
    this.addr = addr.replace(/\/$/, "");
    const keyHex = readFileSync(keyPath, "utf8").trim();
    const rawKey = Buffer.from(keyHex, "hex");
    // PKCS8 wrapper for Ed25519 (seed = first 32 bytes)
    const pkcs8Prefix = Buffer.from(
      "302e020100300506032b657004220420",
      "hex"
    );
    this._privkeyDer = Buffer.concat([pkcs8Prefix, rawKey.slice(0, 32)]);
    this._token = null;
    this._caPath = caPath;
  }

  async _fetch(method, path, body) {
    const https = require("https");
    const agent = this._caPath
      ? new https.Agent({ ca: readFileSync(this._caPath) })
      : new https.Agent({ rejectUnauthorized: false });

    const { default: fetch } = await import("node-fetch");
    const res = await fetch(this.addr + path, {
      method,
      headers: {
        "Content-Type": "application/json",
        ...(this._token ? { Authorization: `Bearer ${this._token}` } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
      agent,
    });
    return res.json();
  }

  async authenticate(service) {
    const r1 = await this._fetch("POST", "/v1/auth/challenge", { service });
    const challengeHex = r1.data.challenge;
    const challenge = Buffer.from(challengeHex, "hex");

    const privKey = createPrivateKey({ key: this._privkeyDer, format: "der", type: "pkcs8" });
    const sig = sign(null, challenge, privKey);

    const r2 = await this._fetch("POST", "/v1/auth/verify", {
      challenge: challengeHex,
      signature: sig.toString("hex"),
    });
    this._token = r2.data.token;
  }

  async kvGet(path, version = 0) {
    const url = version ? `${path}?version=${version}` : path;
    const r = await this._fetch("GET", `/v1/secrets/kv/${url}`);
    return r.data?.value ?? r.data;
  }

  async kvSet(path, value) {
    return this._fetch("PUT", `/v1/secrets/kv/${path}`, value);
  }

  async transitEncrypt(keyName, plaintext) {
    const r = await this._fetch("POST", `/v1/secrets/transit/${keyName}/encrypt`, { plaintext });
    return r.data.ciphertext;
  }

  async transitDecrypt(keyName, ciphertext) {
    const r = await this._fetch("POST", `/v1/secrets/transit/${keyName}/decrypt`, { ciphertext });
    return r.data.plaintext;
  }
}

(async () => {
  const vault = new LockrClient({
    addr: "https://lockr:8300",
    keyPath: "./certs/api-server.key",
    caPath: "./certs/ca.crt",
  });

  await vault.authenticate("api-server");

  const stripe = await vault.kvGet("secrets/prod/stripe_key");
  console.log("stripe key:", stripe.key);

  const ct = await vault.transitEncrypt("payments-key", "card:4111111111111111");
  console.log("encrypted:", ct);

  const pt = await vault.transitDecrypt("payments-key", ct);
  console.log("decrypted:", pt);
})();
