"""
Lockr Python client example using Ed25519 challenge-response auth.
Requires: pip install httpx cryptography
"""
import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import binascii


class LockrClient:
    def __init__(self, addr: str, key_path: str, ca_path: str | None = None):
        self.addr = addr.rstrip("/")
        with open(key_path) as f:
            key_hex = f.read().strip()
        raw = bytes.fromhex(key_hex)
        # Ed25519 private key is 64 bytes: first 32 = seed, last 32 = public key
        self._privkey = Ed25519PrivateKey.from_private_bytes(raw[:32])
        self._token: str | None = None
        verify = ca_path if ca_path else False
        self._http = httpx.Client(base_url=self.addr, verify=verify, timeout=15)

    def authenticate(self, service: str) -> None:
        r = self._http.post("/v1/auth/challenge", json={"service": service})
        r.raise_for_status()
        challenge_hex = r.json()["data"]["challenge"]
        challenge = bytes.fromhex(challenge_hex)
        sig = self._privkey.sign(challenge)
        r2 = self._http.post("/v1/auth/verify", json={
            "challenge": challenge_hex,
            "signature": sig.hex(),
        })
        r2.raise_for_status()
        self._token = r2.json()["data"]["token"]
        self._http.headers.update({"Authorization": f"Bearer {self._token}"})

    def kv_get(self, path: str, version: int = 0) -> dict:
        url = f"/v1/secrets/kv/{path}"
        if version:
            url += f"?version={version}"
        r = self._http.get(url)
        r.raise_for_status()
        return r.json()["data"]["value"]

    def kv_set(self, path: str, value: dict) -> None:
        r = self._http.put(f"/v1/secrets/kv/{path}", json=value)
        r.raise_for_status()

    def transit_encrypt(self, key_name: str, plaintext: str) -> str:
        r = self._http.post(f"/v1/secrets/transit/{key_name}/encrypt",
                            json={"plaintext": plaintext})
        r.raise_for_status()
        return r.json()["data"]["ciphertext"]

    def transit_decrypt(self, key_name: str, ciphertext: str) -> str:
        r = self._http.post(f"/v1/secrets/transit/{key_name}/decrypt",
                            json={"ciphertext": ciphertext})
        r.raise_for_status()
        return r.json()["data"]["plaintext"]


if __name__ == "__main__":
    vault = LockrClient(
        addr="https://lockr:8300",
        key_path="./certs/api-server.key",
        ca_path="./certs/ca.crt",
    )
    vault.authenticate("api-server")

    stripe = vault.kv_get("secrets/prod/stripe_key")
    print("stripe key:", stripe["key"])

    ct = vault.transit_encrypt("payments-key", "card:4111111111111111")
    print("encrypted:", ct)

    pt = vault.transit_decrypt("payments-key", ct)
    print("decrypted:", pt)
