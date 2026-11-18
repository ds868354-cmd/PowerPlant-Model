"""Standalone API-key tool for this bundle -- needs only the Python standard library (no pipeline modules).

  python create_api_key.py --owner my-service [--role reader|predictor|admin] [--expires-days 90] [--file api_keys.json]
  python create_api_key.py --revoke <key_id> [--file api_keys.json]

The RAW key is printed once and never stored; api_keys.json keeps only a salted HMAC-SHA256 hash (the format app.py checks).
Callers send it as  -H "X-API-Key: <key_id>.<secret>"  -- print exactly what this script prints. api_keys.json is a credential store: never commit it
or bake it into the Docker image -- publish it as a Secret / mounted file (see the README, "Deploying") and point API_KEYS_PATH at it."""
import argparse, hashlib, hmac, json, os, secrets, sys, tempfile, time


def _load(path):
    if not os.path.isfile(path):
        return {"keys": {}}
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    data.setdefault("keys", {})
    return data


def _save(path, data):
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)) or ".", suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def create_key(path, owner, role="reader", expires_days=None):
    data = _load(path)
    raw_key, salt, key_id = secrets.token_urlsafe(32), secrets.token_hex(16), secrets.token_hex(8)
    data["keys"][key_id] = {
        "hash": hmac.new(salt.encode(), raw_key.encode(), hashlib.sha256).hexdigest(), "salt": salt,
        "owner": owner, "role": role, "created_at": time.time(),
        "expires_at": (time.time() + float(expires_days) * 86400.0) if expires_days else None, "revoked": False}
    _save(path, data)
    return key_id + "." + raw_key


def revoke_key(path, key_id):
    data = _load(path)
    if key_id not in data["keys"]:
        raise SystemExit("No such key id: " + key_id)
    data["keys"][key_id]["revoked"] = True
    _save(path, data)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Create or revoke an API key for this model bundle.")
    ap.add_argument("--file", default="api_keys.json")
    ap.add_argument("--owner", default="my-service")
    ap.add_argument("--role", default="reader", help="reader (default, least privilege) | predictor | admin -- app.py only accepts roles in PREDICT_ROLES")
    ap.add_argument("--expires-days", type=float, default=None)
    ap.add_argument("--revoke", metavar="KEY_ID", default=None)
    a = ap.parse_args()
    if a.revoke:
        revoke_key(a.file, a.revoke)
        print("Revoked key " + a.revoke + " in " + a.file)
    else:
        print(create_key(a.file, a.owner, a.role, a.expires_days))
        print("(shown once -- store it now; " + a.file + " keeps only its hash)", file=sys.stderr)
        print("Mount " + a.file + " as a secret, e.g. kubectl create secret generic <app>-api-keys --from-file=api_keys.json=" + a.file
              + " ; never commit it or bake it into the Docker image.", file=sys.stderr)
