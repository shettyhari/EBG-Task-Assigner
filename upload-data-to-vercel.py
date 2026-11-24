"""Copy the workspace from this PC (data.json) into the Vercel database (Upstash Redis).

Usage (PowerShell), with the two values from Vercel -> Storage -> your Upstash database -> ".env.local" tab:
    $env:KV_REST_API_URL="https://....upstash.io"
    $env:KV_REST_API_TOKEN="...."
    python upload-data-to-vercel.py

It refuses to overwrite a database that already has members unless you add --force.
Passwords stay hashed; users keep their current passwords.
"""
import json
import os
import sys

DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(DIR, "api"))
from _ebg_core import FileStorage, Result, normalize_data, storage_from_env, upgrade_data  # noqa: E402


def main():
    remote = storage_from_env()
    if remote is None:
        print("Set KV_REST_API_URL and KV_REST_API_TOKEN (or UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN) first.")
        sys.exit(1)

    local = normalize_data(FileStorage(DIR).read())
    upgrade_data(local)  # never upload plaintext passwords
    print(f"Local data.json: {len(local['members'])} members, {len(local['tasks'])} tasks.")

    force = "--force" in sys.argv

    def replace(data):
        if data["members"] and not force:
            raise SystemExit(f"The Vercel database already has {len(data['members'])} member(s). "
                             "Run again with --force to replace them with this PC's data.")
        data.clear()
        data.update(json.loads(json.dumps(local)))
        result = Result()
        result.changed = True
        return result

    remote.transact(replace)
    print("Uploaded. Everyone can now sign in on the Vercel site with their existing passwords.")


if __name__ == "__main__":
    main()
