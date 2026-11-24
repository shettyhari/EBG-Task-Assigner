# Running the EBG Task Assigner

The app is one page (`index.html`) plus an API. The API can run in two places:

| Where | How it runs | Where data is stored |
|---|---|---|
| **Vercel** (team website) | `api/index.py` as a Vercel Function | Upstash Redis database |
| **A PC** (local / office network) | `server.py` via `start-server.bat` | `data.json` next to `server.py` |

Both use the same rules in `api/_ebg_core.py`.

---

## Vercel setup (one time)

1. **Deploy the latest code.** Push to GitHub; Vercel builds it automatically.
   In Vercel → your project → *Settings → Build and Deployment*, use Framework Preset **Other**,
   and leave Build Command and Output Directory empty (default).

2. **Add the database.** In Vercel → your project → **Storage** → *Create Database* →
   **Upstash for Redis** (free plan is fine) → connect it to this project for **all environments**.
   This adds the `KV_REST_API_URL` and `KV_REST_API_TOKEN` environment variables automatically.

3. **Redeploy** so the new variables take effect: *Deployments* → latest → **⋯ → Redeploy**.

4. **Check it works.** Open `https://<your-site>/api/bootstrap`. You should see
   `{"hasAdmin": ..., "server": "ebg"}`.
   Also open `https://<your-site>/data.json`. It must show **404 Not Found**.

5. **Bring in your accounts** (choose one):
   - **Copy from this PC** (keeps everyone's current password). In PowerShell, in this folder,
     using the two values shown in Vercel → Storage → your database → *.env.local* tab:
     ```powershell
     $env:KV_REST_API_URL="https://xxxx.upstash.io"; $env:KV_REST_API_TOKEN="xxxx"; python upload-data-to-vercel.py
     ```
   - **Start fresh:** the first person to *Create Account* on the site can choose the **Admin** role;
     after that, only an Admin can make other Admins.

### Optional settings (Vercel → Settings → Environment Variables)
- `EBG_TIMEZONE` — timezone for scheduled releases (default `Asia/Kolkata`).
- `WHATSAPP_WEBHOOK_URL` — webhook called when a task is created, reassigned or changes status.

### Limits worth knowing
- Each open browser refreshes the workspace once a minute. Upstash's free plan
  (500,000 commands/month) covers a small team working normal hours; upgrade the plan if you see quota errors.
- All workspace data is stored as one record. That is fine for thousands of tasks.

---

## Running on a PC instead

Double-click **`start-server.bat`** and keep its window open. The app opens at
<http://localhost:8090>. Colleagues on the same network can use `http://<this-PC's-IP>:8090`.

The local server and Vercel have **separate data**. Use one of them for the team.

---

## Troubleshooting

| Message | Meaning |
|---|---|
| "The database is not connected…" | Step 2–3 above: add Upstash Redis and redeploy. |
| "The EBG server isn't responding…" | The deployed site is an old version without `api/`. Redeploy the latest commit. |
| "Can't reach the EBG server… start-server.bat" | Local mode: the server window isn't running. |
| "Too many failed attempts" | 5 wrong passwords from one device: wait 5 minutes, or an Admin resets the password. |
