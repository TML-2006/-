# ModelScope AI Service Console

## Admin audit backend

The Pages site is static and cannot persist server-side login records. `backend/main.py` serves the static dashboard and provides a FastAPI + SQLite backend for admin authentication and audit records. Successful administrator login events store IP address, UTC login timestamp, and logout timestamp. The admin dashboard renders timestamps in Asia/Shanghai. MAC addresses are not collected because browsers do not expose them to websites.

### Deploy on Render

1. Push this repository to GitHub and create a Render Blueprint from it using `render.yaml`.
2. Set `ADMIN_USERNAME` and a strong, unique `ADMIN_PASSWORD` in the Render service environment.
3. The blueprint uses a persistent disk at `/var/data` for SQLite. The disk-backed `starter` service is a paid Render plan; review current plan pricing before deployment.
4. After deploy, use the Render service URL. The static GitHub Pages page does not host Python/API code, so it will not provide login audit until served by the backend deployment.

For local testing:

```powershell
$env:ADMIN_USERNAME = "admin"
$env:ADMIN_PASSWORD = "replace-with-a-unique-password"
$env:DATA_DIR = "./data"
uvicorn backend.main:app --reload
```

Then open `http://127.0.0.1:8000/` and select **管理员后台**. Successful logins are recorded; logging out updates that session's logout time. An unclosed session remains marked **进行中**.

