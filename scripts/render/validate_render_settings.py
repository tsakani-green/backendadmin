"""Validate Render service settings (backendadmin-specific helper).

See top-level docs. Requires `RENDER_API_KEY` and `RENDER_SERVICE_ID` in environment.
"""
import os
import sys
import requests

API = os.environ.get("RENDER_API_BASE", "https://api.render.com")
KEY = os.environ.get("RENDER_API_KEY")
SID = os.environ.get("RENDER_SERVICE_ID")

if not KEY or not SID:
    print("ERROR: set RENDER_API_KEY and RENDER_SERVICE_ID as env vars or repo secrets.")
    sys.exit(1)

h = {"Authorization": f"Bearer {KEY}", "Accept": "application/json"}
resp = requests.get(f"{API}/v1/services/{SID}", headers=h, timeout=20)
if resp.status_code != 200:
    print("ERROR: could not fetch service from Render API:", resp.status_code, resp.text)
    sys.exit(2)
svc = resp.json()
print("Service:", svc.get('name'), svc.get('id'))
root = svc.get('rootDirectory') or svc.get('repoRoot')
print('rootDirectory:', root)
if root and root.strip('/') != 'app':
    print('WARNING: recommended rootDirectory=app/ for this repo (CI can patch it)')

required = ['FRONTEND_URL', 'CORS_ORIGINS']
missing = []
# Render API may not expose env vars via this endpoint; attempt best-effort
for key in required:
    # look in service object for common fields
    ev = svc.get('envVars') or svc.get('env') or {}
    if isinstance(ev, dict):
        if key not in ev:
            missing.append(key)

if missing:
    print('Missing (or not-observable) environment variables on Render service:', ', '.join(missing))
    print('Ensure these are set in Render → Service → Environment to avoid runtime CORS/auth issues.')

print('\nValidation complete — fix warnings in Render dashboard or run workflow with set_root_dir=true if you want CI to patch the service.')
sys.exit(0)
