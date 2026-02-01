"""Trigger a Render deploy and poll status (backendadmin helper).

Requires: RENDER_API_KEY, RENDER_SERVICE_ID
"""
import os
import sys
import time
import requests

API = os.environ.get('RENDER_API_BASE', 'https://api.render.com')
KEY = os.environ.get('RENDER_API_KEY')
SID = os.environ.get('RENDER_SERVICE_ID')

if not KEY or not SID:
    print('RENDER_API_KEY and RENDER_SERVICE_ID must be set')
    sys.exit(2)

h = {'Authorization': f'Bearer {KEY}', 'Content-Type': 'application/json'}
print('Triggering deploy for', SID)
r = requests.post(f"{API}/v1/services/{SID}/deploys", headers=h, timeout=30)
if r.status_code not in (200,201):
    print('Failed to trigger deploy:', r.status_code, r.text)
    sys.exit(3)

d = r.json()
deploy_id = d.get('id') or d.get('deployId')
print('deploy id:', deploy_id)

deadline = time.time() + 900
while time.time() < deadline:
    rr = requests.get(f"{API}/v1/services/{SID}/deploys/{deploy_id}", headers=h, timeout=20)
    if rr.status_code != 200:
        print('deploy status fetch returned', rr.status_code)
        time.sleep(3)
        continue
    info = rr.json()
    status = info.get('status') or info.get('state')
    print('status =>', status)
    if status and status.lower() in ('failed','error','canceled'):
        print('DEPLOY FAILED — check Render dashboard for full logs')
        sys.exit(4)
    if status and status.lower() in ('live','success','succeeded','ready'):
        print('Deploy finished:', status)
        print('Service URL (if available):', info.get('serviceUrl') or info.get('webServiceUrl') or info.get('externalUrl'))
        sys.exit(0)
    time.sleep(4)

print('Timed out waiting for deploy — check Render dashboard')
sys.exit(5)
