## Render: CI & settings change

This PR adds a workflow to validate Render settings, trigger a preview deploy and optionally patch the service Root Directory to `app/`.

Checklist for maintainers:
- [ ] Add `RENDER_API_KEY` (repo secret, deploy permissions)
- [ ] Add `RENDER_SERVICE_ID` (repo secret)
- [ ] Run the `Render — trigger & monitor deploy (backendadmin)` workflow from Actions

If you enable the optional `set_root_dir` input the workflow will PATCH the Render service (audit logs retained by Render).