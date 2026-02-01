Render CI helper — how to use

1. Add these repo secrets (GitHub):
   - RENDER_API_KEY (has deploy permissions)
   - RENDER_SERVICE_ID (backendadmin service id)
2. From Actions → run `Render — trigger & monitor deploy (backendadmin)`
3. To set Root Directory to `app/` from CI, run the workflow and set input `set_root_dir=true` (manual action)

If you want me to open the PR for you, I can prepare it; otherwise push the branch and open a PR in the repo.
