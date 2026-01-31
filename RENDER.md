Render deploy checklist — backendadmin service

Problem fixed in this PR:
- Render failed because it couldn't find a Dockerfile at the expected rootDir. Added a top-level `Dockerfile` that builds the app from `./app/` so Render will find a Dockerfile regardless of rootDir.
- Removed sensitive secrets from `./.env.production` and added guidance to set them via Render environment variables.

If your Render service is configured to use a subdirectory (recommended options):
- Option A (preferred): set the service Root Directory to `app/` in Render and use the existing `app/Dockerfile`.
- Option B: keep Root Directory = repo root — the top-level `Dockerfile` (added here) will build the app.

Required environment variables (set in Render → Service → Environment):
- MONGODB_URL  (MongoDB Atlas connection string)
- SECRET_KEY
- GEMINI_API_KEY (if using Gemini)
- FRONTEND_URL (used for activation links)
- EMAIL_HOST, EMAIL_PORT, EMAIL_USERNAME, EMAIL_PASSWORD (SMTP)
- CORS_ORIGINS (comma-separated frontend origins)

How to redeploy (quick):
1) Go to your Render service dashboard for `backendadmin`.
2) Verify the **Root Directory** matches where your Dockerfile lives:
   - If you want Render to build from `app/`, set Root Directory → `app/` and keep the `app/Dockerfile`.
   - If Root Directory is the repo root, use the top-level `Dockerfile` (already added).
3) Set the required environment variables (see list above).
4) Trigger a manual deploy and inspect the build logs.

Useful checks if deploy fails:
- "Dockerfile does not exist" → check Root Directory setting and that `Dockerfile` exists there.
- "Could not install dependencies" → confirm `requirements.txt` is present in the same directory as the Dockerfile.
- CORS issues → ensure `CORS_ORIGINS` includes your frontend origin(s).

If you want, I can open a PR that:
- Adds a GitHub Action to run a Render preview build on PRs
- Adds a small script to validate Render service settings programmatically
