# Public CyberGuard demo

This project includes a Render Blueprint for a public, single-service demo. The app serves its frontend and API from the same HTTPS origin.

## Publish it

1. Create a **private GitHub repository** for this project. The root `.gitignore` excludes `.env`, local virtual environments, caches, and local databases.
2. Push the project source to that private repository. Do not commit or upload `.env`.
3. In Render, connect the repository and create a **Blueprint** from its `render.yaml` file.
4. Wait for the deploy to finish, then open the `onrender.com` URL shown for the service. That HTTPS URL works from other Wi-Fi networks and phones/laptops.

## Public demo behavior

- `PUBLIC_DEMO_MODE=true` disables database persistence. Visitors can analyze their own inputs, but scan history is not saved or shared in the dashboard.
- API requests are limited to 30 per minute per client IP.
- Gemini is not configured by the Blueprint. Without `GEMINI_API_KEY`, AI-assisted features use their documented rule-based or unavailable fallback behavior.
- If an operator later adds `GEMINI_API_KEY` in Render, submitted URL, message, and image content may be sent to Gemini, and anonymous users can consume that API quota. Review the account's billing and usage limits before enabling it.
- The app displays a public-demo notice advising visitors not to submit passwords, OTPs, private links, or personal/confidential data.
- Render's free web service sleeps after 15 minutes without traffic, so the first request after inactivity may take longer. This Blueprint uses no persistent database.

## Provider documentation

- [Deploy a FastAPI app on Render](https://render.com/docs/deploy-fastapi)
- [Render Blueprint specification](https://render.com/docs/blueprint-spec)
- [Render free service limitations](https://render.com/docs/free)
