# Google Search Console + GA4 MCP Server for Vercel

This project is a Vercel-hosted Node.js MCP server for ChatGPT. The Vercel app is the OAuth authorization server for ChatGPT, and it uses Google OAuth 2.0 behind the scenes with read-only scopes only.

It exposes these MCP tools:

- `list_search_console_sites`
- `query_search_console`
- `list_ga4_properties`
- `run_ga4_report`

## Routes

- `GET /mcp` and `POST /mcp` for the public MCP endpoint
- `GET /auth/google/start` as the app authorization endpoint that redirects into Google OAuth
- `GET /auth/google/callback` for the Google OAuth callback
- `POST /oauth/token` as the app token endpoint that mints Vercel-issued MCP tokens
- `GET /.well-known/oauth-authorization-server`
- `GET /.well-known/oauth-protected-resource`

## Required environment variables

- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `APP_BASE_URL`
- `APP_ENCRYPTION_KEY`

Compatibility fallback names also supported:

- `BASE_URL`
- `SESSION_SECRET`

You can copy `.env.example` locally and fill in your values.

Generate `APP_ENCRYPTION_KEY` as a base64-encoded 32-byte secret. Example:

```powershell
[Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Minimum 0 -Maximum 256 }))
```

## Google Cloud setup

1. Create a Google Cloud project.
2. Enable these APIs:
   - Google Search Console API
   - Google Analytics Data API
   - Google Analytics Admin API
3. Create OAuth 2.0 credentials for a Web application.
4. Add this authorized redirect URI:

```text
https://YOUR-VERCEL-DOMAIN/auth/google/callback
```

## Scopes used

- `https://www.googleapis.com/auth/webmasters.readonly`
- `https://www.googleapis.com/auth/analytics.readonly`

## Deploy to Vercel

1. Import the repo into Vercel.
2. Set the environment variables above.
3. Deploy.
4. In ChatGPT, configure the connector to use your Vercel app for auth:
   - Authorization URL: `https://YOUR-VERCEL-DOMAIN/auth/google/start`
   - Token URL: `https://YOUR-VERCEL-DOMAIN/oauth/token`
   - Resource / Audience: `https://YOUR-VERCEL-DOMAIN/mcp`
5. Confirm these URLs respond:
   - `/`
   - `/.well-known/oauth-authorization-server`
   - `/.well-known/oauth-protected-resource`
   - `/mcp`

## Local development

```bash
npm install
npm run dev
```

Or run the Express server directly:

```bash
npm start
```

## Notes

- This server keeps OAuth state stateless by encrypting authorization codes and Vercel-issued access and refresh tokens instead of storing them in a database.
- Keep `APP_ENCRYPTION_KEY` or `SESSION_SECRET` stable across deploys so sessions and tokens remain decryptable.
- `/mcp` validates only Vercel-issued MCP bearer tokens. It does not accept raw Google tokens directly.
- Those Vercel-issued tokens include issuer, resource, scope, expiry, and the Google credentials needed for downstream API calls.
- The current server-side session store is in-process memory. For stronger persistence across cold starts and regions on Vercel, move session storage to a durable store such as Redis or Vercel KV.
