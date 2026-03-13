# Marketing Data MCP Server for Vercel

This project is a Vercel-hosted Node.js MCP server for ChatGPT. The Vercel app is the OAuth authorization server for ChatGPT. Google-backed tools use Google OAuth 2.0 behind the scenes, and CallRail-backed tools use a server-side CallRail API token.

It exposes these MCP tools:

- `list_search_console_sites`
- `query_search_console`
- `list_ga4_properties`
- `run_ga4_report`
- `list_merchant_accounts`
- `get_merchant_account`
- `list_merchant_products`
- `get_merchant_product`
- `list_callrail_accounts`
- `list_callrail_companies`
- `list_callrail_calls`

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
- `CALLRAIL_API_TOKEN` for CallRail tools

Compatibility fallback names also supported:

- `BASE_URL`
- `SESSION_SECRET`

Optional:

- `CALLRAIL_API_BASE_URL` to override the default CallRail API base URL (`https://api.callrail.com/v3`)

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
   - Merchant API
3. Create OAuth 2.0 credentials for a Web application.
4. Add this authorized redirect URI:

```text
https://YOUR-VERCEL-DOMAIN/auth/google/callback
```

## Scopes used

- `https://www.googleapis.com/auth/webmasters.readonly`
- `https://www.googleapis.com/auth/analytics.readonly`
- `https://www.googleapis.com/auth/content`

## Merchant Center notes

- Merchant Center tools use the Google Merchant API v1.
- Google may require the Cloud project to be registered for Merchant API access before Merchant Center requests succeed.
- The Merchant Center OAuth scope is not read-only; this server exposes only read-only Merchant Center MCP tools.

## CallRail notes

- CallRail tools use `CALLRAIL_API_TOKEN` from the server environment.
- ChatGPT does not perform a separate CallRail OAuth flow in this setup.
- `list_callrail_calls` accepts documented CallRail query parameters via the `query` object and also supports `nextPageUrl` from a previous response.

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
- Those Vercel-issued tokens include issuer, resource, scope, expiry, and the Google credentials needed for downstream Google API calls.
- The current server-side session store is in-process memory. For stronger persistence across cold starts and regions on Vercel, move session storage to a durable store such as Redis or Vercel KV.
