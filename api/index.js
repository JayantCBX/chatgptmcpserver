import crypto from "node:crypto";
import express from "express";
import { google } from "googleapis";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

const SEARCH_CONSOLE_SCOPE = "https://www.googleapis.com/auth/webmasters.readonly";
const GA4_SCOPE = "https://www.googleapis.com/auth/analytics.readonly";
const GOOGLE_SCOPES = [SEARCH_CONSOLE_SCOPE, GA4_SCOPE];
const AUTH_CODE_TTL_MS = 5 * 60 * 1000;
const ACCESS_TOKEN_TTL_MS = 60 * 60 * 1000;
const REFRESH_TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const OAUTH_STATE_TTL_MS = 10 * 60 * 1000;
const TOOL_SCOPE_MAP = {
  list_search_console_sites: [SEARCH_CONSOLE_SCOPE],
  query_search_console: [SEARCH_CONSOLE_SCOPE],
  list_ga4_properties: [GA4_SCOPE],
  run_ga4_report: [GA4_SCOPE]
};

function requireEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
}

function getBaseUrl(req) {
  return process.env.APP_BASE_URL || `${req.protocol}://${req.get("host")}`;
}

function getResourceUrl(req) {
  return `${getBaseUrl(req)}/mcp`;
}

function getEncryptionKey() {
  const key = Buffer.from(requireEnv("APP_ENCRYPTION_KEY"), "base64");
  if (key.length !== 32) throw new Error("APP_ENCRYPTION_KEY must be a base64-encoded 32-byte key.");
  return key;
}

function base64UrlEncode(value) {
  return Buffer.from(value).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlDecode(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padding = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  return Buffer.from(`${normalized}${padding}`, "base64");
}

function encryptJson(payload) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", getEncryptionKey(), iv);
  const plaintext = Buffer.from(JSON.stringify(payload), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return [base64UrlEncode(iv), base64UrlEncode(cipher.getAuthTag()), base64UrlEncode(ciphertext)].join(".");
}

function decryptJson(token) {
  const [ivPart, tagPart, cipherPart] = String(token || "").split(".");
  if (!ivPart || !tagPart || !cipherPart) throw new Error("Malformed token.");
  const decipher = crypto.createDecipheriv("aes-256-gcm", getEncryptionKey(), base64UrlDecode(ivPart));
  decipher.setAuthTag(base64UrlDecode(tagPart));
  const plaintext = Buffer.concat([decipher.update(base64UrlDecode(cipherPart)), decipher.final()]);
  return JSON.parse(plaintext.toString("utf8"));
}

function sha256Base64Url(value) {
  return base64UrlEncode(crypto.createHash("sha256").update(value).digest());
}

function createOauthClient(req) {
  return new google.auth.OAuth2(
    requireEnv("GOOGLE_CLIENT_ID"),
    requireEnv("GOOGLE_CLIENT_SECRET"),
    `${getBaseUrl(req)}/auth/google/callback`
  );
}

function normalizePropertyName(propertyId) {
  return propertyId.startsWith("properties/") ? propertyId : `properties/${propertyId}`;
}

function normalizeScopes(scopeValue) {
  if (!scopeValue) return [...GOOGLE_SCOPES];
  const requested = String(scopeValue).split(/\s+/).map((s) => s.trim()).filter(Boolean);
  const allowed = requested.filter((scope) => GOOGLE_SCOPES.includes(scope));
  return allowed.length ? Array.from(new Set(allowed)) : [...GOOGLE_SCOPES];
}

function hasScopes(grantedScopes, requiredScopes) {
  return requiredScopes.every((scope) => grantedScopes.includes(scope));
}

function buildAuthError({ httpStatus = 401, error = "invalid_token", errorDescription, details = {} }) {
  const authError = new Error(errorDescription);
  authError.statusCode = httpStatus;
  authError.oauthError = error;
  authError.oauthErrorDescription = errorDescription;
  authError.details = details;
  return authError;
}

function formatAuthErrorResponse(error) {
  return {
    error: error.oauthError || "invalid_token",
    error_description: error.oauthErrorDescription || error.message,
    ...error.details
  };
}

function getAuthenticateHeader(error) {
  const parts = ['Bearer realm="mcp"'];
  if (error.oauthError) parts.push(`error="${error.oauthError}"`);
  if (error.oauthErrorDescription) parts.push(`error_description="${String(error.oauthErrorDescription).replace(/"/g, "'")}"`);
  if (error.details?.required_scopes?.length) parts.push(`scope="${error.details.required_scopes.join(" ")}"`);
  return parts.join(", ");
}

function logAuthorizationDebug(req) {
  const authHeader = req.headers.authorization;
  const hasAuthorizationHeader = Boolean(authHeader);
  const startsWithBearer = Boolean(authHeader?.startsWith("Bearer "));
  const tokenLength = startsWithBearer ? authHeader.slice("Bearer ".length).length : 0;
  console.log(JSON.stringify({ type: "auth_debug", hasAuthorizationHeader, startsWithBearer, tokenLength }));
}

function extractBearerToken(req) {
  logAuthorizationDebug(req);
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    throw buildAuthError({
      httpStatus: 401,
      error: "invalid_request",
      errorDescription: "Missing Authorization header.",
      details: { debug: "missing_authorization_header" }
    });
  }
  if (!authHeader.startsWith("Bearer ")) {
    throw buildAuthError({
      httpStatus: 401,
      error: "invalid_request",
      errorDescription: 'Authorization header must start with "Bearer ".',
      details: { debug: "bad_authorization_scheme" }
    });
  }
  return authHeader.slice("Bearer ".length);
}

function mintAccessToken(req, payload) {
  return encryptJson({
    typ: "mcp_access_token",
    iss: getBaseUrl(req),
    aud: payload.resource,
    resource: payload.resource,
    scope: payload.scope,
    iat: Date.now(),
    exp: Date.now() + ACCESS_TOKEN_TTL_MS,
    google: payload.google
  });
}

function mintRefreshToken(req, payload) {
  return encryptJson({
    typ: "mcp_refresh_token",
    iss: getBaseUrl(req),
    aud: payload.resource,
    resource: payload.resource,
    scope: payload.scope,
    iat: Date.now(),
    exp: Date.now() + REFRESH_TOKEN_TTL_MS,
    google: {
      refreshToken: payload.google.refreshToken,
      scope: payload.google.scope,
      tokenType: payload.google.tokenType || "Bearer"
    }
  });
}

function getRequestedResource(req, fallback) {
  const requested = req.query.resource || req.query.audience || req.body?.resource || req.body?.audience;
  return requested ? String(requested) : fallback;
}

async function refreshGoogleTokensIfNeeded(req, googleTokenBundle) {
  if (!googleTokenBundle?.refreshToken) {
    throw buildAuthError({
      httpStatus: 401,
      error: "invalid_token",
      errorDescription: "Token is missing Google refresh credentials.",
      details: { debug: "missing_google_refresh_token" }
    });
  }
  const expiresAt = Number(googleTokenBundle.expiryDate || 0);
  const isFresh = googleTokenBundle.accessToken && expiresAt && expiresAt - Date.now() > 60_000;
  if (isFresh) return googleTokenBundle;
  const oauthClient = createOauthClient(req);
  oauthClient.setCredentials({ refresh_token: googleTokenBundle.refreshToken });
  try {
    const { credentials } = await oauthClient.refreshAccessToken();
    return {
      accessToken: credentials.access_token,
      refreshToken: googleTokenBundle.refreshToken,
      expiryDate: credentials.expiry_date,
      scope: credentials.scope || googleTokenBundle.scope,
      tokenType: credentials.token_type || googleTokenBundle.tokenType || "Bearer"
    };
  } catch (error) {
    throw buildAuthError({
      httpStatus: 401,
      error: "invalid_token",
      errorDescription: "Failed to refresh Google credentials.",
      details: { debug: "google_refresh_failed", google_error: error instanceof Error ? error.message : String(error) }
    });
  }
}

async function verifyMcpAccessToken(req, requiredScopes = []) {
  if (req.mcpAuth?.verifiedScopesKey === requiredScopes.join(" ")) return req.mcpAuth;
  const rawToken = extractBearerToken(req);
  let payload;
  try {
    payload = decryptJson(rawToken);
  } catch {
    throw buildAuthError({
      httpStatus: 401,
      error: "invalid_token",
      errorDescription: "Malformed token.",
      details: { debug: "malformed_token" }
    });
  }
  const issuer = getBaseUrl(req);
  const resource = getResourceUrl(req);
  if (payload.typ !== "mcp_access_token") {
    throw buildAuthError({
      httpStatus: 401,
      error: "invalid_token",
      errorDescription: "Token is not a Vercel-issued MCP access token.",
      details: { debug: "wrong_token_type", token_type: payload.typ || null }
    });
  }
  if (payload.iss !== issuer) {
    throw buildAuthError({
      httpStatus: 401,
      error: "invalid_token",
      errorDescription: "Bad issuer.",
      details: { debug: "bad_issuer", expected_issuer: issuer, actual_issuer: payload.iss || null }
    });
  }
  const tokenAudience = payload.resource || payload.aud;
  if (tokenAudience !== resource) {
    throw buildAuthError({
      httpStatus: 401,
      error: "invalid_token",
      errorDescription: "Bad audience/resource.",
      details: { debug: "bad_audience_resource", expected_resource: resource, actual_resource: tokenAudience || null }
    });
  }
  if (!payload.exp || Number(payload.exp) <= Date.now()) {
    throw buildAuthError({
      httpStatus: 401,
      error: "invalid_token",
      errorDescription: "Expired token.",
      details: { debug: "expired_token", expired_at: payload.exp || null }
    });
  }
  const grantedScopes = normalizeScopes(payload.scope);
  if (!hasScopes(grantedScopes, requiredScopes)) {
    throw buildAuthError({
      httpStatus: 403,
      error: "insufficient_scope",
      errorDescription: "Missing scopes.",
      details: { debug: "missing_scopes", required_scopes: requiredScopes, granted_scopes: grantedScopes }
    });
  }
  const googleCredentials = await refreshGoogleTokensIfNeeded(req, payload.google);
  req.mcpAuth = {
    issuer,
    resource,
    scope: grantedScopes.join(" "),
    scopes: grantedScopes,
    googleCredentials,
    verifiedScopesKey: requiredScopes.join(" ")
  };
  return req.mcpAuth;
}

async function exchangeGoogleRefreshToken(req, refreshToken) {
  const oauthClient = createOauthClient(req);
  oauthClient.setCredentials({ refresh_token: refreshToken });
  const { credentials } = await oauthClient.refreshAccessToken();
  return credentials;
}

async function callGoogleApi(url, accessToken, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: {
      Authorization: `Bearer ${accessToken}`,
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...options.headers
    }
  });
  const rawBody = await response.text();
  let parsedBody = rawBody;
  try {
    parsedBody = rawBody ? JSON.parse(rawBody) : null;
  } catch {}
  console.log(JSON.stringify({ type: "google_api_debug", url, status: response.status, body: parsedBody }));
  return { ok: response.ok, status: response.status, body: parsedBody };
}

function buildToolResult(payload, isError = false) {
  return {
    content: [{ type: "text", text: typeof payload === "string" ? payload : JSON.stringify(payload, null, 2) }],
    ...(payload && typeof payload === "object" ? { structuredContent: payload } : {}),
    ...(isError ? { isError: true } : {})
  };
}

function toGoogleDebugPayload(response) {
  return response.ok ? response.body : { status: response.status, error: response.body };
}

function toToolErrorPayload(error) {
  if (error?.oauthError) return formatAuthErrorResponse(error);
  return { error: "tool_execution_failed", error_description: error instanceof Error ? error.message : String(error) };
}

async function withVerifiedToolAuth(req, requiredScopes, handler) {
  try {
    const auth = await verifyMcpAccessToken(req, requiredScopes);
    return await handler(auth);
  } catch (error) {
    return buildToolResult(toToolErrorPayload(error), true);
  }
}

async function listSearchConsoleSites(accessToken) {
  return callGoogleApi("https://www.googleapis.com/webmasters/v3/sites", accessToken, { method: "GET" });
}

async function querySearchConsole(accessToken, params) {
  return callGoogleApi(`https://www.googleapis.com/webmasters/v3/sites/${encodeURIComponent(params.siteUrl)}/searchAnalytics/query`, accessToken, {
    method: "POST",
    body: JSON.stringify({
      startDate: params.startDate,
      endDate: params.endDate,
      dimensions: params.dimensions,
      rowLimit: params.rowLimit,
      startRow: params.startRow,
      aggregationType: params.aggregationType,
      dataState: params.dataState,
      dimensionFilterGroups: params.dimensionFilterGroups,
      searchType: params.searchType,
      type: params.type
    })
  });
}

async function listGa4Properties(accessToken) {
  const accountSummaries = [];
  let pageToken;
  let lastError;
  do {
    const url = new URL("https://analyticsadmin.googleapis.com/v1beta/accountSummaries");
    url.searchParams.set("pageSize", "200");
    if (pageToken) url.searchParams.set("pageToken", pageToken);
    const response = await callGoogleApi(url.toString(), accessToken, { method: "GET" });
    if (!response.ok) {
      lastError = response;
      break;
    }
    accountSummaries.push(...(response.body?.accountSummaries || []));
    pageToken = response.body?.nextPageToken || undefined;
  } while (pageToken);
  if (lastError) return lastError;
  return { ok: true, status: 200, body: { accountSummaries } };
}

async function runGa4Report(accessToken, params) {
  return callGoogleApi(`https://analyticsdata.googleapis.com/v1beta/${normalizePropertyName(params.propertyId)}:runReport`, accessToken, {
    method: "POST",
    body: JSON.stringify({
      dateRanges: params.dateRanges,
      dimensions: params.dimensions,
      metrics: params.metrics,
      dimensionFilter: params.dimensionFilter,
      metricFilter: params.metricFilter,
      offset: params.offset,
      limit: params.limit,
      metricAggregations: params.metricAggregations,
      orderBys: params.orderBys,
      currencyCode: params.currencyCode,
      cohortSpec: params.cohortSpec,
      keepEmptyRows: params.keepEmptyRows,
      returnPropertyQuota: params.returnPropertyQuota
    })
  });
}

function isToolCall(body) {
  return body?.method === "tools/call" && typeof body?.params?.name === "string";
}

function createServer(req) {
  const server = new McpServer({ name: "google-search-console-ga4", version: "1.0.0" });
  server.registerTool("list_search_console_sites", {
    title: "List Search Console Sites",
    description: "List the Google Search Console sites accessible to the authenticated user.",
    inputSchema: {},
    annotations: { readOnlyHint: true }
  }, async () => withVerifiedToolAuth(req, TOOL_SCOPE_MAP.list_search_console_sites, async ({ googleCredentials }) => {
    const response = await listSearchConsoleSites(googleCredentials.accessToken);
    return buildToolResult(toGoogleDebugPayload(response), !response.ok);
  }));
  server.registerTool("query_search_console", {
    title: "Query Search Console",
    description: "Run a Search Console search analytics query against a verified site.",
    inputSchema: {
      siteUrl: z.string().min(1),
      startDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
      endDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
      dimensions: z.array(z.string()).optional(),
      rowLimit: z.number().int().min(1).max(25000).optional(),
      startRow: z.number().int().min(0).optional(),
      aggregationType: z.enum(["auto", "byPage", "byProperty", "byNewsShowcasePanel"]).optional(),
      dataState: z.enum(["all", "final", "hourly_all"]).optional(),
      searchType: z.enum(["web", "image", "video", "news", "discover", "googleNews"]).optional(),
      type: z.enum(["web", "image", "video", "discover", "googleNews", "news"]).optional(),
      dimensionFilterGroups: z.array(z.record(z.any())).optional()
    },
    annotations: { readOnlyHint: true }
  }, async (params) => {
    const parsed = z.object({
      siteUrl: z.string().min(1),
      startDate: z.string(),
      endDate: z.string(),
      dimensions: z.array(z.string()).optional(),
      rowLimit: z.number().int().optional(),
      startRow: z.number().int().optional(),
      aggregationType: z.string().optional(),
      dataState: z.string().optional(),
      searchType: z.string().optional(),
      type: z.string().optional(),
      dimensionFilterGroups: z.array(z.record(z.any())).optional()
    }).parse(params);
    return withVerifiedToolAuth(req, TOOL_SCOPE_MAP.query_search_console, async ({ googleCredentials }) => {
      const response = await querySearchConsole(googleCredentials.accessToken, parsed);
      return buildToolResult(toGoogleDebugPayload(response), !response.ok);
    });
  });
  server.registerTool("list_ga4_properties", {
    title: "List GA4 Properties",
    description: "List GA4 properties available to the authenticated user.",
    inputSchema: {},
    annotations: { readOnlyHint: true }
  }, async () => withVerifiedToolAuth(req, TOOL_SCOPE_MAP.list_ga4_properties, async ({ googleCredentials }) => {
    const response = await listGa4Properties(googleCredentials.accessToken);
    return buildToolResult(toGoogleDebugPayload(response), !response.ok);
  }));
  server.registerTool("run_ga4_report", {
    title: "Run GA4 Report",
    description: "Run a GA4 Data API report for a property the authenticated user can access.",
    inputSchema: {
      propertyId: z.string().min(1),
      dateRanges: z.array(z.object({ startDate: z.string(), endDate: z.string() })),
      dimensions: z.array(z.object({ name: z.string().min(1) })).optional(),
      metrics: z.array(z.object({ name: z.string().min(1) })).min(1),
      dimensionFilter: z.record(z.any()).optional(),
      metricFilter: z.record(z.any()).optional(),
      offset: z.string().optional(),
      limit: z.string().optional(),
      metricAggregations: z.array(z.string()).optional(),
      orderBys: z.array(z.record(z.any())).optional(),
      currencyCode: z.string().optional(),
      cohortSpec: z.record(z.any()).optional(),
      keepEmptyRows: z.boolean().optional(),
      returnPropertyQuota: z.boolean().optional()
    },
    annotations: { readOnlyHint: true }
  }, async (params) => {
    const parsed = z.object({
      propertyId: z.string().min(1),
      dateRanges: z.array(z.object({ startDate: z.string(), endDate: z.string() })),
      dimensions: z.array(z.object({ name: z.string().min(1) })).optional(),
      metrics: z.array(z.object({ name: z.string().min(1) })).min(1),
      dimensionFilter: z.record(z.any()).optional(),
      metricFilter: z.record(z.any()).optional(),
      offset: z.string().optional(),
      limit: z.string().optional(),
      metricAggregations: z.array(z.string()).optional(),
      orderBys: z.array(z.record(z.any())).optional(),
      currencyCode: z.string().optional(),
      cohortSpec: z.record(z.any()).optional(),
      keepEmptyRows: z.boolean().optional(),
      returnPropertyQuota: z.boolean().optional()
    }).parse(params);
    return withVerifiedToolAuth(req, TOOL_SCOPE_MAP.run_ga4_report, async ({ googleCredentials }) => {
      const response = await runGa4Report(googleCredentials.accessToken, parsed);
      return buildToolResult(toGoogleDebugPayload(response), !response.ok);
    });
  });
  return server;
}

const app = express();
app.set("trust proxy", true);
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false }));

app.get("/", (req, res) => {
  const baseUrl = getBaseUrl(req);
  res.json({
    name: "google-search-console-ga4-mcp",
    mcpUrl: `${baseUrl}/mcp`,
    oauthStartUrl: `${baseUrl}/auth/google/start`,
    oauthCallbackUrl: `${baseUrl}/auth/google/callback`,
    tokenUrl: `${baseUrl}/oauth/token`,
    resource: getResourceUrl(req),
    scopes: GOOGLE_SCOPES,
    tools: Object.keys(TOOL_SCOPE_MAP)
  });
});

app.get("/auth/google/start", (req, res) => {
  const oauthClient = createOauthClient(req);
  const requestedScopes = normalizeScopes(req.query.scope);
  const resource = getRequestedResource(req, getResourceUrl(req));
  const appState = {
    returnTo: req.query.return_to || "/",
    clientRedirectUri: req.query.redirect_uri || null,
    clientState: req.query.state || null,
    codeChallenge: req.query.code_challenge || null,
    codeChallengeMethod: req.query.code_challenge_method || "S256",
    scope: requestedScopes.join(" "),
    resource,
    audience: resource,
    issuedAt: Date.now()
  };

  const googleAuthUrl = oauthClient.generateAuthUrl({
    access_type: "offline",
    scope: GOOGLE_SCOPES,
    include_granted_scopes: true,
    prompt: "consent",
    state: encryptJson(appState)
  });

  res.redirect(googleAuthUrl);
});

app.get("/auth/google/callback", async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || !state) {
      return res.status(400).json({ error: "Missing Google OAuth code or state." });
    }

    const appState = decryptJson(state);
    if (Date.now() - Number(appState.issuedAt || 0) > OAUTH_STATE_TTL_MS) {
      return res.status(400).json({ error: "OAuth state expired. Start over from /auth/google/start." });
    }

    const oauthClient = createOauthClient(req);
    const { tokens } = await oauthClient.getToken(String(code));
    if (!tokens.refresh_token) {
      return res.status(400).json({
        error: "Google did not return a refresh token. Re-run consent with prompt=consent."
      });
    }

    const grantedScopes = normalizeScopes(tokens.scope || appState.scope);
    const authCode = encryptJson({
      typ: "mcp_authorization_code",
      iss: getBaseUrl(req),
      aud: appState.resource,
      resource: appState.resource,
      scope: grantedScopes.join(" "),
      codeChallenge: appState.codeChallenge,
      codeChallengeMethod: appState.codeChallengeMethod,
      exp: Date.now() + AUTH_CODE_TTL_MS,
      google: {
        accessToken: tokens.access_token,
        refreshToken: tokens.refresh_token,
        expiryDate: tokens.expiry_date,
        scope: tokens.scope || grantedScopes.join(" "),
        tokenType: tokens.token_type || "Bearer"
      }
    });

    if (appState.clientRedirectUri) {
      const redirectUrl = new URL(String(appState.clientRedirectUri));
      redirectUrl.searchParams.set("code", authCode);
      if (appState.clientState) redirectUrl.searchParams.set("state", String(appState.clientState));
      return res.redirect(redirectUrl.toString());
    }

    const successUrl = new URL(String(appState.returnTo || "/"), getBaseUrl(req));
    successUrl.searchParams.set("auth", "success");
    return res.redirect(successUrl.toString());
  } catch (error) {
    return res.status(500).json({
      error: "OAuth callback failed.",
      details: error instanceof Error ? error.message : String(error)
    });
  }
});

app.post("/oauth/token", async (req, res) => {
  try {
    const {
      grant_type: grantType,
      code,
      code_verifier: codeVerifier,
      refresh_token: refreshToken,
      resource,
      audience
    } = req.body;

    if (grantType === "authorization_code") {
      const payload = decryptJson(code);
      if (payload.typ !== "mcp_authorization_code") {
        return res.status(400).json({
          error: "invalid_grant",
          error_description: "Code is not a Vercel-issued authorization code."
        });
      }
      if (payload.iss !== getBaseUrl(req)) {
        return res.status(400).json({
          error: "invalid_grant",
          error_description: "Authorization code issuer mismatch."
        });
      }
      if (Date.now() > Number(payload.exp || 0)) {
        return res.status(400).json({ error: "expired_grant", error_description: "Code expired." });
      }
      if (payload.codeChallenge) {
        const verifierMethod = payload.codeChallengeMethod || "S256";
        const actualChallenge =
          verifierMethod === "S256" ? sha256Base64Url(String(codeVerifier || "")) : String(codeVerifier || "");
        if (actualChallenge !== payload.codeChallenge) {
          return res.status(400).json({
            error: "invalid_grant",
            error_description: "PKCE verification failed."
          });
        }
      }

      const requestedResource = String(resource || audience || payload.resource);
      if (requestedResource !== payload.resource) {
        return res.status(400).json({
          error: "invalid_grant",
          error_description: "Requested resource does not match authorization code."
        });
      }

      const accessToken = mintAccessToken(req, {
        resource: payload.resource,
        scope: payload.scope,
        google: payload.google
      });
      const newRefreshToken = mintRefreshToken(req, {
        resource: payload.resource,
        scope: payload.scope,
        google: payload.google
      });

      return res.json({
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: Math.floor(ACCESS_TOKEN_TTL_MS / 1000),
        refresh_token: newRefreshToken,
        scope: payload.scope,
        resource: payload.resource
      });
    }

    if (grantType === "refresh_token") {
      let payload;
      try {
        payload = decryptJson(refreshToken);
      } catch {
        return res.status(400).json({
          error: "invalid_grant",
          error_description: "Malformed refresh token."
        });
      }

      if (payload.typ !== "mcp_refresh_token") {
        return res.status(400).json({
          error: "invalid_grant",
          error_description: "Refresh token is not a Vercel-issued refresh token."
        });
      }
      if (payload.iss !== getBaseUrl(req)) {
        return res.status(400).json({
          error: "invalid_grant",
          error_description: "Refresh token issuer mismatch."
        });
      }
      if (Date.now() > Number(payload.exp || 0)) {
        return res.status(400).json({
          error: "invalid_grant",
          error_description: "Refresh token expired."
        });
      }

      const requestedResource = String(resource || audience || payload.resource);
      if (requestedResource !== payload.resource) {
        return res.status(400).json({
          error: "invalid_grant",
          error_description: "Requested resource does not match refresh token."
        });
      }

      const refreshed = await exchangeGoogleRefreshToken(req, payload.google.refreshToken);
      const grantedScopes = normalizeScopes(refreshed.scope || payload.scope);
      const googleCredentials = {
        accessToken: refreshed.access_token,
        refreshToken: payload.google.refreshToken,
        expiryDate: refreshed.expiry_date,
        scope: refreshed.scope || payload.google.scope || payload.scope,
        tokenType: refreshed.token_type || payload.google.tokenType || "Bearer"
      };
      const accessToken = mintAccessToken(req, {
        resource: payload.resource,
        scope: grantedScopes.join(" "),
        google: googleCredentials
      });
      const newRefreshToken = mintRefreshToken(req, {
        resource: payload.resource,
        scope: grantedScopes.join(" "),
        google: googleCredentials
      });

      return res.json({
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: Math.floor(ACCESS_TOKEN_TTL_MS / 1000),
        refresh_token: newRefreshToken,
        scope: grantedScopes.join(" "),
        resource: payload.resource
      });
    }

    return res.status(400).json({
      error: "unsupported_grant_type",
      error_description: "Supported grant types are authorization_code and refresh_token."
    });
  } catch (error) {
    return res.status(500).json({
      error: "token_exchange_failed",
      error_description: error instanceof Error ? error.message : String(error)
    });
  }
});

app.get("/.well-known/oauth-authorization-server", (req, res) => {
  const baseUrl = getBaseUrl(req);
  res.json({
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/auth/google/start`,
    token_endpoint: `${baseUrl}/oauth/token`,
    scopes_supported: GOOGLE_SCOPES,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256", "plain"],
    token_endpoint_auth_methods_supported: ["none"]
  });
});

app.get("/.well-known/oauth-protected-resource", (req, res) => {
  const baseUrl = getBaseUrl(req);
  res.json({
    resource: getResourceUrl(req),
    authorization_servers: [baseUrl],
    bearer_methods_supported: ["header"],
    scopes_supported: GOOGLE_SCOPES
  });
});

app.all("/mcp", async (req, res) => {
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true
  });
  const server = createServer(req);

  try {
    if (isToolCall(req.body)) {
      const requiredScopes = TOOL_SCOPE_MAP[req.body.params.name] || [];
      await verifyMcpAccessToken(req, requiredScopes);
    }

    res.on("close", () => {
      transport.close().catch(() => {});
      server.close().catch(() => {});
    });

    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (error) {
    const statusCode = error?.statusCode || 500;
    if (error?.oauthError) {
      res.setHeader("WWW-Authenticate", getAuthenticateHeader(error));
    } else if (statusCode === 401) {
      res.setHeader("WWW-Authenticate", 'Bearer realm="mcp", error="invalid_token"');
    }

    if (!res.headersSent) {
      res.status(statusCode).json(
        error?.oauthError
          ? formatAuthErrorResponse(error)
          : { error: "mcp_request_failed", details: error instanceof Error ? error.message : String(error) }
      );
    }
  }
});

export default app;
