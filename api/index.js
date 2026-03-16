import crypto from "node:crypto";
import express from "express";
import { google } from "googleapis";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

const SEARCH_CONSOLE_SCOPE = "https://www.googleapis.com/auth/webmasters.readonly";
const GA4_SCOPE = "https://www.googleapis.com/auth/analytics.readonly";
const MERCHANT_CENTER_SCOPE = "https://www.googleapis.com/auth/content";
const GOOGLE_ADS_SCOPE = "https://www.googleapis.com/auth/adwords";
const GOOGLE_SCOPES = [SEARCH_CONSOLE_SCOPE, GA4_SCOPE, MERCHANT_CENTER_SCOPE, GOOGLE_ADS_SCOPE];
const AUTH_CODE_TTL_MS = 5 * 60 * 1000;
const ACCESS_TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const REFRESH_TOKEN_TTL_MS = 90 * 24 * 60 * 60 * 1000;
const SESSION_TTL_MS = 90 * 24 * 60 * 60 * 1000;
const OAUTH_STATE_TTL_MS = 10 * 60 * 1000;
const EXPERT_VERSION = "2026.03.14";
const TOOL_SCOPE_MAP = {
  list_search_console_sites: [SEARCH_CONSOLE_SCOPE],
  query_search_console: [SEARCH_CONSOLE_SCOPE],
  list_ga4_properties: [GA4_SCOPE],
  run_ga4_report: [GA4_SCOPE],
  get_ga4_metadata: [GA4_SCOPE],
  check_ga4_compatibility: [GA4_SCOPE],
  batch_run_ga4_reports: [GA4_SCOPE],
  run_ga4_realtime_report: [GA4_SCOPE],
  run_ga4_pivot_report: [GA4_SCOPE],
  list_merchant_accounts: [MERCHANT_CENTER_SCOPE],
  get_merchant_account: [MERCHANT_CENTER_SCOPE],
  list_merchant_products: [MERCHANT_CENTER_SCOPE],
  get_merchant_product: [MERCHANT_CENTER_SCOPE],
  search_merchant_reports: [MERCHANT_CENTER_SCOPE],
  list_search_console_sitemaps: [SEARCH_CONSOLE_SCOPE],
  get_search_console_sitemap: [SEARCH_CONSOLE_SCOPE],
  inspect_search_console_url: [SEARCH_CONSOLE_SCOPE],
  list_google_ads_accessible_customers: [GOOGLE_ADS_SCOPE],
  query_google_ads: [GOOGLE_ADS_SCOPE],
  search_stream_google_ads: [GOOGLE_ADS_SCOPE],
  get_google_ads_field: [GOOGLE_ADS_SCOPE],
  search_google_ads_fields: [GOOGLE_ADS_SCOPE],
  run_google_ads_preset: [GOOGLE_ADS_SCOPE],
  run_ga4_preset: [GA4_SCOPE],
  run_search_console_preset: [SEARCH_CONSOLE_SCOPE]
};
const CALLRAIL_TOOL_NAMES = [
  "list_callrail_accounts",
  "list_callrail_companies",
  "list_callrail_calls",
  "get_callrail_call",
  "get_callrail_call_summary",
  "get_callrail_call_timeseries",
  "list_callrail_trackers",
  "get_callrail_resource"
];
const EXPERT_TOOL_NAMES = [
  "list_marketing_presets",
  "get_marketing_schema",
  "list_marketing_guardrails",
  "normalize_marketing_records"
];
const GOOGLE_ADS_PRESET_DEFINITIONS = {
  campaign_performance: {
    entityType: "campaign",
    description: "Campaign performance with delivery, cost, click, conversion, and channel fields."
  },
  ad_group_performance: {
    entityType: "ad_group",
    description: "Ad group performance with campaign context and spend/conversion metrics."
  },
  keyword_performance: {
    entityType: "keyword",
    description: "Keyword performance with campaign, ad group, text, match type, and conversion metrics."
  },
  search_terms: {
    entityType: "search_term",
    description: "Search term performance with matched campaign and ad group context."
  },
  asset_performance: {
    entityType: "asset",
    description: "Asset-level performance for ads with campaign and ad group context."
  },
  conversions_by_campaign: {
    entityType: "campaign",
    description: "Campaign conversion performance focused on conversion counts and value."
  }
};
const GA4_PRESET_DEFINITIONS = {
  channels: {
    entityType: "channel",
    description: "Channel performance by session default channel group."
  },
  landing_pages: {
    entityType: "landing_page",
    description: "Landing page performance with channel and engagement context."
  },
  source_medium: {
    entityType: "source_medium",
    description: "Source / medium performance with sessions, users, and revenue."
  },
  campaigns: {
    entityType: "campaign",
    description: "GA4 campaign performance by session campaign and source / medium."
  },
  key_events: {
    entityType: "event",
    description: "Key event and conversion-oriented event performance."
  },
  ecommerce: {
    entityType: "product",
    description: "Item and ecommerce performance."
  },
  attribution_breakdown: {
    entityType: "attribution",
    description: "Acquisition-style breakdown with session and first-user channel dimensions."
  }
};
const SEARCH_CONSOLE_PRESET_DEFINITIONS = {
  queries: {
    entityType: "query",
    description: "Search queries with clicks, impressions, CTR, and average position."
  },
  pages: {
    entityType: "page",
    description: "Landing pages or indexed URLs with search performance."
  },
  countries: {
    entityType: "country",
    description: "Country-level organic search performance."
  },
  devices: {
    entityType: "device",
    description: "Device-level organic search performance."
  },
  date_trends: {
    entityType: "date",
    description: "Date trend performance, optionally with a secondary breakdown."
  },
  branded_vs_non_branded: {
    entityType: "query_segment",
    description: "Branded or non-branded query performance using provided brand terms."
  }
};
const PLATFORM_GUARDRAILS = {
  google_ads: {
    strengths: [
      "Best source for campaigns, ad groups, ads, keywords, search terms, assets, segments, and paid conversion reporting.",
      "GAQL can express complex filters, joins, and segmentation."
    ],
    limitations: [
      "Requires GOOGLE_ADS_DEVELOPER_TOKEN and often a login-customer-id for MCC access.",
      "Accuracy depends on using valid GAQL fields for the selected resource."
    ]
  },
  ga4: {
    strengths: [
      "Best source for web/app engagement, channels, landing pages, ecommerce, and event-driven conversion reporting.",
      "Metadata and compatibility APIs reduce invalid report combinations."
    ],
    limitations: [
      "Not every GA4 UI exploration is mirrored exactly by a single Data API request.",
      "Attribution views depend on the available GA4 dimensions and metrics, not arbitrary UI-only widgets."
    ]
  },
  search_console: {
    strengths: [
      "Best source for queries, pages, countries, devices, and organic search trend reporting.",
      "URL Inspection gives URL-level Google indexing diagnostics."
    ],
    limitations: [
      "The aggregate Index Coverage UI is not exposed as an equivalent public API dataset.",
      "Search Analytics row sampling and aggregation limits still apply."
    ]
  },
  merchant_center: {
    strengths: [
      "Best source for product, account, and Merchant report datasets exposed by the Merchant API.",
      "Good for product diagnostics and performance where Merchant report datasets are available."
    ],
    limitations: [
      "Merchant API access may require GCP registration beyond enabling the API.",
      "Not every Merchant Center UI panel is exposed with equivalent API fidelity."
    ]
  },
  callrail: {
    strengths: [
      "Best source for call records, trackers, summaries, time series, and CallRail-native attribution fields.",
      "Generic resource mode allows read-only expansion across supported CallRail endpoints."
    ],
    limitations: [
      "Transcripts, intent, recordings, and landing-page fields depend on account features and endpoint payloads.",
      "Coverage is limited to what CallRail returns via the public v3 API."
    ]
  }
};
const NORMALIZED_MARKETING_SCHEMA = {
  version: EXPERT_VERSION,
  recordShape: {
    platform: "google_ads | ga4 | search_console | merchant_center | callrail",
    preset: "preset or custom normalization label",
    entityType: "campaign | ad_group | keyword | search_term | asset | channel | landing_page | source_medium | event | attribution | query | page | country | device | date | product | call | tracker",
    sourcePrimaryKey: "stable identifier from the source when available",
    dimensions: "normalized dimension dictionary",
    metrics: "normalized metric dictionary",
    sourceContext: "platform-native metadata needed for traceability"
  },
  standardDimensions: [
    "date",
    "campaign_id",
    "campaign_name",
    "ad_group_id",
    "ad_group_name",
    "keyword_text",
    "keyword_match_type",
    "search_term",
    "channel",
    "source_medium",
    "landing_page",
    "page",
    "query",
    "country",
    "device",
    "product_id",
    "product_title",
    "call_id",
    "tracker_id"
  ],
  standardMetrics: [
    "impressions",
    "clicks",
    "cost",
    "ctr",
    "average_cpc",
    "conversions",
    "conversion_value",
    "sessions",
    "users",
    "engaged_sessions",
    "event_count",
    "revenue",
    "calls",
    "qualified_calls",
    "call_duration_seconds"
  ],
  crossSourceMappings: {
    campaign_name: {
      google_ads: ["campaign.name"],
      ga4: ["sessionCampaignName", "firstUserCampaignName"],
      search_console: [],
      merchant_center: [],
      callrail: ["utm_campaign", "campaign"]
    },
    channel: {
      google_ads: ["campaign.advertising_channel_type"],
      ga4: ["sessionDefaultChannelGroup", "firstUserDefaultChannelGroup"],
      search_console: ["searchType"],
      merchant_center: ["marketingMethod"],
      callrail: ["source", "medium", "channel"]
    },
    landing_page: {
      google_ads: ["landing_page_view.unexpanded_final_url"],
      ga4: ["landingPagePlusQueryString"],
      search_console: ["page"],
      merchant_center: [],
      callrail: ["landing_page_url"]
    }
  }
};
const sessionStore = globalThis.__googleMcpSessionStore || new Map();
globalThis.__googleMcpSessionStore = sessionStore;

function requireEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
}

function getBaseUrl(req) {
  const raw = process.env.APP_BASE_URL || process.env.BASE_URL || `${req.protocol}://${req.get("host")}`;
  return String(raw).replace(/\/+$/, "");
}

function getResourceUrl(req) {
  return `${getBaseUrl(req)}/mcp`;
}

function getCallRailBaseUrl() {
  return String(process.env.CALLRAIL_API_BASE_URL || "https://api.callrail.com/v3").replace(/\/+$/, "");
}

function getGoogleAdsApiVersion() {
  return String(process.env.GOOGLE_ADS_API_VERSION || "v22").trim();
}

function getEncryptionKey() {
  const encodedKey = process.env.APP_ENCRYPTION_KEY;
  if (encodedKey) {
    const key = Buffer.from(encodedKey, "base64");
    if (key.length !== 32) throw new Error("APP_ENCRYPTION_KEY must be a base64-encoded 32-byte key.");
    return key;
  }

  const sessionSecret = process.env.SESSION_SECRET;
  if (sessionSecret) {
    return crypto.createHash("sha256").update(sessionSecret).digest();
  }

  throw new Error("Missing required environment variable: APP_ENCRYPTION_KEY or SESSION_SECRET");
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

function logAuthRouteDebug(payload) {
  console.log(JSON.stringify({ type: "auth_route_debug", ...payload }));
}

function normalizePropertyName(propertyId) {
  return propertyId.startsWith("properties/") ? propertyId : `properties/${propertyId}`;
}

function normalizeGoogleAdsCustomerId(customerId) {
  return String(customerId || "").replace(/-/g, "").trim();
}

function normalizeMerchantAccountName(accountName) {
  const normalized = String(accountName || "").trim();
  return normalized.startsWith("accounts/") ? normalized : `accounts/${normalized}`;
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

function requireCallRailApiToken() {
  const token =
    process.env.CALLRAIL_API_TOKEN ||
    process.env.CALLRAIL_TOKEN ||
    process.env.CALLRAIL_API_KEY;
  if (!token) {
    throw new Error("CallRail API token is not configured. Set CALLRAIL_API_TOKEN, CALLRAIL_TOKEN, or CALLRAIL_API_KEY.");
  }
  return token;
}

function requireGoogleAdsDeveloperToken() {
  return requireEnv("GOOGLE_ADS_DEVELOPER_TOKEN");
}

function getGoogleAdsLoginCustomerId(value) {
  const candidate = value || process.env.GOOGLE_ADS_LOGIN_CUSTOMER_ID;
  return candidate ? normalizeGoogleAdsCustomerId(candidate) : undefined;
}

function normalizeCallRailPath(path) {
  const candidate = String(path || "").trim();
  if (!candidate) throw new Error("CallRail path is required.");
  if (candidate.startsWith("http://") || candidate.startsWith("https://")) {
    const url = new URL(candidate);
    const expectedPrefix = new URL(getCallRailBaseUrl()).origin;
    if (url.origin !== expectedPrefix) {
      throw new Error("CallRail absolute URLs must match CALLRAIL_API_BASE_URL.");
    }
    return url.toString();
  }
  const normalized = candidate.startsWith("/") ? candidate : `/${candidate}`;
  if (!normalized.endsWith(".json")) {
    throw new Error('CallRail paths must end with ".json".');
  }
  return normalized;
}

function appendQueryParams(url, params = {}) {
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    if (Array.isArray(value)) {
      for (const item of value) {
        if (item === undefined || item === null || item === "") continue;
        url.searchParams.append(key, String(item));
      }
      continue;
    }
    url.searchParams.set(key, String(value));
  }
  return url;
}

function compactObject(value) {
  return Object.fromEntries(
    Object.entries(value).filter(([, entry]) => entry !== undefined && entry !== null && entry !== "")
  );
}

function getNestedValue(source, path) {
  return String(path || "").split(".").filter(Boolean).reduce((current, segment) => current?.[segment], source);
}

function toNumber(value) {
  if (value === undefined || value === null || value === "") return undefined;
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : undefined;
}

function microsToStandardCurrency(value) {
  const numeric = toNumber(value);
  return numeric === undefined ? undefined : numeric / 1_000_000;
}

function formatDateForApi(date) {
  return new Date(date).toISOString().slice(0, 10);
}

function resolveDateWindow({ startDate, endDate, lookbackDays = 30 }) {
  const end = endDate ? new Date(endDate) : new Date();
  const start = startDate ? new Date(startDate) : new Date(end.getTime() - lookbackDays * 24 * 60 * 60 * 1000);
  return {
    startDate: formatDateForApi(start),
    endDate: formatDateForApi(end)
  };
}

function buildNormalizedRecord({ platform, preset, entityType, sourcePrimaryKey, dimensions = {}, metrics = {}, sourceContext = {} }) {
  return {
    schemaVersion: NORMALIZED_MARKETING_SCHEMA.version,
    platform,
    preset,
    entityType,
    sourcePrimaryKey: sourcePrimaryKey || null,
    dimensions: compactObject(dimensions),
    metrics: compactObject(metrics),
    sourceContext: compactObject(sourceContext)
  };
}

function mapGa4ReportRows(body) {
  const dimensionHeaders = body?.dimensionHeaders || [];
  const metricHeaders = body?.metricHeaders || [];
  return (body?.rows || []).map((row) => {
    const dimensions = Object.fromEntries(
      dimensionHeaders.map((header, index) => [header.name, row.dimensionValues?.[index]?.value])
    );
    const metrics = Object.fromEntries(
      metricHeaders.map((header, index) => [header.name, row.metricValues?.[index]?.value])
    );
    return { dimensions, metrics };
  });
}

function buildSearchConsoleRowObjects(body, dimensions = []) {
  return (body?.rows || []).map((row) => {
    const mappedDimensions = Object.fromEntries(dimensions.map((dimension, index) => [dimension, row.keys?.[index]]));
    return {
      ...mappedDimensions,
      clicks: row.clicks,
      impressions: row.impressions,
      ctr: row.ctr,
      position: row.position
    };
  });
}

function saveSession(sessionId, session) {
  const record = {
    ...session,
    updatedAt: Date.now(),
    sessionExpiresAt: session.sessionExpiresAt || Date.now() + SESSION_TTL_MS
  };
  sessionStore.set(sessionId, record);
  return record;
}

function getSession(sessionId) {
  const session = sessionStore.get(sessionId);
  if (!session) return null;
  if (session.sessionExpiresAt && Number(session.sessionExpiresAt) <= Date.now()) {
    sessionStore.delete(sessionId);
    return null;
  }
  return session;
}

function deleteSession(sessionId) {
  sessionStore.delete(sessionId);
}

function mintAccessToken(req, payload) {
  return encryptJson({
    typ: "mcp_access_token",
    iss: getBaseUrl(req),
    aud: payload.resource,
    resource: payload.resource,
    sessionId: payload.sessionId,
    scope: payload.scope,
    iat: Date.now(),
    exp: Date.now() + ACCESS_TOKEN_TTL_MS
  });
}

function mintRefreshToken(req, payload) {
  return encryptJson({
    typ: "mcp_refresh_token",
    iss: getBaseUrl(req),
    aud: payload.resource,
    resource: payload.resource,
    sessionId: payload.sessionId,
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

async function refreshGoogleTokensIfNeeded(req, session) {
  if (!session?.refreshToken) {
    throw buildAuthError({
      httpStatus: 401,
      error: "invalid_token",
      errorDescription: "No valid session.",
      details: { debug: "no_valid_session" }
    });
  }
  const expiresAt = Number(session.expiryDate || 0);
  const isFresh = session.accessToken && expiresAt && expiresAt - Date.now() > 60_000;
  if (isFresh) return session;
  const oauthClient = createOauthClient(req);
  oauthClient.setCredentials({ refresh_token: session.refreshToken });
  try {
    const { credentials } = await oauthClient.refreshAccessToken();
    return saveSession(session.sessionId, {
      ...session,
      accessToken: credentials.access_token,
      refreshToken: session.refreshToken,
      expiryDate: credentials.expiry_date,
      scope: credentials.scope || session.scope,
      tokenType: credentials.token_type || session.tokenType || "Bearer"
    });
  } catch (error) {
    if (session.sessionId) {
      deleteSession(session.sessionId);
    }
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
  const sessionId = payload.sessionId;
  const session = sessionId ? getSession(sessionId) : null;
  if (!session) {
    throw buildAuthError({
      httpStatus: 401,
      error: "invalid_token",
      errorDescription: "No valid session.",
      details: { debug: "no_valid_session" }
    });
  }
  const grantedScopes = normalizeScopes(session.scope || payload.scope);
  if (!hasScopes(grantedScopes, requiredScopes)) {
    throw buildAuthError({
      httpStatus: 403,
      error: "insufficient_scope",
      errorDescription: "Missing scopes.",
      details: { debug: "missing_scopes", required_scopes: requiredScopes, granted_scopes: grantedScopes }
    });
  }
  const googleCredentials = await refreshGoogleTokensIfNeeded(req, session);
  req.mcpAuth = {
    issuer,
    resource,
    scope: grantedScopes.join(" "),
    scopes: grantedScopes,
    googleCredentials,
    sessionId,
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

async function callCallRailApi(pathOrUrl, query = {}) {
  const url = pathOrUrl.startsWith("http")
    ? new URL(pathOrUrl)
    : new URL(`${getCallRailBaseUrl()}${pathOrUrl.startsWith("/") ? "" : "/"}${pathOrUrl}`);
  appendQueryParams(url, query);
  const response = await fetch(url.toString(), {
    method: "GET",
    headers: {
      Authorization: `Token token="${requireCallRailApiToken()}"`,
      Accept: "application/json"
    }
  });
  const rawBody = await response.text();
  let parsedBody = rawBody;
  try {
    parsedBody = rawBody ? JSON.parse(rawBody) : null;
  } catch {}
  console.log(JSON.stringify({ type: "callrail_api_debug", url: url.toString(), status: response.status, body: parsedBody }));
  return { ok: response.ok, status: response.status, body: parsedBody };
}

async function callGoogleAdsApi(path, accessToken, options = {}) {
  const url = path.startsWith("http") ? path : `https://googleads.googleapis.com/${getGoogleAdsApiVersion()}/${path.replace(/^\/+/, "")}`;
  const response = await fetch(url, {
    method: options.method || "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "developer-token": requireGoogleAdsDeveloperToken(),
      ...(getGoogleAdsLoginCustomerId(options.loginCustomerId) ? { "login-customer-id": getGoogleAdsLoginCustomerId(options.loginCustomerId) } : {}),
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...options.headers
    },
    ...(options.body ? { body: JSON.stringify(options.body) } : {})
  });
  const rawBody = await response.text();
  let parsedBody = rawBody;
  try {
    parsedBody = rawBody ? JSON.parse(rawBody) : null;
  } catch {}
  console.log(JSON.stringify({ type: "google_ads_api_debug", url, status: response.status, body: parsedBody }));
  return { ok: response.ok, status: response.status, body: parsedBody };
}

function buildToolResult(payload, isError = false, meta) {
  return {
    content: [{ type: "text", text: typeof payload === "string" ? payload : JSON.stringify(payload, null, 2) }],
    ...(payload && typeof payload === "object" ? { structuredContent: payload } : {}),
    ...(isError ? { isError: true } : {}),
    ...(meta ? { _meta: meta } : {})
  };
}

function toGoogleDebugPayload(response) {
  return response.ok ? response.body : { status: response.status, error: response.body };
}

function toToolErrorPayload(error) {
  if (error?.oauthError) return formatAuthErrorResponse(error);
  return { error: "tool_execution_failed", error_description: error instanceof Error ? error.message : String(error) };
}

function shouldEmitAuthChallenge(error) {
  return ["missing_authorization_header", "bad_authorization_scheme", "no_valid_session", "google_refresh_failed", "missing_scopes"].includes(error?.details?.debug);
}

async function withVerifiedToolAuth(req, requiredScopes, handler) {
  try {
    const auth = await verifyMcpAccessToken(req, requiredScopes);
    return await handler(auth);
  } catch (error) {
    return buildToolResult(
      toToolErrorPayload(error),
      true,
      shouldEmitAuthChallenge(error) ? { "mcp/www_authenticate": getAuthenticateHeader(error) } : undefined
    );
  }
}

async function withCallRailTool(handler) {
  try {
    return await handler();
  } catch (error) {
    return buildToolResult(toToolErrorPayload(error), true);
  }
}

function buildGoogleAdsPresetQuery(params) {
  const { preset, startDate, endDate } = {
    ...params,
    ...resolveDateWindow(params)
  };
  const dateFilter = `segments.date BETWEEN '${startDate}' AND '${endDate}'`;
  const limit = Number(params.limit || 100);
  const extraWhere = Array.isArray(params.extraWhereClauses) ? params.extraWhereClauses.filter(Boolean) : [];
  const whereClauses = [dateFilter, ...extraWhere];
  const whereSql = whereClauses.length ? ` WHERE ${whereClauses.join(" AND ")}` : "";
  const orderBySql = params.orderBy ? ` ORDER BY ${params.orderBy}` : "";
  const limitSql = limit > 0 ? ` LIMIT ${limit}` : "";
  const includeDailyBreakdown = params.includeDailyBreakdown !== false;
  const dailyField = includeDailyBreakdown ? ", segments.date" : "";
  const queries = {
    campaign_performance: {
      entityType: "campaign",
      query: `SELECT campaign.id, campaign.name, campaign.status, campaign.advertising_channel_type${dailyField}, metrics.impressions, metrics.clicks, metrics.ctr, metrics.average_cpc, metrics.cost_micros, metrics.conversions, metrics.conversions_value FROM campaign${whereSql}${orderBySql || " ORDER BY metrics.cost_micros DESC"}${limitSql}`
    },
    ad_group_performance: {
      entityType: "ad_group",
      query: `SELECT campaign.id, campaign.name, ad_group.id, ad_group.name, ad_group.status${dailyField}, metrics.impressions, metrics.clicks, metrics.ctr, metrics.average_cpc, metrics.cost_micros, metrics.conversions, metrics.conversions_value FROM ad_group${whereSql}${orderBySql || " ORDER BY metrics.cost_micros DESC"}${limitSql}`
    },
    keyword_performance: {
      entityType: "keyword",
      query: `SELECT campaign.id, campaign.name, ad_group.id, ad_group.name, ad_group_criterion.criterion_id, ad_group_criterion.keyword.text, ad_group_criterion.keyword.match_type, ad_group_criterion.status${dailyField}, metrics.impressions, metrics.clicks, metrics.ctr, metrics.average_cpc, metrics.cost_micros, metrics.conversions, metrics.conversions_value FROM keyword_view${whereSql}${orderBySql || " ORDER BY metrics.clicks DESC"}${limitSql}`
    },
    search_terms: {
      entityType: "search_term",
      query: `SELECT campaign.id, campaign.name, ad_group.id, ad_group.name, search_term_view.search_term${dailyField}, metrics.impressions, metrics.clicks, metrics.ctr, metrics.cost_micros, metrics.conversions, metrics.conversions_value FROM search_term_view${whereSql}${orderBySql || " ORDER BY metrics.clicks DESC"}${limitSql}`
    },
    asset_performance: {
      entityType: "asset",
      query: `SELECT campaign.id, campaign.name, ad_group.id, ad_group.name, asset.id, asset.name, asset.type, ad_group_ad_asset_view.field_type, ad_group_ad_asset_view.performance_label${dailyField}, metrics.impressions, metrics.clicks, metrics.ctr, metrics.cost_micros, metrics.conversions FROM ad_group_ad_asset_view${whereSql}${orderBySql || " ORDER BY metrics.impressions DESC"}${limitSql}`
    },
    conversions_by_campaign: {
      entityType: "campaign",
      query: `SELECT campaign.id, campaign.name, campaign.status${dailyField}, metrics.conversions, metrics.conversions_value, metrics.cost_micros, metrics.cost_per_conversion, metrics.all_conversions, metrics.all_conversions_value FROM campaign${whereSql}${orderBySql || " ORDER BY metrics.conversions DESC"}${limitSql}`
    }
  };
  const definition = queries[preset];
  if (!definition) throw new Error(`Unsupported Google Ads preset: ${preset}`);
  return {
    ...definition,
    query: definition.query,
    dateRange: { startDate, endDate },
    limit
  };
}

function buildGa4PresetRequest(params) {
  const dateRange = resolveDateWindow(params);
  const common = {
    propertyId: params.propertyId,
    dateRanges: [{ startDate: dateRange.startDate, endDate: dateRange.endDate }],
    limit: params.limit ? String(params.limit) : undefined,
    dimensionFilter: params.dimensionFilter,
    metricFilter: params.metricFilter,
    keepEmptyRows: params.keepEmptyRows,
    orderBys: params.orderBys
  };
  const presets = {
    channels: {
      entityType: "channel",
      request: {
        ...common,
        dimensions: [{ name: "sessionDefaultChannelGroup" }],
        metrics: [{ name: "sessions" }, { name: "totalUsers" }, { name: "engagedSessions" }, { name: "conversions" }, { name: "totalRevenue" }]
      }
    },
    landing_pages: {
      entityType: "landing_page",
      request: {
        ...common,
        dimensions: [{ name: "landingPagePlusQueryString" }, { name: "sessionDefaultChannelGroup" }],
        metrics: [{ name: "sessions" }, { name: "engagedSessions" }, { name: "conversions" }, { name: "totalRevenue" }]
      }
    },
    source_medium: {
      entityType: "source_medium",
      request: {
        ...common,
        dimensions: [{ name: "sessionSourceMedium" }],
        metrics: [{ name: "sessions" }, { name: "totalUsers" }, { name: "conversions" }, { name: "totalRevenue" }]
      }
    },
    campaigns: {
      entityType: "campaign",
      request: {
        ...common,
        dimensions: [{ name: "sessionCampaignName" }, { name: "sessionSourceMedium" }],
        metrics: [{ name: "sessions" }, { name: "engagedSessions" }, { name: "conversions" }, { name: "totalRevenue" }]
      }
    },
    key_events: {
      entityType: "event",
      request: {
        ...common,
        dimensions: [{ name: "eventName" }],
        metrics: [{ name: "eventCount" }, { name: "totalUsers" }, { name: "conversions" }, { name: "totalRevenue" }]
      }
    },
    ecommerce: {
      entityType: "product",
      request: {
        ...common,
        dimensions: [{ name: "itemName" }, { name: "itemCategory" }],
        metrics: [{ name: "itemsViewed" }, { name: "itemsPurchased" }, { name: "itemRevenue" }]
      }
    },
    attribution_breakdown: {
      entityType: "attribution",
      request: {
        ...common,
        dimensions: [{ name: "sessionDefaultChannelGroup" }, { name: "firstUserDefaultChannelGroup" }],
        metrics: [{ name: "sessions" }, { name: "conversions" }, { name: "totalRevenue" }]
      }
    }
  };
  const definition = presets[params.preset];
  if (!definition) throw new Error(`Unsupported GA4 preset: ${params.preset}`);
  return {
    ...definition,
    dateRange
  };
}

function buildSearchConsolePresetRequest(params) {
  const dateRange = resolveDateWindow(params);
  const presets = {
    queries: { entityType: "query", dimensions: ["query"] },
    pages: { entityType: "page", dimensions: ["page"] },
    countries: { entityType: "country", dimensions: ["country"] },
    devices: { entityType: "device", dimensions: ["device"] },
    date_trends: { entityType: "date", dimensions: ["date", ...(params.secondaryDimension ? [params.secondaryDimension] : [])] },
    branded_vs_non_branded: { entityType: "query_segment", dimensions: ["query"] }
  };
  const definition = presets[params.preset];
  if (!definition) throw new Error(`Unsupported Search Console preset: ${params.preset}`);
  const dimensionFilterGroups = [...(params.dimensionFilterGroups || [])];
  if (params.preset === "branded_vs_non_branded") {
    if (!params.brandTerms?.length) {
      throw new Error("brandTerms is required for branded_vs_non_branded.");
    }
    const escapedTerms = params.brandTerms.map((term) => String(term).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
    const operator = params.brandMode === "non_branded" ? "excludingRegex" : "includingRegex";
    dimensionFilterGroups.push({
      groupType: "and",
      filters: [{
        dimension: "query",
        operator,
        expression: `(${escapedTerms.join("|")})`
      }]
    });
  }
  return {
    entityType: definition.entityType,
    request: {
      siteUrl: params.siteUrl,
      startDate: dateRange.startDate,
      endDate: dateRange.endDate,
      dimensions: definition.dimensions,
      rowLimit: params.rowLimit,
      startRow: params.startRow,
      aggregationType: params.aggregationType,
      dataState: params.dataState,
      searchType: params.searchType,
      type: params.type,
      dimensionFilterGroups: dimensionFilterGroups.length ? dimensionFilterGroups : undefined
    },
    dateRange
  };
}

function normalizeGoogleAdsPresetRows(preset, responseBody) {
  const rows = responseBody?.results || [];
  return rows.map((row) => {
    const dimensions = {
      date: getNestedValue(row, "segments.date"),
      campaign_id: getNestedValue(row, "campaign.id"),
      campaign_name: getNestedValue(row, "campaign.name"),
      ad_group_id: getNestedValue(row, "ad_group.id"),
      ad_group_name: getNestedValue(row, "ad_group.name"),
      keyword_text: getNestedValue(row, "ad_group_criterion.keyword.text"),
      keyword_match_type: getNestedValue(row, "ad_group_criterion.keyword.match_type"),
      search_term: getNestedValue(row, "search_term_view.search_term"),
      channel: getNestedValue(row, "campaign.advertising_channel_type"),
      asset_id: getNestedValue(row, "asset.id"),
      asset_name: getNestedValue(row, "asset.name"),
      asset_type: getNestedValue(row, "asset.type")
    };
    const sourcePrimaryKey =
      dimensions.keyword_text ? `${dimensions.ad_group_id || ""}:${dimensions.keyword_text}` :
      dimensions.search_term ? `${dimensions.ad_group_id || ""}:${dimensions.search_term}` :
      dimensions.asset_id || dimensions.ad_group_id || dimensions.campaign_id;
    return buildNormalizedRecord({
      platform: "google_ads",
      preset,
      entityType: GOOGLE_ADS_PRESET_DEFINITIONS[preset]?.entityType || "custom",
      sourcePrimaryKey,
      dimensions,
      metrics: {
        impressions: toNumber(getNestedValue(row, "metrics.impressions")),
        clicks: toNumber(getNestedValue(row, "metrics.clicks")),
        ctr: toNumber(getNestedValue(row, "metrics.ctr")),
        average_cpc: microsToStandardCurrency(getNestedValue(row, "metrics.average_cpc")),
        cost: microsToStandardCurrency(getNestedValue(row, "metrics.cost_micros")),
        conversions: toNumber(getNestedValue(row, "metrics.conversions")),
        conversion_value: toNumber(getNestedValue(row, "metrics.conversions_value"))
      },
      sourceContext: {
        status: getNestedValue(row, "campaign.status") || getNestedValue(row, "ad_group.status") || getNestedValue(row, "ad_group_criterion.status"),
        performance_label: getNestedValue(row, "ad_group_ad_asset_view.performance_label")
      }
    });
  });
}

function normalizeGa4PresetRows(preset, responseBody) {
  const rows = mapGa4ReportRows(responseBody);
  return rows.map((row) => buildNormalizedRecord({
    platform: "ga4",
    preset,
    entityType: GA4_PRESET_DEFINITIONS[preset]?.entityType || "custom",
    sourcePrimaryKey:
      row.dimensions.sessionCampaignName ||
      row.dimensions.landingPagePlusQueryString ||
      row.dimensions.sessionSourceMedium ||
      row.dimensions.itemName ||
      row.dimensions.eventName ||
      row.dimensions.sessionDefaultChannelGroup ||
      null,
    dimensions: {
      campaign_name: row.dimensions.sessionCampaignName,
      source_medium: row.dimensions.sessionSourceMedium,
      landing_page: row.dimensions.landingPagePlusQueryString,
      channel: row.dimensions.sessionDefaultChannelGroup || row.dimensions.firstUserDefaultChannelGroup,
      product_title: row.dimensions.itemName,
      query: row.dimensions.eventName
    },
    metrics: {
      sessions: toNumber(row.metrics.sessions),
      users: toNumber(row.metrics.totalUsers),
      engaged_sessions: toNumber(row.metrics.engagedSessions),
      conversions: toNumber(row.metrics.conversions),
      event_count: toNumber(row.metrics.eventCount),
      revenue: toNumber(row.metrics.totalRevenue || row.metrics.itemRevenue)
    },
    sourceContext: row.dimensions
  }));
}

function normalizeSearchConsolePresetRows(preset, responseBody, dimensions = []) {
  const rows = buildSearchConsoleRowObjects(responseBody, dimensions);
  return rows.map((row) => buildNormalizedRecord({
    platform: "search_console",
    preset,
    entityType: SEARCH_CONSOLE_PRESET_DEFINITIONS[preset]?.entityType || "custom",
    sourcePrimaryKey: row.query || row.page || row.country || row.device || row.date || null,
    dimensions: {
      date: row.date,
      query: row.query,
      page: row.page,
      country: row.country,
      device: row.device,
      channel: responseBody?.responseAggregationType
    },
    metrics: {
      clicks: toNumber(row.clicks),
      impressions: toNumber(row.impressions),
      ctr: toNumber(row.ctr),
      average_position: toNumber(row.position)
    },
    sourceContext: {
      keys: row.keys
    }
  }));
}

function buildMarketingGuardrailsPayload() {
  return {
    expertVersion: EXPERT_VERSION,
    platforms: PLATFORM_GUARDRAILS,
    normalizedSchema: NORMALIZED_MARKETING_SCHEMA
  };
}

function buildMarketingPresetCatalog() {
  return {
    expertVersion: EXPERT_VERSION,
    google_ads: GOOGLE_ADS_PRESET_DEFINITIONS,
    ga4: GA4_PRESET_DEFINITIONS,
    search_console: SEARCH_CONSOLE_PRESET_DEFINITIONS
  };
}

  function getEnvironmentPresence() {
    return {
      GOOGLE_CLIENT_ID: Boolean(process.env.GOOGLE_CLIENT_ID),
      GOOGLE_CLIENT_SECRET: Boolean(process.env.GOOGLE_CLIENT_SECRET),
      APP_BASE_URL: Boolean(process.env.APP_BASE_URL || process.env.BASE_URL),
      APP_ENCRYPTION_KEY: Boolean(process.env.APP_ENCRYPTION_KEY || process.env.SESSION_SECRET),
      GOOGLE_ADS_DEVELOPER_TOKEN: Boolean(process.env.GOOGLE_ADS_DEVELOPER_TOKEN),
      GOOGLE_ADS_LOGIN_CUSTOMER_ID: Boolean(process.env.GOOGLE_ADS_LOGIN_CUSTOMER_ID),
      CALLRAIL_API_TOKEN: Boolean(process.env.CALLRAIL_API_TOKEN),
      CALLRAIL_TOKEN: Boolean(process.env.CALLRAIL_TOKEN),
      CALLRAIL_API_KEY: Boolean(process.env.CALLRAIL_API_KEY),
      CALLRAIL_API_BASE_URL: Boolean(process.env.CALLRAIL_API_BASE_URL)
    };
  }

async function buildIntegrationDebugPayload(req) {
  const env = getEnvironmentPresence();
  const auth = {
    hasAuthorizationHeader: Boolean(req.headers.authorization),
    verified: false
  };
  try {
    const verified = await verifyMcpAccessToken(req, []);
    auth.verified = true;
    auth.scopes = verified.scopes;
    auth.scope = verified.scope;
    auth.sessionId = verified.sessionId;
    auth.resource = verified.resource;
    auth.sessionExpiresAt = verified.googleCredentials?.sessionExpiresAt || null;
    auth.googleExpiryDate = verified.googleCredentials?.expiryDate || null;
  } catch (error) {
    auth.error = formatAuthErrorResponse(error);
    if (error?.details?.required_scopes) {
      auth.requiredScopes = error.details.required_scopes;
    }
  }

  return {
    expertVersion: EXPERT_VERSION,
    baseUrl: getBaseUrl(req),
    resource: getResourceUrl(req),
    env,
    googleScopesSupported: GOOGLE_SCOPES,
    toolCoverage: {
      googleScopedTools: Object.keys(TOOL_SCOPE_MAP),
      callrailTools: CALLRAIL_TOOL_NAMES,
      advisoryTools: EXPERT_TOOL_NAMES
    },
    presets: buildMarketingPresetCatalog(),
    guardrails: PLATFORM_GUARDRAILS,
    auth
  };
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

async function getGa4Metadata(accessToken, propertyId) {
  return callGoogleApi(`https://analyticsdata.googleapis.com/v1beta/${normalizePropertyName(propertyId)}/metadata`, accessToken, {
    method: "GET"
  });
}

async function checkGa4Compatibility(accessToken, params) {
  return callGoogleApi(`https://analyticsdata.googleapis.com/v1beta/${normalizePropertyName(params.propertyId)}:checkCompatibility`, accessToken, {
    method: "POST",
    body: JSON.stringify({
      dimensions: params.dimensions,
      metrics: params.metrics,
      dimensionFilter: params.dimensionFilter,
      metricFilter: params.metricFilter,
      compatibilityFilter: params.compatibilityFilter
    })
  });
}

async function batchRunGa4Reports(accessToken, params) {
  return callGoogleApi(`https://analyticsdata.googleapis.com/v1beta/${normalizePropertyName(params.propertyId)}:batchRunReports`, accessToken, {
    method: "POST",
    body: JSON.stringify({
      requests: params.requests
    })
  });
}

async function runGa4RealtimeReport(accessToken, params) {
  return callGoogleApi(`https://analyticsdata.googleapis.com/v1beta/${normalizePropertyName(params.propertyId)}:runRealtimeReport`, accessToken, {
    method: "POST",
    body: JSON.stringify({
      dimensions: params.dimensions,
      metrics: params.metrics,
      dimensionFilter: params.dimensionFilter,
      metricFilter: params.metricFilter,
      limit: params.limit,
      minuteRanges: params.minuteRanges,
      orderBys: params.orderBys,
      returnPropertyQuota: params.returnPropertyQuota
    })
  });
}

async function runGa4PivotReport(accessToken, params) {
  return callGoogleApi(`https://analyticsdata.googleapis.com/v1beta/${normalizePropertyName(params.propertyId)}:runPivotReport`, accessToken, {
    method: "POST",
    body: JSON.stringify({
      dateRanges: params.dateRanges,
      pivots: params.pivots,
      dimensions: params.dimensions,
      metrics: params.metrics,
      dimensionFilter: params.dimensionFilter,
      metricFilter: params.metricFilter,
      currencyCode: params.currencyCode,
      cohortSpec: params.cohortSpec,
      keepEmptyRows: params.keepEmptyRows,
      returnPropertyQuota: params.returnPropertyQuota
    })
  });
}

async function listSearchConsoleSitemaps(accessToken, siteUrl) {
  return callGoogleApi(`https://www.googleapis.com/webmasters/v3/sites/${encodeURIComponent(siteUrl)}/sitemaps`, accessToken, {
    method: "GET"
  });
}

async function getSearchConsoleSitemap(accessToken, siteUrl, feedpath) {
  return callGoogleApi(`https://www.googleapis.com/webmasters/v3/sites/${encodeURIComponent(siteUrl)}/sitemaps/${encodeURIComponent(feedpath)}`, accessToken, {
    method: "GET"
  });
}

async function inspectSearchConsoleUrl(accessToken, params) {
  return callGoogleApi("https://searchconsole.googleapis.com/v1/urlInspection/index:inspect", accessToken, {
    method: "POST",
    body: JSON.stringify({
      inspectionUrl: params.inspectionUrl,
      siteUrl: params.siteUrl,
      languageCode: params.languageCode
    })
  });
}

async function listMerchantAccounts(accessToken, params = {}) {
  const url = new URL("https://merchantapi.googleapis.com/accounts/v1/accounts");
  appendQueryParams(url, {
    pageSize: params.pageSize,
    pageToken: params.pageToken,
    filter: params.filter
  });
  return callGoogleApi(url.toString(), accessToken, { method: "GET" });
}

async function getMerchantAccount(accessToken, name) {
  return callGoogleApi(`https://merchantapi.googleapis.com/accounts/v1/${normalizeMerchantAccountName(name)}`, accessToken, {
    method: "GET"
  });
}

async function listMerchantProducts(accessToken, params) {
  const parent = normalizeMerchantAccountName(params.accountId);
  const url = new URL(`https://merchantapi.googleapis.com/products/v1/${parent}/products`);
  appendQueryParams(url, {
    pageSize: params.pageSize,
    pageToken: params.pageToken
  });
  return callGoogleApi(url.toString(), accessToken, { method: "GET" });
}

async function getMerchantProduct(accessToken, name) {
  return callGoogleApi(`https://merchantapi.googleapis.com/products/v1/${String(name || "").trim()}`, accessToken, {
    method: "GET"
  });
}

async function searchMerchantReports(accessToken, params) {
  const parent = normalizeMerchantAccountName(params.accountId);
  return callGoogleApi(`https://merchantapi.googleapis.com/reports/v1beta/${parent}/reports:search`, accessToken, {
    method: "POST",
    body: JSON.stringify({
      query: params.query,
      pageSize: params.pageSize,
      pageToken: params.pageToken
    })
  });
}

async function listGoogleAdsAccessibleCustomers(accessToken) {
  return callGoogleAdsApi("customers:listAccessibleCustomers", accessToken, {
    method: "GET"
  });
}

async function queryGoogleAds(accessToken, params) {
  const customerId = normalizeGoogleAdsCustomerId(params.customerId);
  return callGoogleAdsApi(`customers/${customerId}/googleAds:search`, accessToken, {
    method: "POST",
    loginCustomerId: params.loginCustomerId,
    body: {
      query: params.query,
      pageSize: params.pageSize,
      pageToken: params.pageToken
    }
  });
}

async function searchStreamGoogleAds(accessToken, params) {
  const customerId = normalizeGoogleAdsCustomerId(params.customerId);
  return callGoogleAdsApi(`customers/${customerId}/googleAds:searchStream`, accessToken, {
    method: "POST",
    loginCustomerId: params.loginCustomerId,
    body: {
      query: params.query,
      summaryRowSetting: params.summaryRowSetting
    }
  });
}

async function getGoogleAdsField(accessToken, name) {
  return callGoogleAdsApi(`googleAdsFields/${encodeURIComponent(String(name || "").trim())}`, accessToken, {
    method: "GET"
  });
}

async function searchGoogleAdsFields(accessToken, params) {
  const url = new URL(`https://googleads.googleapis.com/${getGoogleAdsApiVersion()}/googleAdsFields:search`);
  appendQueryParams(url, {
    query: params.query,
    pageSize: params.pageSize,
    pageToken: params.pageToken
  });
  return callGoogleAdsApi(url.toString(), accessToken, {
    method: "GET"
  });
}

async function listCallRailAccounts(params = {}) {
  return callCallRailApi("/a.json", params.query);
}

async function listCallRailCompanies(params) {
  return callCallRailApi(`/a/${encodeURIComponent(params.accountId)}/companies.json`, params.query);
}

async function listCallRailCalls(params) {
  if (params.nextPageUrl) {
    return callCallRailApi(params.nextPageUrl);
  }
  return callCallRailApi(`/a/${encodeURIComponent(params.accountId)}/calls.json`, params.query);
}

async function getCallRailCall(params) {
  return callCallRailApi(`/a/${encodeURIComponent(params.accountId)}/calls/${encodeURIComponent(params.callId)}.json`, params.query);
}

async function getCallRailCallSummary(params) {
  return callCallRailApi(`/a/${encodeURIComponent(params.accountId)}/calls/summary.json`, params.query);
}

async function getCallRailCallTimeseries(params) {
  return callCallRailApi(`/a/${encodeURIComponent(params.accountId)}/calls/timeseries.json`, params.query);
}

async function listCallRailTrackers(params) {
  return callCallRailApi(`/a/${encodeURIComponent(params.accountId)}/trackers.json`, params.query);
}

async function getCallRailResource(params) {
  return callCallRailApi(normalizeCallRailPath(params.path), params.query);
}

function isToolCall(body) {
  return body?.method === "tools/call" && typeof body?.params?.name === "string";
}

function createServer(req) {
  const server = new McpServer({ name: "marketing-data-mcp", version: "1.3.0" });
  server.registerTool("list_marketing_presets", {
    title: "List Marketing Presets",
    description: "List expert Google Ads, GA4, and Search Console presets with their intended analyst use cases.",
    inputSchema: {},
    annotations: { readOnlyHint: true }
  }, async () => buildToolResult(buildMarketingPresetCatalog()));
  server.registerTool("get_marketing_schema", {
    title: "Get Marketing Schema",
    description: "Return the normalized cross-platform marketing schema and field mapping guide.",
    inputSchema: {},
    annotations: { readOnlyHint: true }
  }, async () => buildToolResult(NORMALIZED_MARKETING_SCHEMA));
  server.registerTool("list_marketing_guardrails", {
    title: "List Marketing Guardrails",
    description: "Return platform capability limits and truthfulness guardrails so analysis stays inside what each API can support.",
    inputSchema: {},
    annotations: { readOnlyHint: true }
  }, async () => buildToolResult(buildMarketingGuardrailsPayload()));
  server.registerTool("normalize_marketing_records", {
    title: "Normalize Marketing Records",
    description: "Map arbitrary platform records into the normalized cross-platform marketing schema using supplied field-path mappings.",
    inputSchema: {
      platform: z.enum(["google_ads", "ga4", "search_console", "merchant_center", "callrail"]),
      preset: z.string().optional(),
      entityType: z.string().min(1),
      records: z.array(z.record(z.any())).min(1),
      mapping: z.object({
        sourcePrimaryKey: z.string().optional(),
        dimensions: z.record(z.string()).optional(),
        metrics: z.record(z.string()).optional(),
        sourceContext: z.record(z.string()).optional()
      }).optional()
    },
    annotations: { readOnlyHint: true }
  }, async (params) => {
    const parsed = z.object({
      platform: z.enum(["google_ads", "ga4", "search_console", "merchant_center", "callrail"]),
      preset: z.string().optional(),
      entityType: z.string().min(1),
      records: z.array(z.record(z.any())).min(1),
      mapping: z.object({
        sourcePrimaryKey: z.string().optional(),
        dimensions: z.record(z.string()).optional(),
        metrics: z.record(z.string()).optional(),
        sourceContext: z.record(z.string()).optional()
      }).optional()
    }).parse(params);
    const normalizedRecords = parsed.records.map((record) => buildNormalizedRecord({
      platform: parsed.platform,
      preset: parsed.preset || "custom_normalization",
      entityType: parsed.entityType,
      sourcePrimaryKey: parsed.mapping?.sourcePrimaryKey ? getNestedValue(record, parsed.mapping.sourcePrimaryKey) : undefined,
      dimensions: Object.fromEntries(
        Object.entries(parsed.mapping?.dimensions || {}).map(([key, path]) => [key, getNestedValue(record, path)])
      ),
      metrics: Object.fromEntries(
        Object.entries(parsed.mapping?.metrics || {}).map(([key, path]) => [key, toNumber(getNestedValue(record, path)) ?? getNestedValue(record, path)])
      ),
      sourceContext: Object.fromEntries(
        Object.entries(parsed.mapping?.sourceContext || {}).map(([key, path]) => [key, getNestedValue(record, path)])
      )
    }));
    return buildToolResult({
      normalizedSchema: NORMALIZED_MARKETING_SCHEMA,
      records: normalizedRecords
    });
  });
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
  server.registerTool("list_search_console_sitemaps", {
    title: "List Search Console Sitemaps",
    description: "List sitemaps submitted for a verified Search Console property.",
    inputSchema: {
      siteUrl: z.string().min(1)
    },
    annotations: { readOnlyHint: true }
  }, async (params) => {
    const parsed = z.object({
      siteUrl: z.string().min(1)
    }).parse(params);
    return withVerifiedToolAuth(req, TOOL_SCOPE_MAP.list_search_console_sitemaps, async ({ googleCredentials }) => {
      const response = await listSearchConsoleSitemaps(googleCredentials.accessToken, parsed.siteUrl);
      return buildToolResult(toGoogleDebugPayload(response), !response.ok);
    });
  });
  server.registerTool("get_search_console_sitemap", {
    title: "Get Search Console Sitemap",
    description: "Get details for one Search Console sitemap feed path on a verified property.",
    inputSchema: {
      siteUrl: z.string().min(1),
      feedpath: z.string().min(1)
    },
    annotations: { readOnlyHint: true }
  }, async (params) => {
    const parsed = z.object({
      siteUrl: z.string().min(1),
      feedpath: z.string().min(1)
    }).parse(params);
    return withVerifiedToolAuth(req, TOOL_SCOPE_MAP.get_search_console_sitemap, async ({ googleCredentials }) => {
      const response = await getSearchConsoleSitemap(googleCredentials.accessToken, parsed.siteUrl, parsed.feedpath);
      return buildToolResult(toGoogleDebugPayload(response), !response.ok);
    });
  });
  server.registerTool("inspect_search_console_url", {
    title: "Inspect Search Console URL",
    description: "Inspect Google index status for a single URL. This is the API alternative to aggregate Index Coverage UI data.",
    inputSchema: {
      siteUrl: z.string().min(1),
      inspectionUrl: z.string().url(),
      languageCode: z.string().optional()
    },
    annotations: { readOnlyHint: true }
  }, async (params) => {
    const parsed = z.object({
      siteUrl: z.string().min(1),
      inspectionUrl: z.string().url(),
      languageCode: z.string().optional()
    }).parse(params);
    return withVerifiedToolAuth(req, TOOL_SCOPE_MAP.inspect_search_console_url, async ({ googleCredentials }) => {
      const response = await inspectSearchConsoleUrl(googleCredentials.accessToken, parsed);
      return buildToolResult(toGoogleDebugPayload(response), !response.ok);
    });
  });
  server.registerTool("run_search_console_preset", {
    title: "Run Search Console Preset",
    description: "Run expert Search Console presets for queries, pages, countries, devices, date trends, or branded vs non-branded analysis.",
    inputSchema: {
      preset: z.enum(["queries", "pages", "countries", "devices", "date_trends", "branded_vs_non_branded"]),
      siteUrl: z.string().min(1),
      startDate: z.string().optional(),
      endDate: z.string().optional(),
      rowLimit: z.number().int().min(1).max(25000).optional(),
      startRow: z.number().int().min(0).optional(),
      aggregationType: z.enum(["auto", "byPage", "byProperty", "byNewsShowcasePanel"]).optional(),
      dataState: z.enum(["all", "final", "hourly_all"]).optional(),
      searchType: z.enum(["web", "image", "video", "news", "discover", "googleNews"]).optional(),
      type: z.enum(["web", "image", "video", "discover", "googleNews", "news"]).optional(),
      secondaryDimension: z.enum(["country", "device", "page", "query"]).optional(),
      brandTerms: z.array(z.string()).optional(),
      brandMode: z.enum(["branded", "non_branded"]).optional(),
      dimensionFilterGroups: z.array(z.record(z.any())).optional()
    },
    annotations: { readOnlyHint: true }
  }, async (params) => {
    const parsed = z.object({
      preset: z.enum(["queries", "pages", "countries", "devices", "date_trends", "branded_vs_non_branded"]),
      siteUrl: z.string().min(1),
      startDate: z.string().optional(),
      endDate: z.string().optional(),
      rowLimit: z.number().int().min(1).max(25000).optional(),
      startRow: z.number().int().min(0).optional(),
      aggregationType: z.enum(["auto", "byPage", "byProperty", "byNewsShowcasePanel"]).optional(),
      dataState: z.enum(["all", "final", "hourly_all"]).optional(),
      searchType: z.enum(["web", "image", "video", "news", "discover", "googleNews"]).optional(),
      type: z.enum(["web", "image", "video", "discover", "googleNews", "news"]).optional(),
      secondaryDimension: z.enum(["country", "device", "page", "query"]).optional(),
      brandTerms: z.array(z.string()).optional(),
      brandMode: z.enum(["branded", "non_branded"]).optional(),
      dimensionFilterGroups: z.array(z.record(z.any())).optional()
    }).parse(params);
    return withVerifiedToolAuth(req, TOOL_SCOPE_MAP.run_search_console_preset, async ({ googleCredentials }) => {
      const presetConfig = buildSearchConsolePresetRequest(parsed);
      const response = await querySearchConsole(googleCredentials.accessToken, presetConfig.request);
      return buildToolResult({
        preset: parsed.preset,
        entityType: presetConfig.entityType,
        guardrails: PLATFORM_GUARDRAILS.search_console,
        request: presetConfig.request,
        normalizedSchema: NORMALIZED_MARKETING_SCHEMA,
        normalizedRows: response.ok ? normalizeSearchConsolePresetRows(parsed.preset, response.body, presetConfig.request.dimensions) : [],
        raw: toGoogleDebugPayload(response)
      }, !response.ok);
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
  server.registerTool("get_ga4_metadata", {
    title: "Get GA4 Metadata",
    description: "List GA4 dimensions and metrics available for a property, including custom definitions and compatibility metadata.",
    inputSchema: {
      propertyId: z.string().min(1)
    },
    annotations: { readOnlyHint: true }
  }, async (params) => {
    const parsed = z.object({
      propertyId: z.string().min(1)
    }).parse(params);
    return withVerifiedToolAuth(req, TOOL_SCOPE_MAP.get_ga4_metadata, async ({ googleCredentials }) => {
      const response = await getGa4Metadata(googleCredentials.accessToken, parsed.propertyId);
      return buildToolResult(toGoogleDebugPayload(response), !response.ok);
    });
  });
  server.registerTool("check_ga4_compatibility", {
    title: "Check GA4 Compatibility",
    description: "Validate whether a GA4 dimension and metric set can be queried together before running a report.",
    inputSchema: {
      propertyId: z.string().min(1),
      dimensions: z.array(z.object({ name: z.string().min(1) })).optional(),
      metrics: z.array(z.object({ name: z.string().min(1) })).optional(),
      dimensionFilter: z.record(z.any()).optional(),
      metricFilter: z.record(z.any()).optional(),
      compatibilityFilter: z.string().optional()
    },
    annotations: { readOnlyHint: true }
  }, async (params) => {
    const parsed = z.object({
      propertyId: z.string().min(1),
      dimensions: z.array(z.object({ name: z.string().min(1) })).optional(),
      metrics: z.array(z.object({ name: z.string().min(1) })).optional(),
      dimensionFilter: z.record(z.any()).optional(),
      metricFilter: z.record(z.any()).optional(),
      compatibilityFilter: z.string().optional()
    }).parse(params);
    return withVerifiedToolAuth(req, TOOL_SCOPE_MAP.check_ga4_compatibility, async ({ googleCredentials }) => {
      const response = await checkGa4Compatibility(googleCredentials.accessToken, parsed);
      return buildToolResult(toGoogleDebugPayload(response), !response.ok);
    });
  });
  server.registerTool("batch_run_ga4_reports", {
    title: "Batch Run GA4 Reports",
    description: "Run multiple GA4 core reports in one request.",
    inputSchema: {
      propertyId: z.string().min(1),
      requests: z.array(z.record(z.any())).min(1)
    },
    annotations: { readOnlyHint: true }
  }, async (params) => {
    const parsed = z.object({
      propertyId: z.string().min(1),
      requests: z.array(z.record(z.any())).min(1)
    }).parse(params);
    return withVerifiedToolAuth(req, TOOL_SCOPE_MAP.batch_run_ga4_reports, async ({ googleCredentials }) => {
      const response = await batchRunGa4Reports(googleCredentials.accessToken, parsed);
      return buildToolResult(toGoogleDebugPayload(response), !response.ok);
    });
  });
  server.registerTool("run_ga4_realtime_report", {
    title: "Run GA4 Realtime Report",
    description: "Run a GA4 realtime report for live users, sources, channels, campaigns, and events.",
    inputSchema: {
      propertyId: z.string().min(1),
      dimensions: z.array(z.object({ name: z.string().min(1) })).optional(),
      metrics: z.array(z.object({ name: z.string().min(1) })).min(1),
      dimensionFilter: z.record(z.any()).optional(),
      metricFilter: z.record(z.any()).optional(),
      limit: z.string().optional(),
      minuteRanges: z.array(z.record(z.any())).optional(),
      orderBys: z.array(z.record(z.any())).optional(),
      returnPropertyQuota: z.boolean().optional()
    },
    annotations: { readOnlyHint: true }
  }, async (params) => {
    const parsed = z.object({
      propertyId: z.string().min(1),
      dimensions: z.array(z.object({ name: z.string().min(1) })).optional(),
      metrics: z.array(z.object({ name: z.string().min(1) })).min(1),
      dimensionFilter: z.record(z.any()).optional(),
      metricFilter: z.record(z.any()).optional(),
      limit: z.string().optional(),
      minuteRanges: z.array(z.record(z.any())).optional(),
      orderBys: z.array(z.record(z.any())).optional(),
      returnPropertyQuota: z.boolean().optional()
    }).parse(params);
    return withVerifiedToolAuth(req, TOOL_SCOPE_MAP.run_ga4_realtime_report, async ({ googleCredentials }) => {
      const response = await runGa4RealtimeReport(googleCredentials.accessToken, parsed);
      return buildToolResult(toGoogleDebugPayload(response), !response.ok);
    });
  });
  server.registerTool("run_ga4_pivot_report", {
    title: "Run GA4 Pivot Report",
    description: "Run a GA4 pivot report for channel, attribution, landing page, country, device, or other pivoted breakdowns.",
    inputSchema: {
      propertyId: z.string().min(1),
      dateRanges: z.array(z.object({ startDate: z.string(), endDate: z.string() })),
      pivots: z.array(z.record(z.any())).min(1),
      dimensions: z.array(z.object({ name: z.string().min(1) })).optional(),
      metrics: z.array(z.object({ name: z.string().min(1) })).min(1),
      dimensionFilter: z.record(z.any()).optional(),
      metricFilter: z.record(z.any()).optional(),
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
      pivots: z.array(z.record(z.any())).min(1),
      dimensions: z.array(z.object({ name: z.string().min(1) })).optional(),
      metrics: z.array(z.object({ name: z.string().min(1) })).min(1),
      dimensionFilter: z.record(z.any()).optional(),
      metricFilter: z.record(z.any()).optional(),
      currencyCode: z.string().optional(),
      cohortSpec: z.record(z.any()).optional(),
      keepEmptyRows: z.boolean().optional(),
      returnPropertyQuota: z.boolean().optional()
    }).parse(params);
    return withVerifiedToolAuth(req, TOOL_SCOPE_MAP.run_ga4_pivot_report, async ({ googleCredentials }) => {
      const response = await runGa4PivotReport(googleCredentials.accessToken, parsed);
      return buildToolResult(toGoogleDebugPayload(response), !response.ok);
    });
  });
  server.registerTool("run_ga4_preset", {
    title: "Run GA4 Preset",
    description: "Run expert GA4 presets for channels, landing pages, source / medium, campaigns, key events, ecommerce, or attribution-style analysis.",
    inputSchema: {
      preset: z.enum(["channels", "landing_pages", "source_medium", "campaigns", "key_events", "ecommerce", "attribution_breakdown"]),
      propertyId: z.string().min(1),
      startDate: z.string().optional(),
      endDate: z.string().optional(),
      limit: z.number().int().min(1).max(100000).optional(),
      dimensionFilter: z.record(z.any()).optional(),
      metricFilter: z.record(z.any()).optional(),
      orderBys: z.array(z.record(z.any())).optional(),
      keepEmptyRows: z.boolean().optional()
    },
    annotations: { readOnlyHint: true }
  }, async (params) => {
    const parsed = z.object({
      preset: z.enum(["channels", "landing_pages", "source_medium", "campaigns", "key_events", "ecommerce", "attribution_breakdown"]),
      propertyId: z.string().min(1),
      startDate: z.string().optional(),
      endDate: z.string().optional(),
      limit: z.number().int().min(1).max(100000).optional(),
      dimensionFilter: z.record(z.any()).optional(),
      metricFilter: z.record(z.any()).optional(),
      orderBys: z.array(z.record(z.any())).optional(),
      keepEmptyRows: z.boolean().optional()
    }).parse(params);
    return withVerifiedToolAuth(req, TOOL_SCOPE_MAP.run_ga4_preset, async ({ googleCredentials }) => {
      const presetConfig = buildGa4PresetRequest(parsed);
      const response = await runGa4Report(googleCredentials.accessToken, presetConfig.request);
      return buildToolResult({
        preset: parsed.preset,
        entityType: presetConfig.entityType,
        dateRange: presetConfig.dateRange,
        guardrails: PLATFORM_GUARDRAILS.ga4,
        request: presetConfig.request,
        normalizedSchema: NORMALIZED_MARKETING_SCHEMA,
        normalizedRows: response.ok ? normalizeGa4PresetRows(parsed.preset, response.body) : [],
        raw: toGoogleDebugPayload(response)
      }, !response.ok);
    });
  });
  server.registerTool("list_merchant_accounts", {
    title: "List Merchant Center Accounts",
    description: "List Merchant Center accounts accessible to the authenticated Google user.",
    inputSchema: {
      pageSize: z.number().int().min(1).max(500).optional(),
      pageToken: z.string().optional(),
      filter: z.string().optional()
    },
    annotations: { readOnlyHint: true }
  }, async (params) => {
    const parsed = z.object({
      pageSize: z.number().int().min(1).max(500).optional(),
      pageToken: z.string().optional(),
      filter: z.string().optional()
    }).parse(params);
    return withVerifiedToolAuth(req, TOOL_SCOPE_MAP.list_merchant_accounts, async ({ googleCredentials }) => {
      const response = await listMerchantAccounts(googleCredentials.accessToken, parsed);
      return buildToolResult(toGoogleDebugPayload(response), !response.ok);
    });
  });
  server.registerTool("get_merchant_account", {
    title: "Get Merchant Center Account",
    description: "Get a Merchant Center account by account resource name or numeric account ID.",
    inputSchema: {
      name: z.string().min(1)
    },
    annotations: { readOnlyHint: true }
  }, async (params) => {
    const parsed = z.object({
      name: z.string().min(1)
    }).parse(params);
    return withVerifiedToolAuth(req, TOOL_SCOPE_MAP.get_merchant_account, async ({ googleCredentials }) => {
      const response = await getMerchantAccount(googleCredentials.accessToken, parsed.name);
      return buildToolResult(toGoogleDebugPayload(response), !response.ok);
    });
  });
  server.registerTool("list_merchant_products", {
    title: "List Merchant Center Products",
    description: "List processed products for a Merchant Center account.",
    inputSchema: {
      accountId: z.string().min(1),
      pageSize: z.number().int().min(1).max(250).optional(),
      pageToken: z.string().optional()
    },
    annotations: { readOnlyHint: true }
  }, async (params) => {
    const parsed = z.object({
      accountId: z.string().min(1),
      pageSize: z.number().int().min(1).max(250).optional(),
      pageToken: z.string().optional()
    }).parse(params);
    return withVerifiedToolAuth(req, TOOL_SCOPE_MAP.list_merchant_products, async ({ googleCredentials }) => {
      const response = await listMerchantProducts(googleCredentials.accessToken, parsed);
      return buildToolResult(toGoogleDebugPayload(response), !response.ok);
    });
  });
  server.registerTool("get_merchant_product", {
    title: "Get Merchant Center Product",
    description: "Get a processed Merchant Center product by full resource name, for example accounts/123/products/en~US~sku123.",
    inputSchema: {
      name: z.string().min(1)
    },
    annotations: { readOnlyHint: true }
  }, async (params) => {
    const parsed = z.object({
      name: z.string().min(1)
    }).parse(params);
    return withVerifiedToolAuth(req, TOOL_SCOPE_MAP.get_merchant_product, async ({ googleCredentials }) => {
      const response = await getMerchantProduct(googleCredentials.accessToken, parsed.name);
      return buildToolResult(toGoogleDebugPayload(response), !response.ok);
    });
  });
  server.registerTool("search_merchant_reports", {
    title: "Search Merchant Center Reports",
    description: "Run Merchant Center report queries for product performance, competitive visibility, price benchmarks, and other reporting datasets.",
    inputSchema: {
      accountId: z.string().min(1),
      query: z.string().min(1),
      pageSize: z.number().int().min(1).max(1000).optional(),
      pageToken: z.string().optional()
    },
    annotations: { readOnlyHint: true }
  }, async (params) => {
    const parsed = z.object({
      accountId: z.string().min(1),
      query: z.string().min(1),
      pageSize: z.number().int().min(1).max(1000).optional(),
      pageToken: z.string().optional()
    }).parse(params);
    return withVerifiedToolAuth(req, TOOL_SCOPE_MAP.search_merchant_reports, async ({ googleCredentials }) => {
      const response = await searchMerchantReports(googleCredentials.accessToken, parsed);
      return buildToolResult(toGoogleDebugPayload(response), !response.ok);
    });
  });
  server.registerTool("list_google_ads_accessible_customers", {
    title: "List Google Ads Accessible Customers",
    description: "List Google Ads customer resource names available to the authenticated Google user.",
    inputSchema: {},
    annotations: { readOnlyHint: true }
  }, async () => withVerifiedToolAuth(req, TOOL_SCOPE_MAP.list_google_ads_accessible_customers, async ({ googleCredentials }) => {
    const response = await listGoogleAdsAccessibleCustomers(googleCredentials.accessToken);
    return buildToolResult(toGoogleDebugPayload(response), !response.ok);
  }));
  server.registerTool("query_google_ads", {
    title: "Query Google Ads",
    description: "Run a GAQL query against a Google Ads customer. Use this for campaigns, ad groups, ads, keywords, assets, conversions, placements, audiences, search terms, and reporting.",
    inputSchema: {
      customerId: z.string().min(1),
      query: z.string().min(1),
      loginCustomerId: z.string().optional(),
      pageSize: z.number().int().min(1).max(10000).optional(),
      pageToken: z.string().optional()
    },
    annotations: { readOnlyHint: true }
  }, async (params) => {
    const parsed = z.object({
      customerId: z.string().min(1),
      query: z.string().min(1),
      loginCustomerId: z.string().optional(),
      pageSize: z.number().int().min(1).max(10000).optional(),
      pageToken: z.string().optional()
    }).parse(params);
    return withVerifiedToolAuth(req, TOOL_SCOPE_MAP.query_google_ads, async ({ googleCredentials }) => {
      const response = await queryGoogleAds(googleCredentials.accessToken, parsed);
      return buildToolResult(toGoogleDebugPayload(response), !response.ok);
    });
  });
  server.registerTool("search_stream_google_ads", {
    title: "Search Stream Google Ads",
    description: "Run a streamed GAQL query for large Google Ads result sets.",
    inputSchema: {
      customerId: z.string().min(1),
      query: z.string().min(1),
      loginCustomerId: z.string().optional(),
      summaryRowSetting: z.enum(["NO_SUMMARY_ROW", "SUMMARY_ROW_WITH_RESULTS", "SUMMARY_ROW_ONLY"]).optional()
    },
    annotations: { readOnlyHint: true }
  }, async (params) => {
    const parsed = z.object({
      customerId: z.string().min(1),
      query: z.string().min(1),
      loginCustomerId: z.string().optional(),
      summaryRowSetting: z.enum(["NO_SUMMARY_ROW", "SUMMARY_ROW_WITH_RESULTS", "SUMMARY_ROW_ONLY"]).optional()
    }).parse(params);
    return withVerifiedToolAuth(req, TOOL_SCOPE_MAP.search_stream_google_ads, async ({ googleCredentials }) => {
      const response = await searchStreamGoogleAds(googleCredentials.accessToken, parsed);
      return buildToolResult(toGoogleDebugPayload(response), !response.ok);
    });
  });
  server.registerTool("get_google_ads_field", {
    title: "Get Google Ads Field",
    description: "Get metadata for a Google Ads field or resource, including whether it is selectable, filterable, sortable, and repeated.",
    inputSchema: {
      name: z.string().min(1)
    },
    annotations: { readOnlyHint: true }
  }, async (params) => {
    const parsed = z.object({
      name: z.string().min(1)
    }).parse(params);
    return withVerifiedToolAuth(req, TOOL_SCOPE_MAP.get_google_ads_field, async ({ googleCredentials }) => {
      const response = await getGoogleAdsField(googleCredentials.accessToken, parsed.name);
      return buildToolResult(toGoogleDebugPayload(response), !response.ok);
    });
  });
  server.registerTool("search_google_ads_fields", {
    title: "Search Google Ads Fields",
    description: "Search Google Ads field metadata so you can discover valid attributes, segments, metrics, and filters before writing GAQL.",
    inputSchema: {
      query: z.string().min(1),
      pageSize: z.number().int().min(1).max(1000).optional(),
      pageToken: z.string().optional()
    },
    annotations: { readOnlyHint: true }
  }, async (params) => {
    const parsed = z.object({
      query: z.string().min(1),
      pageSize: z.number().int().min(1).max(1000).optional(),
      pageToken: z.string().optional()
    }).parse(params);
    return withVerifiedToolAuth(req, TOOL_SCOPE_MAP.search_google_ads_fields, async ({ googleCredentials }) => {
      const response = await searchGoogleAdsFields(googleCredentials.accessToken, parsed);
      return buildToolResult(toGoogleDebugPayload(response), !response.ok);
    });
  });
  server.registerTool("run_google_ads_preset", {
    title: "Run Google Ads Preset",
    description: "Run expert Google Ads presets for campaign, ad group, keyword, search term, asset, and conversion performance using GAQL.",
    inputSchema: {
      preset: z.enum(["campaign_performance", "ad_group_performance", "keyword_performance", "search_terms", "asset_performance", "conversions_by_campaign"]),
      customerId: z.string().min(1),
      loginCustomerId: z.string().optional(),
      startDate: z.string().optional(),
      endDate: z.string().optional(),
      limit: z.number().int().min(1).max(100000).optional(),
      includeDailyBreakdown: z.boolean().optional(),
      orderBy: z.string().optional(),
      extraWhereClauses: z.array(z.string()).optional(),
      pageToken: z.string().optional()
    },
    annotations: { readOnlyHint: true }
  }, async (params) => {
    const parsed = z.object({
      preset: z.enum(["campaign_performance", "ad_group_performance", "keyword_performance", "search_terms", "asset_performance", "conversions_by_campaign"]),
      customerId: z.string().min(1),
      loginCustomerId: z.string().optional(),
      startDate: z.string().optional(),
      endDate: z.string().optional(),
      limit: z.number().int().min(1).max(100000).optional(),
      includeDailyBreakdown: z.boolean().optional(),
      orderBy: z.string().optional(),
      extraWhereClauses: z.array(z.string()).optional(),
      pageToken: z.string().optional()
    }).parse(params);
    return withVerifiedToolAuth(req, TOOL_SCOPE_MAP.run_google_ads_preset, async ({ googleCredentials }) => {
      const presetConfig = buildGoogleAdsPresetQuery(parsed);
      const response = await queryGoogleAds(googleCredentials.accessToken, {
        customerId: parsed.customerId,
        loginCustomerId: parsed.loginCustomerId,
        query: presetConfig.query,
        pageSize: parsed.limit,
        pageToken: parsed.pageToken
      });
      return buildToolResult({
        preset: parsed.preset,
        entityType: presetConfig.entityType,
        dateRange: presetConfig.dateRange,
        guardrails: PLATFORM_GUARDRAILS.google_ads,
        gaql: presetConfig.query,
        normalizedSchema: NORMALIZED_MARKETING_SCHEMA,
        normalizedRows: response.ok ? normalizeGoogleAdsPresetRows(parsed.preset, response.body) : [],
        raw: toGoogleDebugPayload(response)
      }, !response.ok);
    });
  });
  server.registerTool("list_callrail_accounts", {
    title: "List CallRail Accounts",
    description: "List CallRail accounts visible to the configured CallRail API token.",
    inputSchema: {
      query: z.record(z.any()).optional()
    },
    annotations: { readOnlyHint: true }
  }, async (params) => {
    const parsed = z.object({
      query: z.record(z.any()).optional()
    }).parse(params);
    return withCallRailTool(async () => {
      const response = await listCallRailAccounts(parsed);
      return buildToolResult(toGoogleDebugPayload(response), !response.ok);
    });
  });
  server.registerTool("list_callrail_companies", {
    title: "List CallRail Companies",
    description: "List CallRail companies for an account visible to the configured CallRail API token.",
    inputSchema: {
      accountId: z.string().min(1),
      query: z.record(z.any()).optional()
    },
    annotations: { readOnlyHint: true }
  }, async (params) => {
    const parsed = z.object({
      accountId: z.string().min(1),
      query: z.record(z.any()).optional()
    }).parse(params);
    return withCallRailTool(async () => {
      const response = await listCallRailCompanies(parsed);
      return buildToolResult(toGoogleDebugPayload(response), !response.ok);
    });
  });
  server.registerTool("list_callrail_calls", {
    title: "List CallRail Calls",
    description: "List CallRail calls for an account. Pass documented API query params via query, or pass nextPageUrl from a previous response for relative pagination.",
    inputSchema: {
      accountId: z.string().min(1).optional(),
      nextPageUrl: z.string().url().optional(),
      query: z.record(z.any()).optional()
    },
    annotations: { readOnlyHint: true }
  }, async (params) => {
    const parsed = z.object({
      accountId: z.string().min(1).optional(),
      nextPageUrl: z.string().url().optional(),
      query: z.record(z.any()).optional()
    }).parse(params);
    if (!parsed.accountId && !parsed.nextPageUrl) {
      return buildToolResult({
        error: "invalid_request",
        error_description: "Provide accountId or nextPageUrl."
      }, true);
    }
    return withCallRailTool(async () => {
      const response = await listCallRailCalls(parsed);
      return buildToolResult(toGoogleDebugPayload(response), !response.ok);
    });
  });
  server.registerTool("get_callrail_call", {
    title: "Get CallRail Call",
    description: "Get one CallRail call record, including transcript, recording, landing page, tags, source, and attribution fields when available from the API.",
    inputSchema: {
      accountId: z.string().min(1),
      callId: z.string().min(1),
      query: z.record(z.any()).optional()
    },
    annotations: { readOnlyHint: true }
  }, async (params) => {
    const parsed = z.object({
      accountId: z.string().min(1),
      callId: z.string().min(1),
      query: z.record(z.any()).optional()
    }).parse(params);
    return withCallRailTool(async () => {
      const response = await getCallRailCall(parsed);
      return buildToolResult(toGoogleDebugPayload(response), !response.ok);
    });
  });
  server.registerTool("get_callrail_call_summary", {
    title: "Get CallRail Call Summary",
    description: "Get CallRail aggregated call summary metrics for an account using CallRail summary filters.",
    inputSchema: {
      accountId: z.string().min(1),
      query: z.record(z.any()).optional()
    },
    annotations: { readOnlyHint: true }
  }, async (params) => {
    const parsed = z.object({
      accountId: z.string().min(1),
      query: z.record(z.any()).optional()
    }).parse(params);
    return withCallRailTool(async () => {
      const response = await getCallRailCallSummary(parsed);
      return buildToolResult(toGoogleDebugPayload(response), !response.ok);
    });
  });
  server.registerTool("get_callrail_call_timeseries", {
    title: "Get CallRail Call Timeseries",
    description: "Get CallRail time-series call metrics for trend analysis with channels, campaigns, sources, and attribution filters.",
    inputSchema: {
      accountId: z.string().min(1),
      query: z.record(z.any()).optional()
    },
    annotations: { readOnlyHint: true }
  }, async (params) => {
    const parsed = z.object({
      accountId: z.string().min(1),
      query: z.record(z.any()).optional()
    }).parse(params);
    return withCallRailTool(async () => {
      const response = await getCallRailCallTimeseries(parsed);
      return buildToolResult(toGoogleDebugPayload(response), !response.ok);
    });
  });
  server.registerTool("list_callrail_trackers", {
    title: "List CallRail Trackers",
    description: "List CallRail tracking numbers and trackers for an account.",
    inputSchema: {
      accountId: z.string().min(1),
      query: z.record(z.any()).optional()
    },
    annotations: { readOnlyHint: true }
  }, async (params) => {
    const parsed = z.object({
      accountId: z.string().min(1),
      query: z.record(z.any()).optional()
    }).parse(params);
    return withCallRailTool(async () => {
      const response = await listCallRailTrackers(parsed);
      return buildToolResult(toGoogleDebugPayload(response), !response.ok);
    });
  });
  server.registerTool("get_callrail_resource", {
    title: "Get CallRail Resource",
    description: "Fetch any supported read-only CallRail v3 JSON endpoint by path, for example /a/{accountId}/calls.json or /a/{accountId}/trackers.json.",
    inputSchema: {
      path: z.string().min(1),
      query: z.record(z.any()).optional()
    },
    annotations: { readOnlyHint: true }
  }, async (params) => {
    const parsed = z.object({
      path: z.string().min(1),
      query: z.record(z.any()).optional()
    }).parse(params);
    return withCallRailTool(async () => {
      const response = await getCallRailResource(parsed);
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
    name: "marketing-data-mcp",
    expertVersion: EXPERT_VERSION,
    mcpUrl: `${baseUrl}/mcp`,
    oauthStartUrl: `${baseUrl}/auth/google/start`,
    oauthCallbackUrl: `${baseUrl}/auth/google/callback`,
    tokenUrl: `${baseUrl}/oauth/token`,
    resource: getResourceUrl(req),
    scopes: GOOGLE_SCOPES,
    tools: [...Object.keys(TOOL_SCOPE_MAP), ...CALLRAIL_TOOL_NAMES, ...EXPERT_TOOL_NAMES],
    presets: buildMarketingPresetCatalog()
  });
});

app.get("/debug/integrations", async (req, res) => {
  try {
    const payload = await buildIntegrationDebugPayload(req);
    res.json(payload);
  } catch (error) {
    res.status(500).json({
      error: "integration_debug_failed",
      error_description: error instanceof Error ? error.message : String(error)
    });
  }
});

app.get("/auth/google/start", (req, res) => {
  try {
    logAuthRouteDebug({
      route: "/auth/google/start",
      env_present: {
        GOOGLE_CLIENT_ID: Boolean(process.env.GOOGLE_CLIENT_ID),
        GOOGLE_CLIENT_SECRET: Boolean(process.env.GOOGLE_CLIENT_SECRET),
        BASE_URL: Boolean(process.env.BASE_URL),
        APP_BASE_URL: Boolean(process.env.APP_BASE_URL),
        SESSION_SECRET: Boolean(process.env.SESSION_SECRET),
        APP_ENCRYPTION_KEY: Boolean(process.env.APP_ENCRYPTION_KEY),
        GOOGLE_ADS_DEVELOPER_TOKEN: Boolean(process.env.GOOGLE_ADS_DEVELOPER_TOKEN),
        GOOGLE_ADS_LOGIN_CUSTOMER_ID: Boolean(process.env.GOOGLE_ADS_LOGIN_CUSTOMER_ID),
        CALLRAIL_API_TOKEN: Boolean(process.env.CALLRAIL_API_TOKEN),
        CALLRAIL_TOKEN: Boolean(process.env.CALLRAIL_TOKEN),
        CALLRAIL_API_KEY: Boolean(process.env.CALLRAIL_API_KEY)
      }
    });

    const computedRedirectUri = `${getBaseUrl(req)}/auth/google/callback`;
    logAuthRouteDebug({
      route: "/auth/google/start",
      computed_redirect_uri: computedRedirectUri
    });

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
      scope: requestedScopes,
      include_granted_scopes: true,
      prompt: "consent",
      state: encryptJson(appState)
    });

    logAuthRouteDebug({
      route: "/auth/google/start",
      generated_auth_url: googleAuthUrl
    });

    return res.redirect(302, googleAuthUrl);
  } catch (error) {
    logAuthRouteDebug({
      route: "/auth/google/start",
      error_message: error instanceof Error ? error.message : String(error),
      error_stack: error instanceof Error ? error.stack : String(error)
    });

    return res.status(500).json({
      error: "auth_start_failed",
      error_description: error instanceof Error ? error.message : String(error)
    });
  }
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
    const sessionId = crypto.randomUUID();
    saveSession(sessionId, {
      sessionId,
      refreshToken: tokens.refresh_token,
      accessToken: tokens.access_token,
      expiryDate: tokens.expiry_date,
      scope: tokens.scope || grantedScopes.join(" "),
      tokenType: tokens.token_type || "Bearer",
      sessionExpiresAt: Date.now() + SESSION_TTL_MS
    });

    const authCode = encryptJson({
      typ: "mcp_authorization_code",
      iss: getBaseUrl(req),
      aud: appState.resource,
      resource: appState.resource,
      sessionId,
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
    logAuthRouteDebug({
      route: "/auth/google/callback",
      error_message: error instanceof Error ? error.message : String(error),
      error_stack: error instanceof Error ? error.stack : String(error)
    });

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

      const sessionId = payload.sessionId || crypto.randomUUID();
      const session = saveSession(sessionId, {
        sessionId,
        refreshToken: payload.google.refreshToken,
        accessToken: payload.google.accessToken,
        expiryDate: payload.google.expiryDate,
        scope: payload.google.scope || payload.scope,
        tokenType: payload.google.tokenType || "Bearer",
        sessionExpiresAt: Date.now() + SESSION_TTL_MS
      });

      const accessToken = mintAccessToken(req, {
        sessionId,
        resource: payload.resource,
        scope: payload.scope,
        google: session
      });
      const newRefreshToken = mintRefreshToken(req, {
        sessionId,
        resource: payload.resource,
        scope: payload.scope,
        google: session
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

      const sessionId = payload.sessionId || crypto.randomUUID();
      const existingSession = getSession(sessionId);
      const session = existingSession || saveSession(sessionId, {
        sessionId,
        refreshToken: payload.google.refreshToken,
        accessToken: null,
        expiryDate: 0,
        scope: payload.google.scope || payload.scope,
        tokenType: payload.google.tokenType || "Bearer",
        sessionExpiresAt: Date.now() + SESSION_TTL_MS
      });

      const refreshed = await exchangeGoogleRefreshToken(req, session.refreshToken);
      const grantedScopes = normalizeScopes(refreshed.scope || payload.scope);
      const googleCredentials = saveSession(sessionId, {
        ...session,
        sessionId,
        accessToken: refreshed.access_token,
        refreshToken: session.refreshToken,
        expiryDate: refreshed.expiry_date,
        scope: refreshed.scope || session.scope || payload.scope,
        tokenType: refreshed.token_type || session.tokenType || "Bearer",
        sessionExpiresAt: Date.now() + SESSION_TTL_MS
      });
      const accessToken = mintAccessToken(req, {
        sessionId,
        resource: payload.resource,
        scope: grantedScopes.join(" "),
        google: googleCredentials
      });
      const newRefreshToken = mintRefreshToken(req, {
        sessionId,
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
    res.on("close", () => {
      transport.close().catch(() => {});
      server.close().catch(() => {});
    });

    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (error) {
    const statusCode = error?.statusCode || 500;
    if (!res.headersSent) {
      res.status(statusCode).json({
        error: "mcp_request_failed",
        details: error instanceof Error ? error.message : String(error)
      });
    }
  }
});

export default app;
