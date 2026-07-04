import { RATE_LIMITS, json, publicUser, withSecurityHeaders } from "./core.js";
import {
  createInvite,
  getAdminSettings,
  listAuditEvents,
  listInvites,
  putAdminSettings,
  revokeInvite,
} from "./admin.js";
import {
  changePassword,
  loginUser,
  logoutAllSessions,
  logoutUser,
  registerUser,
  verifyCurrentPassword,
} from "./auth.js";
import { enforceRateLimit } from "./rate-limit.js";
import { validateApiEnvironment } from "./env.js";
import { getSessionUser, requireAdminUser, requireSessionUser } from "./session.js";
import { getVault, putVault } from "./vault.js";

const API_ROUTES = [
  route("POST", "/api/auth/register", ({ request, env, url }) => registerUser(request, env, url)),
  route("POST", "/api/auth/login", ({ request, env, url }) => loginUser(request, env, url)),
  route("POST", "/api/auth/logout", ({ url }) => logoutUser(url)),
  route("POST", "/api/auth/logout-all", ({ env, user, url }) => logoutAllSessions(env, user, url), {
    auth: "user",
    rateLimit: rateLimit("session-revoke", RATE_LIMITS.sessionRevoke),
  }),
  route("POST", "/api/auth/change-password", ({ request, env, user }) => changePassword(request, env, user), {
    auth: "user",
    rateLimit: rateLimit("password-change", RATE_LIMITS.passwordChange),
  }),
  route("POST", "/api/auth/verify-password", ({ request, env, user }) => verifyCurrentPassword(request, env, user), {
    auth: "user",
    rateLimit: rateLimit("password-verify", RATE_LIMITS.passwordVerify),
  }),
  route("GET", "/api/auth/me", async ({ request, env }) => {
    const user = await getSessionUser(request, env);
    return json({ user: user ? publicUser(user, env) : null });
  }),
  route("GET", "/api/admin/settings", ({ env }) => getAdminSettings(env), { auth: "admin" }),
  route("PUT", "/api/admin/settings", ({ request, env }) => putAdminSettings(request, env), {
    auth: "admin",
    rateLimit: rateLimit("admin-settings", RATE_LIMITS.adminSettings),
  }),
  route("GET", "/api/admin/invites", ({ env }) => listInvites(env), { auth: "admin" }),
  route("POST", "/api/admin/invites", ({ env, user }) => createInvite(env, user), {
    auth: "admin",
    rateLimit: rateLimit("admin-settings", RATE_LIMITS.adminSettings),
  }),
  route("POST", "/api/admin/invites/revoke", ({ request, env, user }) => revokeInvite(request, env, user), {
    auth: "admin",
    rateLimit: rateLimit("admin-settings", RATE_LIMITS.adminSettings),
  }),
  route("GET", "/api/admin/audit", ({ env }) => listAuditEvents(env), { auth: "admin" }),
  route("GET", "/api/vault", ({ env, user }) => getVault(env, user), {
    auth: "user",
    rateLimit: rateLimit("vault-read", RATE_LIMITS.vaultRead),
  }),
  route("PUT", "/api/vault", ({ request, env, user }) => putVault(request, env, user), {
    auth: "user",
    rateLimit: rateLimit("vault-write", RATE_LIMITS.vaultWrite),
  }),
];

async function handleApi(request, env, url) {
  if (request.method === "OPTIONS") {
    return optionsResponse();
  }

  const envError = validateApiEnvironment(env);
  if (envError) return envError;

  const matchedRoute = API_ROUTES.find((item) => item.method === request.method && item.path === url.pathname);
  if (!matchedRoute) return json({ error: "Not found." }, 404);

  const user = await resolveRouteUser(matchedRoute, request, env);
  if (user instanceof Response) return user;

  const limited = await enforceRouteRateLimit(matchedRoute, env, user);
  if (limited) return limited;

  return matchedRoute.handle({ request, env, url, user });
}

function route(method, path, handle, options = {}) {
  return { method, path, handle, auth: options.auth || "none", rateLimit: options.rateLimit || null };
}

function rateLimit(scope, config) {
  return { scope, limit: config.limit, windowSeconds: config.windowSeconds };
}

async function resolveRouteUser(routeConfig, request, env) {
  if (routeConfig.auth === "admin") return requireAdminUser(request, env);
  if (routeConfig.auth === "user") return requireSessionUser(request, env);
  return null;
}

async function enforceRouteRateLimit(routeConfig, env, user) {
  if (!routeConfig.rateLimit) return null;
  return enforceRateLimit(
    env,
    routeConfig.rateLimit.scope,
    user.id,
    routeConfig.rateLimit.limit,
    routeConfig.rateLimit.windowSeconds,
  );
}

function optionsResponse() {
  const response = new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Headers": "content-type",
      "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS",
    },
  });
  return withSecurityHeaders(response);
}

export { handleApi };
