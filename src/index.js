import { json, logApiError, withSecurityHeaders } from "./worker/core.js";
import { handleApi } from "./worker/router.js";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/api/")) {
      try {
        return await handleApi(request, env, url);
      } catch (error) {
        logApiError(request, url, error);
        return json({ error: "Internal server error." }, 500);
      }
    }

    const response = await env.ASSETS.fetch(request);
    return withSecurityHeaders(response);
  },
};
