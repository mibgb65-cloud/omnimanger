import { json } from "./core.js";

const MIN_SECRET_LENGTH = 32;

function validateApiEnvironment(env) {
  if (!isVaultBinding(env.VAULT)) {
    return configurationError("KV binding VAULT is not configured.");
  }

  const sessionSecret = String(env.SESSION_SECRET || "");
  if (!sessionSecret) {
    return configurationError("SESSION_SECRET is not configured.");
  }

  if (sessionSecret.length < MIN_SECRET_LENGTH) {
    return configurationError("SESSION_SECRET must be at least 32 characters.");
  }

  const authPepper = String(env.AUTH_PEPPER || "");
  if (authPepper && authPepper.length < MIN_SECRET_LENGTH) {
    return configurationError("AUTH_PEPPER must be at least 32 characters when configured.");
  }

  return null;
}

function isVaultBinding(value) {
  return Boolean(
    value &&
      typeof value.get === "function" &&
      typeof value.put === "function" &&
      typeof value.delete === "function" &&
      typeof value.getWithMetadata === "function",
  );
}

function configurationError(message) {
  return json({ error: message }, 500);
}

export { validateApiEnvironment };
