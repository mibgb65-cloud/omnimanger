async function apiGet(url, fallback = "请求失败。") {
  return apiRequest(url, { method: "GET" }, fallback);
}

async function apiPost(url, body = null, fallback = "请求失败。") {
  return apiRequest(url, { method: "POST", body }, fallback);
}

async function apiPut(url, body = null, fallback = "请求失败。") {
  return apiRequest(url, { method: "PUT", body }, fallback);
}

async function postJson(url, body) {
  return apiPost(url, body);
}

async function apiRequest(url, options = {}, fallback = "请求失败。") {
  const init = {
    method: options.method || "GET",
    credentials: "same-origin",
    headers: {
      ...(options.headers || {}),
    },
  };

  if (options.body !== null && options.body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(options.body);
  }

  const response = await fetch(url, init);
  const data = await readJsonResponse(response);
  if (!response.ok) {
    const error = new Error(formatApiErrorMessage(data.error, fallback));
    error.status = response.status;
    error.data = data;
    throw error;
  }
  return data;
}

async function readJsonResponse(response) {
  try {
    return await response.json();
  } catch {
    return { error: "远端响应不是 JSON。" };
  }
}

function formatApiErrorMessage(message, fallback = "请求失败。") {
  const normalized = String(message || "").trim();
  const messages = {
    "Account already exists.": "该邮箱已注册，请直接登录。",
    "AUTH_PEPPER must be at least 32 characters when configured.": "服务端 AUTH_PEPPER 至少需要 32 个字符。",
    "Auth secret is invalid.": "登录凭据无效，请重新输入密码。",
    "Body must be JSON.": "请求内容格式无效。",
    "Email is invalid.": "邮箱格式不正确。",
    "Email or password is invalid.": "邮箱或密码不正确。",
    "Forbidden.": "当前账号没有权限执行此操作。",
    "KV binding VAULT is not configured.": "服务端 VAULT KV 绑定未配置。",
    "Payload is too large.": "请求内容过大。",
    "Registration is closed.": "注册已关闭，请使用管理员邀请链接。",
    "SESSION_SECRET is not configured.": "服务端 SESSION_SECRET 未配置。",
    "SESSION_SECRET must be at least 32 characters.": "服务端 SESSION_SECRET 至少需要 32 个字符。",
    "Stored vault data is invalid.": "远端保险箱密文格式无效。",
    "Too many requests. Try again later.": "请求过于频繁，请稍后再试。",
    "Unauthorized.": "登录状态已失效，请重新登录。",
    "Vault has changed on another device.": "保险箱已在另一台设备更新，请先拉取远端版本。",
    "远端响应不是 JSON。": "远端响应不是 JSON。",
  };
  return messages[normalized] || normalized || fallback;
}
