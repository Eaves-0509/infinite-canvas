import { createServer } from "node:http";
import { request as httpsRequest } from "node:https";

import { validateProxyTarget } from "./security.mjs";

const MAX_BODY_BYTES = Number(
  process.env.PROXY_MAX_BODY_BYTES || 25 * 1024 * 1024,
);
const REQUEST_TIMEOUT_MS = Number(process.env.PROXY_TIMEOUT_MS || 300_000);
const RATE_LIMIT = Number(process.env.PROXY_RATE_LIMIT || 60);
const RATE_WINDOW_MS = 60_000;

const allowedMethods = new Set(["GET", "POST", "PUT", "PATCH", "DELETE"]);

const hopByHopHeaders = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

const clients = new Map();

function sendJson(response, status, payload) {
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  response.end(JSON.stringify(payload));
}

function clientKey(request) {
  const forwarded = request.headers["x-forwarded-for"];

  // Nginx 会把真实访客 IP 加在最后；使用最后一个值，防止用户伪造 IP 绕过限流。
  return (
    typeof forwarded === "string"
      ? forwarded.split(",").at(-1)
      : request.socket.remoteAddress || "unknown"
  ).trim();
}

function acquireClient(request) {
  const key = clientKey(request);
  const now = Date.now();
  const current = clients.get(key);

  const record =
    !current || now - current.windowStart >= RATE_WINDOW_MS
      ? { windowStart: now, count: 0, active: 0 }
      : current;

  if (record.count >= RATE_LIMIT || record.active >= 4) return null;

  record.count += 1;
  record.active += 1;
  clients.set(key, record);

  return () => {
    record.active = Math.max(0, record.active - 1);
  };
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;

    request.on("data", (chunk) => {
      size += chunk.length;

      if (size > MAX_BODY_BYTES) {
        reject(
          Object.assign(new Error("Request body is too large"), {
            status: 413,
          }),
        );
        request.destroy();
        return;
      }

      chunks.push(chunk);
    });

    request.on("end", () => resolve(Buffer.concat(chunks)));
    request.on("error", reject);
  });
}

function forwardHeaders(request, target, body) {
  const headers = {};

  for (const [name, value] of Object.entries(request.headers)) {
    const lowerName = name.toLowerCase();

    if (
      value === undefined ||
      hopByHopHeaders.has(lowerName) ||
      lowerName === "host" ||
      lowerName === "content-length" ||
      lowerName === "cookie" ||
      lowerName === "x-forwarded-for" ||
      lowerName === "x-forwarded-host" ||
      lowerName === "x-forwarded-proto"
    ) {
      continue;
    }

    headers[lowerName] = Array.isArray(value) ? value.join(", ") : value;
  }

  headers.host = target.host;

  if (body.length) {
    headers["content-length"] = String(body.length);
  }

  return headers;
}

function responseHeaders(headers) {
  const result = {};

  for (const [name, value] of Object.entries(headers)) {
    if (
      !hopByHopHeaders.has(name.toLowerCase()) &&
      name.toLowerCase() !== "set-cookie"
    ) {
      result[name] = value;
    }
  }

  return result;
}

async function handleProxy(request, response) {
  const parsed = new URL(request.url || "/", "http://proxy.local");

  if (parsed.pathname !== "/proxy") {
    sendJson(response, 404, { error: "Not found" });
    return;
  }

  if (request.method === "OPTIONS") {
    response.writeHead(204, { "Cache-Control": "no-store" });
    response.end();
    return;
  }

  if (!allowedMethods.has(request.method || "")) {
    sendJson(response, 405, { error: "Method not allowed" });
    return;
  }

  const release = acquireClient(request);

  if (!release) {
    sendJson(response, 429, { error: "Too many proxy requests" });
    return;
  }

  let released = false;

  const finish = () => {
    if (!released) {
      released = true;
      release();
    }
  };

  response.once("close", finish);
  response.once("finish", finish);

  try {
    const rawUrl = parsed.searchParams.get("url");

    if (!rawUrl) {
      throw Object.assign(new Error("Missing target URL"), { status: 400 });
    }

    const { url: target, address } = await validateProxyTarget(rawUrl);
    const body = await readBody(request);

    const upstream = httpsRequest(
      {
        protocol: "https:",
        hostname: address.address,
        family: address.family,
        port: target.port || 443,
        servername: target.hostname,
        method: request.method,
        path: `${target.pathname}${target.search}`,
        headers: forwardHeaders(request, target, body),
        timeout: REQUEST_TIMEOUT_MS,
      },
      (upstreamResponse) => {
        if (
          upstreamResponse.statusCode &&
          upstreamResponse.statusCode >= 300 &&
          upstreamResponse.statusCode < 400
        ) {
          upstreamResponse.resume();
          sendJson(response, 502, {
            error: "Upstream redirect is not allowed",
          });
          return;
        }

        response.writeHead(
          upstreamResponse.statusCode || 502,
          responseHeaders(upstreamResponse.headers),
        );

        upstreamResponse.pipe(response);
      },
    );

    upstream.on("timeout", () => {
      upstream.destroy(new Error("Upstream request timed out"));
    });

    upstream.on("error", (error) => {
      if (!response.headersSent) {
        sendJson(response, 502, {
          error: error.message || "Upstream request failed",
        });
      } else {
        response.destroy(error);
      }
    });

    if (body.length) {
      upstream.write(body);
    }

    upstream.end();
  } catch (error) {
    if (!response.headersSent) {
      sendJson(response, error?.status || 400, {
        error: error instanceof Error ? error.message : "Invalid proxy request",
      });
    }
  }
}

export function createProxyServer() {
  return createServer((request, response) => {
    void handleProxy(request, response);
  });
}

if (
  process.argv[1] &&
  new URL(`file://${process.argv[1]}`).href === import.meta.url
) {
  const port = Number(process.env.PORT || 4000);

  createProxyServer().listen(port, "0.0.0.0", () => {
    console.log(`AI proxy listening on ${port}`);
  });
}
