import { isIP } from "node:net";
import { lookup as lookupDns } from "node:dns/promises";

function isPrivateIpv4(address) {
  const [a, b] = address.split(".").map(Number);
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19))
  );
}

function isPrivateIp(address) {
  const family = isIP(address);
  if (family === 4) return isPrivateIpv4(address);
  if (family === 0) return false;

  const normalized = address.toLowerCase();
  if (
    normalized === "::" ||
    normalized === "::1" ||
    normalized.startsWith("fe80:") ||
    normalized.startsWith("fc") ||
    normalized.startsWith("fd")
  ) {
    return true;
  }

  const ipv4Mapped = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  return Boolean(ipv4Mapped && isPrivateIpv4(ipv4Mapped[1]));
}

function isLocalHostname(hostname) {
  const normalized = hostname.toLowerCase().replace(/\.$/, "");
  return (
    normalized === "localhost" ||
    normalized.endsWith(".localhost") ||
    normalized.endsWith(".local") ||
    isPrivateIp(normalized)
  );
}

export async function validateProxyTarget(
  value,
  resolve = (hostname) => lookupDns(hostname, { all: true, verbatim: true }),
) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error("Target URL is invalid");
  }

  if (url.protocol !== "https:") {
    throw new Error("Only HTTPS targets are allowed");
  }

  if (
    url.username ||
    url.password ||
    !url.hostname ||
    isLocalHostname(url.hostname)
  ) {
    throw new Error("Target must not be private or local");
  }

  const addresses = await resolve(url.hostname);
  const address = addresses.find(
    (candidate) => candidate && !isPrivateIp(candidate.address),
  );

  if (
    !address ||
    addresses.some((candidate) => !candidate || isPrivateIp(candidate.address))
  ) {
    throw new Error("Target must not resolve to a private or local address");
  }

  return { url, address };
}
