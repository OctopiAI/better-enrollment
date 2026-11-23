import type { Invite, InviteStatus } from "./types";

export async function sha256Base64Url(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  const bytes = new Uint8Array(digest);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlEncode(input: string): string {
  let bin = "";
  for (const b of new TextEncoder().encode(input)) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlDecode(input: string): string {
  const bin = atob(input.replace(/-/g, "+").replace(/_/g, "/"));
  return new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
}

/** Opaque keyset cursor over (createdAt desc, id desc). */
export function encodeCursor(row: { createdAt: Date | string; id: string }): string {
  return base64UrlEncode(`${new Date(row.createdAt).toISOString()}|${row.id}`);
}

export function decodeCursor(cursor: string): { createdAt: Date; id: string } | null {
  try {
    const raw = base64UrlDecode(cursor);
    const sep = raw.indexOf("|");
    if (sep <= 0 || sep === raw.length - 1) return null;
    const createdAt = new Date(raw.slice(0, sep));
    if (Number.isNaN(createdAt.getTime())) return null;
    return { createdAt, id: raw.slice(sep + 1) };
  } catch {
    return null;
  }
}

export function compareNewestFirst(
  a: { createdAt: Date | string; id: string },
  b: { createdAt: Date | string; id: string }
): number {
  const diff = new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime();
  if (diff !== 0) return diff;
  return a.id < b.id ? 1 : a.id > b.id ? -1 : 0;
}

export { slugify } from "./validation";

export function maskEmail(email: string): string {
  const at = email.indexOf("@");
  if (at <= 0) return "***";
  const local = email.slice(0, at);
  const domain = email.slice(at);
  const visible = local.length > 1 ? local[0] : "*";
  return `${visible}***${domain}`;
}

export function mergeRoles(existing: string | null | undefined, role: string): string {
  const set = new Set(
    (existing ?? "")
      .split(",")
      .map((r) => r.trim())
      .filter(Boolean)
  );
  set.add(role);
  return [...set].join(",");
}

export function splitRoles(role: string | null | undefined): string[] {
  return (role ?? "")
    .split(",")
    .map((r) => r.trim())
    .filter(Boolean);
}

export function isExpired(invite: Invite, now = new Date()): boolean {
  return (
    invite.status === "pending" && invite.expiresAt != null && new Date(invite.expiresAt) < now
  );
}

export function deriveStatus(invite: Invite, now = new Date()): InviteStatus {
  return isExpired(invite, now) ? "expired" : invite.status;
}

/**
 * Drop-in gate for the org plugin's allowUserToCreateOrganization:
 * `organization({ allowUserToCreateOrganization: roleGate(["admin", "org-creator"]) })`.
 * Admins then control org creation at runtime by granting/removing roles
 * through the admin plugin.
 */
export function roleGate(roles: string[]) {
  return (user: { [key: string]: unknown; role?: unknown }): boolean =>
    splitRoles(typeof user.role === "string" ? user.role : null).some((r) => roles.includes(r));
}

/** Pending seats an invite still holds against an org's seat limit. */
export function reservedSeats(invite: Invite, now = new Date()): number {
  if (invite.status !== "pending" || isExpired(invite, now)) return 0;
  if (invite.maxUses == null) return 0;
  return Math.max(0, invite.maxUses - invite.useCount);
}
