import type { Invite, InviteStatus } from "./types";

export async function sha256Base64Url(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  const bytes = new Uint8Array(digest);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export async function storedTokenValue(token: string, hashTokens: boolean): Promise<string> {
  return hashTokens ? sha256Base64Url(token) : token;
}

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
