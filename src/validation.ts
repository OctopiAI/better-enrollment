/**
 * Input rules shared by the server endpoints (authoritative) and the client
 * plugin (early, no network). Pure functions with no server imports, so the
 * client bundle stays small.
 */

export const ORG_SLUG_MAX_LENGTH = 48;
export const ORG_NAME_MAX_LENGTH = 200;

const SLUG_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const CONTROL_CHARS = /\p{Cc}/u;

/** Trims and lowercases, the form every slug is stored and compared in. */
export function normalizeOrgSlug(slug: string): string {
  return slug.trim().toLowerCase();
}

/** a-z, 0-9 and single inner dashes, 1 to 48 characters, after normalizing. */
export function isValidOrgSlug(slug: string): boolean {
  const s = normalizeOrgSlug(slug);
  return s.length > 0 && s.length <= ORG_SLUG_MAX_LENGTH && SLUG_PATTERN.test(s);
}

/** 1 to 200 characters after trimming, no control characters (line breaks included). */
export function isValidOrgName(name: string): boolean {
  const n = name.trim();
  return n.length > 0 && n.length <= ORG_NAME_MAX_LENGTH && !CONTROL_CHARS.test(n);
}

/** URL-safe slug for an org name; "org" when nothing usable remains. */
export function slugify(name: string): string {
  const slug = name
    .normalize("NFKD")
    .replace(/\p{M}/gu, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, ORG_SLUG_MAX_LENGTH)
    .replace(/-+$/, "");
  return slug || "org";
}

export const VALIDATION_ERRORS = {
  INVALID_ORG_SLUG: {
    code: "INVALID_ORG_SLUG",
    message: "Organization slugs use lowercase letters, numbers and single dashes, up to 48 characters"
  },
  INVALID_ORG_NAME: {
    code: "INVALID_ORG_NAME",
    message: "Organization names are 1 to 200 characters with no line breaks or control characters"
  }
} as const;

export type ValidationFailure = (typeof VALIDATION_ERRORS)[keyof typeof VALIDATION_ERRORS];

function checkOrgFields(name: unknown, slug: unknown): ValidationFailure | null {
  if (typeof name === "string" && name.trim() && !isValidOrgName(name)) {
    return VALIDATION_ERRORS.INVALID_ORG_NAME;
  }
  if (typeof slug === "string" && slug.trim() && !isValidOrgSlug(slug)) {
    return VALIDATION_ERRORS.INVALID_ORG_SLUG;
  }
  return null;
}

/**
 * The checks the client runs before calling an invite endpoint. Only rules
 * that do not depend on server configuration; everything else (and these
 * again) is enforced by the server. Missing fields are left to the server,
 * which knows whether they are required.
 */
export function validateInviteRequest(
  path: string,
  body: Record<string, unknown> | undefined,
  query: Record<string, unknown> | undefined
): ValidationFailure | null {
  switch (path) {
    case "/invite/redeem":
    case "/invite/accept":
    case "/invite/activate":
      return checkOrgFields(body?.organizationName, body?.organizationSlug);
    case "/invite/create": {
      const org = body?.organization as Record<string, unknown> | undefined;
      return org ? checkOrgFields(org.name, org.slug) : null;
    }
    case "/invite/check-slug":
      return checkOrgFields(undefined, query?.slug);
    case "/invite/verify-slug":
      return checkOrgFields(undefined, body?.slug);
    default:
      return null;
  }
}
