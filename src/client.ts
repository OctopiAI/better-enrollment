import type { BetterAuthClientPlugin } from "better-auth";
import type { BetterFetchPlugin } from "better-auth/client";
import type { betterEnrollment } from "./index";
import { validateInviteRequest } from "./validation";

export {
  isValidOrgName,
  isValidOrgSlug,
  normalizeOrgSlug,
  ORG_NAME_MAX_LENGTH,
  ORG_SLUG_MAX_LENGTH,
  slugify,
  VALIDATION_ERRORS
} from "./validation";

function pathOf(url: string): string {
  try {
    return new URL(url, "http://localhost").pathname;
  } catch {
    return url;
  }
}

/**
 * Checks the rules the server would reject first and answers locally, with
 * the server's own 422 body, so a malformed request costs no round trip.
 * The server enforces the same rules regardless.
 */
const validateBeforeSend: BetterFetchPlugin = {
  id: "better-enrollment-validate",
  name: "better-enrollment-validate",
  init: async (url, options) => {
    const path = pathOf(url);
    const at = path.lastIndexOf("/invite/");
    if (at === -1) return { url, options };
    const failure = validateInviteRequest(
      path.slice(at),
      options?.body as Record<string, unknown> | undefined,
      options?.query as Record<string, unknown> | undefined
    );
    if (!failure) return { url, options };
    const reply = async () =>
      new Response(JSON.stringify(failure), {
        status: 422,
        statusText: "Unprocessable Entity",
        headers: { "content-type": "application/json" }
      });
    // better-fetch < 1.3.2 hands each plugin the original per-call options, so set it there.
    const opts = options ?? {};
    opts.customFetchImpl = reply;
    return { url, options: opts };
  }
};

export const betterEnrollmentClient = () => {
  return {
    id: "better-enrollment",
    $InferServerPlugin: {} as ReturnType<typeof betterEnrollment>,
    pathMethods: {
      "/invite/get": "GET",
      "/invite/check-slug": "GET",
      "/invite/list": "GET",
      "/invite/uses": "GET",
      "/invite/org/usage": "GET"
    },
    fetchPlugins: [validateBeforeSend]
  } satisfies BetterAuthClientPlugin;
};
