import { magicLink } from "better-auth/plugins";
import { describe, expect, it } from "vitest";
import type { BetterAuthOptions } from "better-auth";
import type { BetterEnrollmentOptions } from "../src";
import {
  createTestAuth,
  findAccounts,
  findInviteRow,
  findUserByEmail,
  insertInviteRow,
  seedUser,
  sentInvites,
  type TestAuth
} from "./helpers";
import { sha256Base64Url } from "../src/utils";

type SentMagicLink = { email: string; token: string; url: string };

// Plugins passed as a dynamic array lose endpoint type inference, so tests
// go through an untyped accessor; runtime behavior is what is under test.
// biome-ignore lint/suspicious/noExplicitAny: dynamic endpoint access
const api = (auth: TestAuth) => auth.api as any;

async function errCode(p: Promise<unknown>): Promise<string | undefined> {
  try {
    await p;
    return undefined;
  } catch (e) {
    const err = e as { body?: { code?: string }; code?: string };
    return err.body?.code ?? err.code;
  }
}

/** A passwordless app: magic link only, credential sign-in disabled. */
async function createMagicLinkAuth(config?: {
  invite?: Partial<BetterEnrollmentOptions>;
  auth?: Partial<BetterAuthOptions>;
  magicLinkSignUp?: boolean;
}) {
  const links: SentMagicLink[] = [];
  const auth = await createTestAuth({
    plugins: [
      magicLink({
        disableSignUp: !config?.magicLinkSignUp,
        sendMagicLink: async ({ email, token, url }) => {
          links.push({ email, token, url });
        }
      })
    ],
    invite: config?.invite,
    auth: { emailAndPassword: { enabled: false }, ...config?.auth }
  });
  return { auth, links };
}

/** Creates a private invite headlessly and returns the delivered token. */
async function createSystemPrivateInvite(auth: TestAuth, email: string) {
  const res = await auth.api.createSystemInvite({
    body: { type: "private", email, role: "user" }
  });
  const delivered = sentInvites(auth).at(-1);
  return { inviteId: res.inviteId, token: delivered!.token };
}

async function verifyMagicLink(auth: TestAuth, links: SentMagicLink[], email: string) {
  await api(auth).signInMagicLink({
    body: { email },
    headers: new Headers()
  });
  const link = links.filter((l) => l.email === email).at(-1);
  return api(auth).magicLinkVerify({
    query: { token: link!.token },
    headers: new Headers(),
    returnHeaders: true
  });
}

describe("passwordless redemption (magic link)", () => {
  it("accepts a private invite without a password and signs the accepter in", async () => {
    const { auth } = await createMagicLinkAuth();
    const { inviteId, token } = await createSystemPrivateInvite(auth, "invitee@test.com");

    const res = await api(auth).acceptInvite({
      body: { token, name: "Invitee" },
      returnHeaders: true
    });
    expect(res.response.action).toBe("ACCEPTED");
    expect(res.response.signedIn).toBe(true);
    expect(res.headers.get("set-cookie")).toContain("session_token");

    const user = await findUserByEmail(auth, "invitee@test.com");
    expect(user?.emailVerified).toBe(true);
    expect(user?.name).toBe("Invitee");
    // Passwordless: no credential account is ever created.
    expect(await findAccounts(auth, user!.id)).toHaveLength(0);
    const row = await findInviteRow(auth, inviteId);
    expect(row?.status).toBe("accepted");
  });

  it("lets the accepter sign in with a magic link afterwards", async () => {
    const { auth, links } = await createMagicLinkAuth();
    const { token } = await createSystemPrivateInvite(auth, "invitee@test.com");
    await auth.api.acceptInvite({ body: { token, name: "Invitee" } });

    const verified = await verifyMagicLink(auth, links, "invitee@test.com");
    expect(verified.response.user.email).toBe("invitee@test.com");
    expect(verified.headers.get("set-cookie")).toContain("session_token");
  });

  it("suppresses magic-link delivery for a pre-created shell, with the normal success body", async () => {
    const { auth, links } = await createMagicLinkAuth();
    await createSystemPrivateInvite(auth, "invitee@test.com");
    const res = await api(auth).signInMagicLink({
      body: { email: "invitee@test.com" },
      headers: new Headers()
    });
    // Same body a real send returns: no invite oracle, no dead link sent.
    const body = res instanceof Response ? await res.json() : res;
    expect(body.status).toBe(true);
    expect(links.filter((l) => l.email === "invitee@test.com")).toHaveLength(0);
  });

  it("blocks a magic link already in flight once the invite shell exists", async () => {
    const { auth, links } = await createMagicLinkAuth();
    // The link was requested before the invite existed, so it was sent.
    await api(auth).signInMagicLink({
      body: { email: "invitee@test.com" },
      headers: new Headers()
    });
    const link = links.at(-1)!;
    const { inviteId } = await createSystemPrivateInvite(auth, "invitee@test.com");

    expect(
      await errCode(
        api(auth).magicLinkVerify({ query: { token: link.token }, headers: new Headers() })
      )
    ).toBe("INVITATION_REQUIRED");

    // The shell stays inert and the invite stays redeemable.
    const user = await findUserByEmail(auth, "invitee@test.com");
    expect(user?.emailVerified).toBe(false);
    const row = await findInviteRow(auth, inviteId);
    expect(row?.status).toBe("pending");
  });

  it("blocks the in-flight link over plain HTTP too", async () => {
    const { auth, links } = await createMagicLinkAuth();
    await api(auth).signInMagicLink({
      body: { email: "invitee@test.com" },
      headers: new Headers()
    });
    const link = links.at(-1)!;
    await createSystemPrivateInvite(auth, "invitee@test.com");

    const res = await auth.handler(
      new Request(
        `http://localhost:3000/api/auth/magic-link/verify?token=${encodeURIComponent(link.token)}`
      )
    );
    expect(res.status).toBe(403);
    const user = await findUserByEmail(auth, "invitee@test.com");
    expect(user?.emailVerified).toBe(false);
  });

  it("routes an accept against an established passwordless account to sign-in", async () => {
    const { auth } = await createMagicLinkAuth();
    await insertInviteRow(auth, {
      token: "veteran-token",
      email: "veteran@test.com",
      role: "user"
    });
    // Turn the row into an activation invite for an established magic-link
    // user: verified, zero account rows, no pre-created shell.
    const ctx = await auth.$context;
    const veteran = await findUserByEmail(auth, "veteran@test.com");
    await ctx.adapter.update({
      model: "invite",
      where: [{ field: "tokenHash", value: await sha256Base64Url("veteran-token") }],
      update: { preCreatedUserId: null }
    });
    await ctx.adapter.update({
      model: "user",
      where: [{ field: "id", value: veteran!.id }],
      update: { emailVerified: true, name: "Veteran" }
    });

    const res = await api(auth).acceptInvite({
      body: { token: "veteran-token", name: "Attacker" }
    });
    expect(res.action).toBe("SIGN_IN_REQUIRED");
    // The account was not touched and no session was minted from the token.
    const user = await findUserByEmail(auth, "veteran@test.com");
    expect(user?.name).toBe("Veteran");
    const sessions = await ctx.adapter.findMany({
      model: "session",
      where: [{ field: "userId", value: veteran!.id }]
    });
    expect(sessions).toHaveLength(0);
  });

  it("removes the minted session when a later step fails, and the retry succeeds", async () => {
    let boom = true;
    const { auth } = await createMagicLinkAuth({
      invite: {
        onInviteAccepted: () => {
          if (boom) throw new Error("boom");
        }
      }
    });
    const { inviteId, token } = await createSystemPrivateInvite(auth, "invitee@test.com");
    await expect(api(auth).acceptInvite({ body: { token, name: "Invitee" } })).rejects.toThrow();

    const row = await findInviteRow(auth, inviteId);
    expect(row?.status).toBe("pending");
    const user = await findUserByEmail(auth, "invitee@test.com");
    const ctx = await auth.$context;
    const sessions = await ctx.adapter.findMany({
      model: "session",
      where: [{ field: "userId", value: user!.id }]
    });
    expect(sessions).toHaveLength(0);

    boom = false;
    const res = await api(auth).acceptInvite({ body: { token, name: "Invitee" } });
    expect(res.signedIn).toBe(true);
  });

  it("does not block magic-link sign-in for unrelated or activation users", async () => {
    const { auth, links } = await createMagicLinkAuth();
    await seedUser(auth, { email: "existing@test.com", emailVerified: true });
    const verified = await verifyMagicLink(auth, links, "existing@test.com");
    expect(verified.response.user.email).toBe("existing@test.com");
  });

  it("accepts a public invite passwordless without signing in; first magic link verifies", async () => {
    const { auth, links } = await createMagicLinkAuth();
    const created = await auth.api.createSystemInvite({
      body: { type: "public", role: "user", maxUses: 5 }
    });
    const res = await api(auth).acceptInvite({
      body: { token: created.token!, name: "Pub", email: "pub@test.com" }
    });
    expect(res.action).toBe("ACCEPTED");
    expect(res.signedIn).toBe(false);
    let user = await findUserByEmail(auth, "pub@test.com");
    // A public link proves nothing about the mailbox.
    expect(user?.emailVerified).toBe(false);
    expect(await findAccounts(auth, user!.id)).toHaveLength(0);

    const verified = await verifyMagicLink(auth, links, "pub@test.com");
    expect(verified.headers.get("set-cookie")).toContain("session_token");
    user = await findUserByEmail(auth, "pub@test.com");
    expect(user?.emailVerified).toBe(true);
  });

  it("rejects a password when the app has no credential sign-in", async () => {
    const { auth } = await createMagicLinkAuth();
    const { token } = await createSystemPrivateInvite(auth, "invitee@test.com");
    expect(
      await errCode(
        auth.api.acceptInvite({
          body: { token, name: "Invitee", password: "some-password-123" }
        })
      )
    ).toBe("PASSWORD_NOT_AVAILABLE");
  });

  it("get omits password from requiredFields and flags passwordless", async () => {
    const { auth } = await createMagicLinkAuth();
    const { token } = await createSystemPrivateInvite(auth, "invitee@test.com");
    const info = await auth.api.getInvite({ query: { token } });
    expect(info.passwordless).toBe(true);
    expect(info.nextAction).toBe("SIGN_UP");
    expect(info.requiredFields).toContain("name");
    expect(info.requiredFields).not.toContain("password");
  });

  it("mixed app (credential + magic link) keeps the password flow", async () => {
    const links: SentMagicLink[] = [];
    const auth = await createTestAuth({
      plugins: [
        magicLink({
          disableSignUp: true,
          sendMagicLink: async ({ email, token, url }) => {
            links.push({ email, token, url });
          }
        })
      ]
    });
    const { token } = await createSystemPrivateInvite(auth, "invitee@test.com");
    const info = await auth.api.getInvite({ query: { token } });
    expect(info.passwordless).toBe(false);
    expect(info.requiredFields).toContain("password");
    expect(await errCode(auth.api.acceptInvite({ body: { token, name: "Invitee" } }))).toBe(
      "PASSWORD_REQUIRED"
    );
    const res = await api(auth).acceptInvite({
      body: { token, name: "Invitee", password: "strong-pass-123" }
    });
    expect(res.signedIn).toBe(false);
    const user = await findUserByEmail(auth, "invitee@test.com");
    expect(await findAccounts(auth, user!.id)).toHaveLength(1);
  });

  it("explicit passwordless: true overrides auto detection", async () => {
    const auth = await createTestAuth({
      invite: { passwordless: true }
    });
    const { token } = await createSystemPrivateInvite(auth, "invitee@test.com");
    const res = await api(auth).acceptInvite({ body: { token, name: "Invitee" } });
    expect(res.action).toBe("ACCEPTED");
    expect(res.signedIn).toBe(true);
  });
});

describe("magic-link mode detection", () => {
  it("auto mode sees an open magic link and picks open", async () => {
    const { auth } = await createMagicLinkAuth({
      invite: { mode: "auto" },
      magicLinkSignUp: true
    });
    const created = await auth.api.createSystemInvite({
      body: { type: "public", role: "user", maxUses: 1 }
    });
    const info = await auth.api.getInvite({ query: { token: created.token! } });
    // Open mode: an unauthenticated holder is sent to sign in, not up.
    expect(info.nextAction).toBe("SIGN_IN");
  });

  it("invite-only with an open magic link throws at init", async () => {
    await expect(createMagicLinkAuth({ magicLinkSignUp: true })).rejects.toThrow(/magic-link/);
  });

  it("open magic link in open mode activates invites for magic-link users", async () => {
    const { auth, links } = await createMagicLinkAuth({
      invite: { mode: "open" },
      magicLinkSignUp: true
    });
    const created = await auth.api.createSystemInvite({
      body: { type: "public", role: "partner", maxUses: 1 }
    });
    const verified = await verifyMagicLink(auth, links, "wanderer@test.com");
    const cookie = verified.headers.get("set-cookie")!;
    const headers = new Headers({
      cookie: cookie
        .split(/,(?=[^ ;]+?=)/)
        .map((c: string) => c.split(";")[0]?.trim())
        .filter(Boolean)
        .join("; ")
    });
    const res = await auth.api.activateInvite({
      body: { token: created.token! },
      headers
    });
    expect(res.action).toBe("ACCEPTED");
    const user = (await findUserByEmail(auth, "wanderer@test.com")) as { role?: string } | null;
    expect(user?.role).toContain("partner");
  });
});
