import { describe, expect, it, vi } from "vitest";
import {
  createInvite,
  createTestAuth,
  expireInvite,
  findAccounts,
  findInviteRow,
  findUserByEmail,
  insertInviteRow,
  seedAdmin,
  seedUser,
  signInHeaders
} from "./helpers";

async function captureError(fn: () => Promise<unknown>) {
  try {
    await fn();
    return null;
  } catch (e) {
    const err = e as { status?: string; body?: { message?: string; code?: string } };
    return { status: err.status, message: err.body?.message, code: err.body?.code };
  }
}

describe("invite-only mode", () => {
  it("creates a private invite: user pre-created unverified, no credential account", async () => {
    const auth = await createTestAuth();
    const headers = await seedAdmin(auth);
    const res = await auth.api.createInvite({
      body: { type: "private", email: "invitee@test.com", name: "Invitee", role: "user" },
      headers
    });
    expect(res.inviteId).toBeTruthy();

    const user = await findUserByEmail(auth, "invitee@test.com");
    expect(user).toBeTruthy();
    expect(user?.emailVerified).toBe(false);
    const accounts = await findAccounts(auth, user!.id);
    expect(accounts).toHaveLength(0);

    const row = await findInviteRow(auth, res.inviteId);
    expect(row?.preCreatedUserId).toBe(user!.id);
  });

  it("runs on a custom rank system with no admin plugin: top ranks invite, lower ranks cannot", async () => {
    const RANKS = [
      "founder",
      "director",
      "manager",
      "lead", // the four that may invite
      "engineer",
      "contractor",
      "observer"
    ];
    const sent: string[] = [];
    const auth = await createTestAuth({
      withoutAdmin: true,
      auth: {
        user: { additionalFields: { role: { type: "string", required: false } } }
      },
      invite: {
        adminRoles: RANKS.slice(0, 4),
        validRoles: RANKS,
        defaultRole: "observer",
        sendPrivateInvitation: async ({ email }) => {
          sent.push(email);
        }
      }
    });

    await seedUser(auth, {
      email: "manager@test.com",
      password: "password123",
      role: "manager"
    });
    await seedUser(auth, {
      email: "engineer@test.com",
      password: "password123",
      role: "engineer"
    });

    // A top-four rank may invite, and may grant any valid rank.
    const managerHeaders = await signInHeaders(auth, "manager@test.com", "password123");
    const invite = await createInvite(auth, {
      body: { type: "private", email: "newlead@test.com", role: "lead" },
      headers: managerHeaders
    });
    expect(sent).toContain("newlead@test.com");

    // A lower rank is refused by the same gate.
    const engineerHeaders = await signInHeaders(auth, "engineer@test.com", "password123");
    const refused = await captureError(() =>
      auth.api.createInvite({
        body: { type: "private", email: "nope@test.com", role: "engineer" },
        headers: engineerHeaders
      })
    );
    expect(refused?.status).toBe("FORBIDDEN");

    // Unknown ranks are still rejected by validRoles.
    const badRank = await captureError(() =>
      auth.api.createInvite({
        body: { type: "private", email: "bad@test.com", role: "overlord" },
        headers: managerHeaders
      })
    );
    expect(badRank?.status).toBe("UNPROCESSABLE_ENTITY");

    // The granted rank lands on the user created by redemption.
    await auth.api.acceptInvite({
      body: { token: invite.token, password: "password123" }
    });
    const created = await findUserByEmail(auth, "newlead@test.com");
    expect((created as { role?: string })?.role).toBe("lead");
  });

  it("warns at init when the user model has no role field, and stays quiet when it does", async () => {
    const warnings: string[] = [];
    const logger = {
      level: "warn" as const,
      log: (level: string, message: string) => {
        if (level === "warn") warnings.push(message);
      }
    };

    // No admin plugin, no additionalFields: nowhere to store an invited role.
    await createTestAuth({ withoutAdmin: true, auth: { logger } });
    expect(warnings.some((w) => /has no `role` field/.test(w))).toBe(true);

    // A hand-rolled role field satisfies the requirement without the plugin.
    warnings.length = 0;
    await createTestAuth({
      withoutAdmin: true,
      auth: {
        logger,
        user: { additionalFields: { role: { type: "string", required: false } } }
      }
    });
    expect(warnings.some((w) => /has no `role` field/.test(w))).toBe(false);

    // The admin plugin provides it too.
    warnings.length = 0;
    await createTestAuth({ auth: { logger } });
    expect(warnings.some((w) => /has no `role` field/.test(w))).toBe(false);
  });

  it("withholds the private invite link from the creator: only the email carries it", async () => {
    const sent: { url: string; token: string; email: string }[] = [];
    const auth = await createTestAuth({
      invite: {
        sendPrivateInvitation: async ({ email, url, token }) => {
          sent.push({ email, url, token });
        }
      }
    });
    const headers = await seedAdmin(auth);
    const res = await auth.api.createInvite({
      body: { type: "private", email: "secret@test.com", role: "user" },
      headers
    });

    // The creator learns the invite exists, never how to redeem it.
    expect(res.inviteId).toBeTruthy();
    expect(res.expiresAt).toBeTruthy();
    expect((res as Record<string, unknown>).token).toBeUndefined();
    expect((res as Record<string, unknown>).url).toBeUndefined();

    // The mailbox owner still gets a working link.
    expect(sent).toHaveLength(1);
    expect(sent[0]!.email).toBe("secret@test.com");
    expect(sent[0]!.token).toBeTruthy();
    expect(sent[0]!.url).toContain(sent[0]!.token);

    const accepted = await auth.api.acceptInvite({
      body: { token: sent[0]!.token, password: "invitee-password-123" }
    });
    expect(accepted).toBeTruthy();
  });

  it("still returns the link for public invites, whose whole purpose is sharing", async () => {
    const auth = await createTestAuth();
    const headers = await seedAdmin(auth);
    const res = await auth.api.createInvite({
      body: { type: "public", role: "user", maxUses: 5 },
      headers
    });
    expect(res.token).toBeTruthy();
    expect(res.url).toContain(res.token);
  });

  it("hand delivery without email is a single-use public invite, not a leaked private link", async () => {
    const auth = await createTestAuth();
    const headers = await seedAdmin(auth);
    const res = await auth.api.createInvite({
      body: { type: "public", role: "user", maxUses: 1 },
      headers
    });
    // The admin gets a link they may pass on by hand...
    expect(res.token).toBeTruthy();
    expect(res.url).toContain(res.token);

    await auth.api.acceptInvite({
      body: { token: res.token!, password: "password123", email: "handed@test.com" }
    });
    // ...but possession of a shareable link never proves the mailbox, so the
    // account is created unverified, unlike a private invite's recipient.
    const user = await findUserByEmail(auth, "handed@test.com");
    expect(user?.emailVerified).toBe(false);

    // And it is spent after that one use.
    const second = await captureError(() =>
      auth.api.acceptInvite({
        body: { token: res.token!, password: "password123", email: "second@test.com" }
      })
    );
    expect(second?.status).toBe("BAD_REQUEST");
  });

  it("stores the token hashed by default (row != raw token) yet accept still works", async () => {
    const auth = await createTestAuth();
    const headers = await seedAdmin(auth);
    const { token, inviteId } = await createInvite(auth, {
      body: { type: "private", email: "hash@test.com", role: "user" },
      headers
    });
    const row = await findInviteRow(auth, inviteId);
    expect(row?.tokenHash).not.toBe(token);
    const res = await auth.api.acceptInvite({ body: { token, password: "password123" } });
    expect(res.user.email).toBe("hash@test.com");
  });

  it("stores raw token when hashTokens:false", async () => {
    const auth = await createTestAuth({ invite: { hashTokens: false } });
    const headers = await seedAdmin(auth);
    const { token, inviteId } = await createInvite(auth, {
      body: { type: "private", email: "raw@test.com", role: "user" },
      headers
    });
    const row = await findInviteRow(auth, inviteId);
    expect(row?.tokenHash).toBe(token);
  });

  it("rejects non-admin create with FORBIDDEN; honors canManageInvites override", async () => {
    const auth = await createTestAuth();
    await seedAdmin(auth);
    await seedUser(auth, { email: "plainuser@test.com", password: "password123", role: "user" });
    const userHeaders = await signInHeaders(auth, "plainuser@test.com", "password123");
    const err = await captureError(() =>
      createInvite(auth, {
        body: { type: "private", email: "x@test.com", role: "user" },
        headers: userHeaders
      })
    );
    expect(err?.status).toBe("FORBIDDEN");

    const auth2 = await createTestAuth({ invite: { canManageInvites: () => true } });
    await seedUser(auth2, { email: "anyone@test.com", password: "password123", role: "user" });
    const anyoneHeaders = await signInHeaders(auth2, "anyone@test.com", "password123");
    const ok = await createInvite(auth2, {
      body: { type: "private", email: "y@test.com", role: "user" },
      headers: anyoneHeaders
    });
    expect(ok.token).toBeTruthy();
  });

  it("blocks a duplicate pending invite (even past expiry) with CONFLICT", async () => {
    const auth = await createTestAuth();
    const headers = await seedAdmin(auth);
    const { inviteId } = await createInvite(auth, {
      body: { type: "private", email: "dup@test.com", role: "user" },
      headers
    });
    await expireInvite(auth, inviteId);
    const err = await captureError(() =>
      createInvite(auth, {
        body: { type: "private", email: "dup@test.com", role: "user" },
        headers
      })
    );
    expect(err?.status).toBe("CONFLICT");
    expect(err?.message).toContain("Delete the existing invite first");
  });

  it("blocks inviting an existing user email with CONFLICT", async () => {
    const auth = await createTestAuth();
    const headers = await seedAdmin(auth);
    await seedUser(auth, { email: "exists@test.com", role: "user" });
    const err = await captureError(() =>
      createInvite(auth, {
        body: { type: "private", email: "exists@test.com", role: "user" },
        headers
      })
    );
    expect(err?.status).toBe("CONFLICT");
  });

  it("rejects an invalid role with UNPROCESSABLE_ENTITY and writes nothing", async () => {
    const auth = await createTestAuth();
    const headers = await seedAdmin(auth);
    const err = await captureError(() =>
      createInvite(auth, {
        body: { type: "private", email: "badrole@test.com", role: "superadmin" },
        headers
      })
    );
    expect(err?.status).toBe("UNPROCESSABLE_ENTITY");
    expect(await findUserByEmail(auth, "badrole@test.com")).toBeFalsy();
  });

  it("get returns masked email and derived status; expired shows 'expired' and fires onInviteExpired", async () => {
    const onInviteExpired = vi.fn();
    const auth = await createTestAuth({ invite: { onInviteExpired } });
    const headers = await seedAdmin(auth);
    const { token, inviteId } = await createInvite(auth, {
      body: { type: "private", email: "masked@test.com", role: "user" },
      headers
    });
    const got = await auth.api.getInvite({ query: { token } });
    expect(got.email).toBe("m***@test.com");
    expect(got.status).toBe("pending");

    await expireInvite(auth, inviteId);
    const expired = await auth.api.getInvite({ query: { token } });
    expect(expired.status).toBe("expired");
    expect(onInviteExpired).toHaveBeenCalled();
  });

  it("get exposes the full email with exposeEmailOnGet", async () => {
    const auth = await createTestAuth({ invite: { exposeEmailOnGet: true } });
    const headers = await seedAdmin(auth);
    const { token } = await createInvite(auth, {
      body: { type: "private", email: "full@test.com", role: "user" },
      headers
    });
    const got = await auth.api.getInvite({ query: { token } });
    expect(got.email).toBe("full@test.com");
  });

  it("accept happy path: credential account created, verified, name applied, session cookie set", async () => {
    const onInviteAccepted = vi.fn();
    const auth = await createTestAuth({ invite: { onInviteAccepted } });
    const headers = await seedAdmin(auth);
    const { token } = await createInvite(auth, {
      body: { type: "private", email: "happy@test.com", role: "partner" },
      headers
    });
    const res = await auth.api.acceptInvite({
      body: { token, password: "password123", name: "Happy User" },
      returnHeaders: true
    });
    expect(res.headers.get("set-cookie")).toBeTruthy();

    const user = await findUserByEmail(auth, "happy@test.com");
    expect(user?.emailVerified).toBe(true);
    expect(user?.name).toBe("Happy User");
    expect((user as { role?: string })?.role).toBe("partner");
    const accounts = await findAccounts(auth, user!.id);
    expect(accounts.some((a) => a.providerId === "credential")).toBe(true);
    expect(onInviteAccepted).toHaveBeenCalled();

    const signIn = await signInHeaders(auth, "happy@test.com", "password123");
    expect(signIn.get("cookie")).toBeTruthy();
  });

  it("falls back to fallbackRole for a stale role; hard-fails + fires onInvalidRole without one", async () => {
    const onInvalidRole = vi.fn();
    const auth = await createTestAuth({
      invite: { validRoles: ["user"], fallbackRole: "user", onInvalidRole }
    });
    await seedAdmin(auth);
    await insertInviteRow(auth, {
      token: "stale-token-1",
      email: "stale1@test.com",
      role: "ghost"
    });
    const res = await auth.api.acceptInvite({
      body: { token: "stale-token-1", password: "password123", email: "stale1@test.com" }
    });
    expect(res.user.email).toBe("stale1@test.com");

    const auth2 = await createTestAuth({ invite: { validRoles: ["user"], onInvalidRole } });
    await seedAdmin(auth2);
    await insertInviteRow(auth2, {
      token: "stale-token-2",
      email: "stale2@test.com",
      role: "ghost"
    });
    const err = await captureError(() =>
      auth2.api.acceptInvite({
        body: { token: "stale-token-2", password: "password123", email: "stale2@test.com" }
      })
    );
    expect(err?.status).toBe("UNPROCESSABLE_ENTITY");
    expect(onInvalidRole).toHaveBeenCalled();
  });

  it("rejects expired, cancelled, and garbage tokens on accept with BAD_REQUEST", async () => {
    const auth = await createTestAuth();
    const headers = await seedAdmin(auth);
    const { token, inviteId } = await createInvite(auth, {
      body: { type: "private", email: "exp@test.com", role: "user" },
      headers
    });
    await expireInvite(auth, inviteId);
    expect(
      (
        await captureError(() =>
          auth.api.acceptInvite({ body: { token, password: "password123" } })
        )
      )?.status
    ).toBe("BAD_REQUEST");
    expect(
      (
        await captureError(() =>
          auth.api.acceptInvite({ body: { token: "garbage", password: "password123" } })
        )
      )?.status
    ).toBe("BAD_REQUEST");

    const { token: t2, inviteId: id2 } = await createInvite(auth, {
      body: { type: "private", email: "rev@test.com", role: "user" },
      headers
    });
    await auth.api.revokeInvite({ body: { inviteId: id2 }, headers });
    expect(
      (
        await captureError(() =>
          auth.api.acceptInvite({ body: { token: t2, password: "password123" } })
        )
      )?.status
    ).toBe("BAD_REQUEST");
  });

  it("second sequential accept fails; parallel double accept lets exactly one win", async () => {
    const auth = await createTestAuth();
    const headers = await seedAdmin(auth);
    const { token } = await createInvite(auth, {
      body: { type: "private", email: "race@test.com", role: "user" },
      headers
    });
    await auth.api.acceptInvite({ body: { token, password: "password123" } });
    expect(
      (
        await captureError(() =>
          auth.api.acceptInvite({ body: { token, password: "password123" } })
        )
      )?.status
    ).toBe("BAD_REQUEST");

    const { token: t2 } = await createInvite(auth, {
      body: { type: "private", email: "race2@test.com", role: "user" },
      headers
    });
    const results = await Promise.allSettled([
      auth.api.acceptInvite({ body: { token: t2, password: "password123" } }),
      auth.api.acceptInvite({ body: { token: t2, password: "password123" } })
    ]);
    const ok = results.filter((r) => r.status === "fulfilled");
    expect(ok).toHaveLength(1);
  });

  it("writes an inviteUse row, flips status to accepted, increments useCount", async () => {
    const auth = await createTestAuth();
    const headers = await seedAdmin(auth);
    const { token, inviteId } = await createInvite(auth, {
      body: { type: "private", email: "use@test.com", role: "user" },
      headers
    });
    await auth.api.acceptInvite({ body: { token, password: "password123" } });
    const row = await findInviteRow(auth, inviteId);
    expect(row?.status).toBe("accepted");
    expect(row?.useCount).toBe(1);
    const ctx = await auth.$context;
    const uses = await ctx.adapter.findMany({
      model: "inviteUse",
      where: [{ field: "inviteId", value: inviteId }]
    });
    expect(uses).toHaveLength(1);
  });

  it("sign-in before accept fails naturally (no credential account)", async () => {
    const auth = await createTestAuth();
    const headers = await seedAdmin(auth);
    await createInvite(auth, {
      body: { type: "private", email: "presignin@test.com", role: "user" },
      headers
    });
    const err = await captureError(() =>
      auth.api.signInEmail({ body: { email: "presignin@test.com", password: "whatever123" } })
    );
    expect(err?.status).toBeTruthy();
  });

  it("password reset for a pending-invite email is a silent no-op with no oracle", async () => {
    const sendReset = vi.fn();
    const auth = await createTestAuth({
      auth: {
        emailAndPassword: {
          enabled: true,
          disableSignUp: true,
          sendResetPassword: async () => {
            sendReset();
          }
        }
      }
    });
    const headers = await seedAdmin(auth);
    await createInvite(auth, {
      body: { type: "private", email: "reset@test.com", role: "user" },
      headers
    });
    const parse = async (r: unknown) => (r instanceof Response ? await r.clone().json() : r);
    const invited = await parse(
      await auth.api.requestPasswordReset({ body: { email: "reset@test.com" } })
    );
    const unknown = await parse(
      await auth.api.requestPasswordReset({ body: { email: "nobody@test.com" } })
    );
    expect(invited).toEqual(unknown);
    expect(sendReset).not.toHaveBeenCalled();

    await seedUser(auth, { email: "realuser@test.com", password: "password123", role: "user" });
    await auth.api.requestPasswordReset({ body: { email: "realuser@test.com" } });
    expect(sendReset).toHaveBeenCalledTimes(1);
  });

  it("public invite: default unverified, autoVerify option, dup email conflict, cap under parallelism", async () => {
    const auth = await createTestAuth();
    const headers = await seedAdmin(auth);
    const { token } = await createInvite(auth, {
      body: { type: "public", role: "user", maxUses: 2 },
      headers
    });
    await auth.api.acceptInvite({ body: { token, password: "password123", email: "p1@test.com" } });
    const u1 = await findUserByEmail(auth, "p1@test.com");
    expect(u1?.emailVerified).toBe(false);

    const dup = await captureError(() =>
      auth.api.acceptInvite({ body: { token, password: "password123", email: "p1@test.com" } })
    );
    expect(dup?.status).toBe("CONFLICT");

    await auth.api.acceptInvite({ body: { token, password: "password123", email: "p2@test.com" } });
    const over = await captureError(() =>
      auth.api.acceptInvite({ body: { token, password: "password123", email: "p3@test.com" } })
    );
    expect(over?.status).toBe("BAD_REQUEST");

    const authV = await createTestAuth({ invite: { autoVerifyPublicInviteEmail: true } });
    const hV = await seedAdmin(authV);
    const { token: tV } = await createInvite(authV, {
      body: { type: "public", role: "user" },
      headers: hV
    });
    await authV.api.acceptInvite({
      body: { token: tV, password: "password123", email: "verified@test.com" }
    });
    expect((await findUserByEmail(authV, "verified@test.com"))?.emailVerified).toBe(true);
  });

  it("public invite parallel accepts never exceed maxUses", async () => {
    const auth = await createTestAuth();
    const headers = await seedAdmin(auth);
    const { token, inviteId } = await createInvite(auth, {
      body: { type: "public", role: "user", maxUses: 3 },
      headers
    });
    const results = await Promise.allSettled(
      Array.from({ length: 6 }, (_, i) =>
        auth.api.acceptInvite({
          body: { token, password: "password123", email: `par${i}@test.com` }
        })
      )
    );
    const ok = results.filter((r) => r.status === "fulfilled");
    expect(ok).toHaveLength(3);
    const row = await findInviteRow(auth, inviteId);
    expect(row?.useCount).toBe(3);
    expect(row?.status).toBe("accepted");
  });

  it("revoke cancels a pending invite and blocks further accepts; re-revoke fails", async () => {
    const onInviteRevoked = vi.fn();
    const auth = await createTestAuth({ invite: { onInviteRevoked } });
    const headers = await seedAdmin(auth);
    const { token, inviteId } = await createInvite(auth, {
      body: { type: "private", email: "revoke@test.com", role: "user" },
      headers
    });
    await auth.api.revokeInvite({ body: { inviteId }, headers });
    const row = await findInviteRow(auth, inviteId);
    expect(row?.status).toBe("cancelled");
    expect(row?.revokedByUserId).toBeTruthy();
    expect(onInviteRevoked).toHaveBeenCalled();
    expect(
      (
        await captureError(() =>
          auth.api.acceptInvite({ body: { token, password: "password123" } })
        )
      )?.status
    ).toBe("BAD_REQUEST");
    expect(
      (await captureError(() => auth.api.revokeInvite({ body: { inviteId }, headers })))?.status
    ).toBe("BAD_REQUEST");
  });

  it("delete removes a pending invite + inert user; accepted invites are permanent", async () => {
    const auth = await createTestAuth();
    const headers = await seedAdmin(auth);
    const { inviteId } = await createInvite(auth, {
      body: { type: "private", email: "del@test.com", role: "user" },
      headers
    });
    await auth.api.deleteInvite({ body: { inviteId }, headers });
    expect(await findInviteRow(auth, inviteId)).toBeFalsy();
    expect(await findUserByEmail(auth, "del@test.com")).toBeFalsy();
    const reinvite = await createInvite(auth, {
      body: { type: "private", email: "del@test.com", role: "user" },
      headers
    });
    expect(reinvite.token).toBeTruthy();

    const { token, inviteId: acceptedId } = await createInvite(auth, {
      body: { type: "private", email: "perm@test.com", role: "user" },
      headers
    });
    await auth.api.acceptInvite({ body: { token, password: "password123" } });
    expect(
      (await captureError(() => auth.api.deleteInvite({ body: { inviteId: acceptedId }, headers })))
        ?.status
    ).toBe("BAD_REQUEST");
  });

  it("cleanupExpiredInvites removes expired inert invites and leaves the rest", async () => {
    const auth = await createTestAuth();
    const headers = await seedAdmin(auth);
    const { inviteId: expiredId } = await createInvite(auth, {
      body: { type: "private", email: "cleanup1@test.com", role: "user" },
      headers
    });
    const { inviteId: liveId } = await createInvite(auth, {
      body: { type: "private", email: "cleanup2@test.com", role: "user" },
      headers
    });
    await expireInvite(auth, expiredId);
    const result = await auth.api.cleanupExpiredInvites();
    expect(result.deleted).toBe(1);
    expect(await findInviteRow(auth, expiredId)).toBeFalsy();
    expect(await findInviteRow(auth, liveId)).toBeTruthy();
  });

  it("list paginates and filters, including derived expired; non-admin is forbidden", async () => {
    const auth = await createTestAuth();
    const headers = await seedAdmin(auth);
    await createInvite(auth, {
      body: { type: "private", email: "l1@test.com", role: "user" },
      headers
    });
    const { inviteId: expId } = await createInvite(auth, {
      body: { type: "private", email: "l2@test.com", role: "user" },
      headers
    });
    await createInvite(auth, { body: { type: "public", role: "user" }, headers });
    await expireInvite(auth, expId);

    const all = await auth.api.listInvites({ query: {}, headers });
    expect(all.total).toBe(3);
    const publics = await auth.api.listInvites({ query: { type: "public" }, headers });
    expect(publics.invites.every((i) => i.type === "public")).toBe(true);
    const expired = await auth.api.listInvites({ query: { status: "expired" }, headers });
    expect(expired.invites).toHaveLength(1);
    expect(expired.invites[0]?.status).toBe("expired");
    expect(all.invites.every((i) => !("tokenHash" in i))).toBe(true);

    await seedUser(auth, { email: "nonadmin@test.com", password: "password123", role: "user" });
    const nonAdmin = await signInHeaders(auth, "nonadmin@test.com", "password123");
    expect(
      (await captureError(() => auth.api.listInvites({ query: {}, headers: nonAdmin })))?.status
    ).toBe("FORBIDDEN");
  });

  it("calls send functions with the expected args", async () => {
    const sendPrivateInvitation = vi.fn();
    const sendPublicInvitation = vi.fn();
    const auth = await createTestAuth({ invite: { sendPrivateInvitation, sendPublicInvitation } });
    const headers = await seedAdmin(auth);
    await createInvite(auth, {
      body: { type: "private", email: "sent@test.com", name: "Sent", role: "partner" },
      headers
    });
    expect(sendPrivateInvitation).toHaveBeenCalledWith(
      expect.objectContaining({
        email: "sent@test.com",
        role: "partner",
        token: expect.any(String),
        url: expect.any(String)
      }),
      undefined
    );
    await createInvite(auth, { body: { type: "public", role: "user", maxUses: 5 }, headers });
    expect(sendPublicInvitation).toHaveBeenCalledWith(
      expect.objectContaining({ role: "user", maxUses: 5, token: expect.any(String) }),
      undefined
    );
  });

  it("init throws on explicit invite-only with an open signup path; allowOpenSignup downgrades to a warning", async () => {
    await expect(
      createTestAuth({ auth: { emailAndPassword: { enabled: true, disableSignUp: false } } })
    ).rejects.toThrow(/invite-only/);

    const auth = await createTestAuth({
      invite: { allowOpenSignup: true },
      auth: { emailAndPassword: { enabled: true, disableSignUp: false } }
    });
    expect(auth).toBeTruthy();
  });

  it("auto mode detects a closed app as invite-only and a mixed config throws", async () => {
    const closed = await createTestAuth({ invite: { mode: "auto" } });
    const headers = await seedAdmin(closed);
    const res = await createInvite(closed, {
      body: { type: "private", email: "auto@test.com", role: "user" },
      headers
    });
    expect(res.token).toBeTruthy();

    await expect(
      createTestAuth({
        invite: { mode: "auto" },
        auth: {
          emailAndPassword: { enabled: true, disableSignUp: true },
          socialProviders: { google: { clientId: "x", clientSecret: "y" } }
        }
      })
    ).rejects.toThrow(/mixed sign-up/);
  });
});
