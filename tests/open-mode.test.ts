import { describe, expect, it, vi } from "vitest";
import type { BetterEnrollmentOptions } from "../src";
import {
  createInvite,
  createTestAuth,
  findUserByEmail,
  seedUser,
  signInHeaders,
  type TestAuth
} from "./helpers";

async function createOpenAuth(invite?: Partial<BetterEnrollmentOptions>) {
  return createTestAuth({
    invite: { mode: "open", ...invite },
    auth: { emailAndPassword: { enabled: true } }
  });
}

async function adminHeaders(auth: TestAuth) {
  await seedUser(auth, {
    email: "admin@test.com",
    password: "password123",
    role: "admin"
  });
  return signInHeaders(auth, "admin@test.com", "password123");
}

async function captureError(fn: () => Promise<unknown>) {
  try {
    await fn();
    return null;
  } catch (e) {
    const err = e as { status?: string; body?: { message?: string } };
    return { status: err.status, message: err.body?.message };
  }
}

async function roleOf(auth: TestAuth, email: string) {
  const user = await findUserByEmail(auth, email);
  return (user as { role?: string } | null)?.role ?? null;
}

describe("open mode", () => {
  it("does not pre-create a user for a private invite", async () => {
    const auth = await createOpenAuth();
    const headers = await adminHeaders(auth);
    await createInvite(auth, {
      body: { type: "private", email: "nopre@test.com", role: "partner" },
      headers
    });
    expect(await findUserByEmail(auth, "nopre@test.com")).toBeFalsy();
  });

  it("returns SIGN_IN_REQUIRED with a callbackURL carrying the token when unauthenticated", async () => {
    const auth = await createOpenAuth();
    const headers = await adminHeaders(auth);
    const { token } = await createInvite(auth, {
      body: { type: "private", email: "signin@test.com", role: "partner" },
      headers
    });
    const res = await auth.api.activateInvite({ body: { token } });
    expect(res.action).toBe("SIGN_IN_REQUIRED");
    expect((res as { callbackURL?: string }).callbackURL).toContain(token);
  });

  it("merges the invited role for a signed-in verified matching email (no downgrade)", async () => {
    const auth = await createOpenAuth();
    const headers = await adminHeaders(auth);
    const { token } = await createInvite(auth, {
      body: { type: "private", email: "merge@test.com", role: "partner" },
      headers
    });
    await seedUser(auth, {
      email: "merge@test.com",
      password: "password123",
      role: "admin",
      emailVerified: true
    });
    const userHeaders = await signInHeaders(auth, "merge@test.com", "password123");
    const res = await auth.api.activateInvite({ body: { token }, headers: userHeaders });
    expect(res.action).toBe("ACCEPTED");
    const role = await roleOf(auth, "merge@test.com");
    expect(role?.split(",").sort()).toEqual(["admin", "partner"]);
  });

  it("rejects a mismatched email and an unverified matching email with FORBIDDEN", async () => {
    const auth = await createOpenAuth();
    const headers = await adminHeaders(auth);
    const { token } = await createInvite(auth, {
      body: { type: "private", email: "target@test.com", role: "partner" },
      headers
    });

    await seedUser(auth, {
      email: "other@test.com",
      password: "password123",
      role: "user",
      emailVerified: true
    });
    const otherHeaders = await signInHeaders(auth, "other@test.com", "password123");
    expect(
      (
        await captureError(() =>
          auth.api.activateInvite({ body: { token }, headers: otherHeaders })
        )
      )?.status
    ).toBe("FORBIDDEN");

    await seedUser(auth, {
      email: "target@test.com",
      password: "password123",
      role: "user",
      emailVerified: false
    });
    const unverified = await signInHeaders(auth, "target@test.com", "password123");
    expect(
      (await captureError(() => auth.api.activateInvite({ body: { token }, headers: unverified })))
        ?.status
    ).toBe("FORBIDDEN");
  });

  it("public invite: any verified session activates with no email check; cap enforced; revoked mid-flow blocked", async () => {
    const auth = await createOpenAuth();
    const headers = await adminHeaders(auth);
    const { token } = await createInvite(auth, {
      body: { type: "public", role: "partner", maxUses: 1 },
      headers
    });
    await seedUser(auth, {
      email: "pub1@test.com",
      password: "password123",
      role: "user",
      emailVerified: true
    });
    const h1 = await signInHeaders(auth, "pub1@test.com", "password123");
    const res = await auth.api.activateInvite({ body: { token }, headers: h1 });
    expect(res.action).toBe("ACCEPTED");
    expect((await roleOf(auth, "pub1@test.com"))?.split(",").sort()).toEqual(["partner", "user"]);

    await seedUser(auth, {
      email: "pub2@test.com",
      password: "password123",
      role: "user",
      emailVerified: true
    });
    const h2 = await signInHeaders(auth, "pub2@test.com", "password123");
    expect(
      (await captureError(() => auth.api.activateInvite({ body: { token }, headers: h2 })))?.status
    ).toBe("BAD_REQUEST");

    const { token: rt, inviteId: rid } = await createInvite(auth, {
      body: { type: "public", role: "partner" },
      headers
    });
    await auth.api.revokeInvite({ body: { inviteId: rid }, headers });
    expect(
      (await captureError(() => auth.api.activateInvite({ body: { token: rt }, headers: h2 })))
        ?.status
    ).toBe("BAD_REQUEST");
  });

  it("rejects an expired token both before and after sign-in", async () => {
    const auth = await createOpenAuth();
    const headers = await adminHeaders(auth);
    const { token, inviteId } = await createInvite(auth, {
      body: { type: "private", email: "expopen@test.com", role: "partner" },
      headers
    });
    const ctx = await auth.$context;
    await ctx.adapter.update({
      model: "invite",
      where: [{ field: "id", value: inviteId }],
      update: { expiresAt: new Date(Date.now() - 60_000) }
    });
    expect((await captureError(() => auth.api.activateInvite({ body: { token } })))?.status).toBe(
      "BAD_REQUEST"
    );
    await seedUser(auth, {
      email: "expopen@test.com",
      password: "password123",
      role: "user",
      emailVerified: true
    });
    const h = await signInHeaders(auth, "expopen@test.com", "password123");
    expect(
      (await captureError(() => auth.api.activateInvite({ body: { token }, headers: h })))?.status
    ).toBe("BAD_REQUEST");
  });

  it("fires onInviteCreated and onInviteAccepted", async () => {
    const onInviteCreated = vi.fn();
    const onInviteAccepted = vi.fn();
    const auth = await createOpenAuth({ onInviteCreated, onInviteAccepted });
    const headers = await adminHeaders(auth);
    const { token } = await createInvite(auth, {
      body: { type: "private", email: "hooks@test.com", role: "partner" },
      headers
    });
    expect(onInviteCreated).toHaveBeenCalled();
    await seedUser(auth, {
      email: "hooks@test.com",
      password: "password123",
      role: "user",
      emailVerified: true
    });
    const h = await signInHeaders(auth, "hooks@test.com", "password123");
    await auth.api.activateInvite({ body: { token }, headers: h });
    expect(onInviteAccepted).toHaveBeenCalled();
  });

  it("accept is unavailable in open mode", async () => {
    const auth = await createOpenAuth();
    const headers = await adminHeaders(auth);
    const { token } = await createInvite(auth, {
      body: { type: "private", email: "wrongep@test.com", role: "partner" },
      headers
    });
    expect(
      (
        await captureError(() =>
          auth.api.acceptInvite({ body: { token, password: "password123" } })
        )
      )?.status
    ).toBe("BAD_REQUEST");
  });

  it("re-activation by the same user is idempotent", async () => {
    const auth = await createOpenAuth();
    const headers = await adminHeaders(auth);
    const { token, inviteId } = await createInvite(auth, {
      body: { type: "public", role: "partner", maxUses: 5 },
      headers
    });
    await seedUser(auth, {
      email: "idem@test.com",
      password: "password123",
      role: "user",
      emailVerified: true
    });
    const h = await signInHeaders(auth, "idem@test.com", "password123");
    await auth.api.activateInvite({ body: { token }, headers: h });
    await auth.api.activateInvite({ body: { token }, headers: h });
    const ctx = await auth.$context;
    const row = await ctx.adapter.findOne<{ useCount: number }>({
      model: "invite",
      where: [{ field: "id", value: inviteId }]
    });
    expect(row?.useCount).toBe(1);
  });

  it("get works identically in open mode", async () => {
    const auth = await createOpenAuth();
    const headers = await adminHeaders(auth);
    const { token } = await createInvite(auth, {
      body: { type: "private", email: "getopen@test.com", role: "partner" },
      headers
    });
    const got = await auth.api.getInvite({ query: { token } });
    expect(got.role).toBe("partner");
    expect(got.email).toBe("g***@test.com");
  });
});
