import { describe, expect, it } from "vitest";
import type { User } from "better-auth";
import {
  createInvite,
  createTestAuth,
  findUserByEmail,
  seedAdmin,
  signInHeaders,
  type TestAuth
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

async function sessionsFor(auth: TestAuth, userId: string) {
  const ctx = await auth.$context;
  return ctx.adapter.findMany<{ id: string; activeOrganizationId?: string | null }>({
    model: "session",
    where: [{ field: "userId", value: userId }]
  });
}

describe("redemption never creates a session", () => {
  it("private accept: no cookie, no token, zero session rows; sign-in works after", async () => {
    const auth = await createTestAuth();
    const headers = await seedAdmin(auth);
    const { token } = await createInvite(auth, {
      body: { type: "private", email: "invitee@test.com" },
      headers
    });
    const res = await auth.api.acceptInvite({
      body: { token, password: "password123", name: "Invitee" },
      returnHeaders: true
    });
    expect(res.headers.get("set-cookie")).toBeNull();
    expect(res.response.action).toBe("ACCEPTED");
    expect("token" in res.response).toBe(false);

    const user = await findUserByEmail(auth, "invitee@test.com");
    expect(await sessionsFor(auth, user!.id)).toHaveLength(0);

    const signedIn = await signInHeaders(auth, "invitee@test.com", "password123");
    expect(signedIn.get("cookie")).toBeTruthy();
    expect(await sessionsFor(auth, user!.id)).toHaveLength(1);
  });

  it("redeem endpoint has the same contract as accept", async () => {
    const auth = await createTestAuth();
    const headers = await seedAdmin(auth);
    const { token } = await createInvite(auth, {
      body: { type: "private", email: "redeem@test.com" },
      headers
    });
    const res = await auth.api.redeemInvite({
      body: { token, password: "password123", name: "Invitee" },
      returnHeaders: true
    });
    expect(res.headers.get("set-cookie")).toBeNull();
    expect(res.response.action).toBe("ACCEPTED");
    expect("token" in res.response).toBe(false);
  });

  it("public accept: no session; sign-in works when verification is not required", async () => {
    const auth = await createTestAuth();
    const headers = await seedAdmin(auth);
    const { token } = await createInvite(auth, {
      body: { type: "public", role: "user", maxUses: 5 },
      headers
    });
    const res = await auth.api.acceptInvite({
      body: { token, password: "password123", email: "open@test.com", name: "Invitee" },
      returnHeaders: true
    });
    expect(res.headers.get("set-cookie")).toBeNull();
    expect("token" in res.response).toBe(false);

    const user = await findUserByEmail(auth, "open@test.com");
    expect(user?.emailVerified).toBe(false);
    expect(await sessionsFor(auth, user!.id)).toHaveLength(0);

    const signedIn = await signInHeaders(auth, "open@test.com", "password123");
    expect(signedIn.get("cookie")).toBeTruthy();
  });

  it("public accept + requireEmailVerification: locked out until verified, then in", async () => {
    const delivered: { token: string }[] = [];
    const auth = await createTestAuth({
      auth: {
        emailVerification: {
          sendVerificationEmail: async ({ token }: { user: User; url: string; token: string }) => {
            delivered.push({ token });
          }
        },
        emailAndPassword: { enabled: true, disableSignUp: true, requireEmailVerification: true }
      }
    });
    const headers = await seedAdmin(auth);
    const { token } = await createInvite(auth, {
      body: { type: "public", role: "user", maxUses: 5 },
      headers
    });
    await auth.api.acceptInvite({
      body: { token, password: "password123", email: "gated@test.com", name: "Invitee" }
    });

    // With no redemption session, an unverified accepter has NO way in.
    const user = await findUserByEmail(auth, "gated@test.com");
    expect(await sessionsFor(auth, user!.id)).toHaveLength(0);
    const blocked = await captureError(() =>
      auth.api.signInEmail({ body: { email: "gated@test.com", password: "password123" } })
    );
    expect(blocked?.status).toBe("FORBIDDEN");

    // The verification email minted at redemption is the way back in.
    expect(delivered).toHaveLength(1);
    await auth.api.verifyEmail({ query: { token: delivered[0]!.token } });
    const signedIn = await signInHeaders(auth, "gated@test.com", "password123");
    expect(signedIn.get("cookie")).toBeTruthy();
  });

  it("public accept + autoVerifyPublicInviteEmail: sign-in works immediately", async () => {
    const auth = await createTestAuth({
      invite: { autoVerifyPublicInviteEmail: true },
      auth: {
        emailAndPassword: { enabled: true, disableSignUp: true, requireEmailVerification: true }
      }
    });
    const headers = await seedAdmin(auth);
    const { token } = await createInvite(auth, {
      body: { type: "public", role: "user", maxUses: 5 },
      headers
    });
    const res = await auth.api.acceptInvite({
      body: { token, password: "password123", email: "auto@test.com", name: "Invitee" },
      returnHeaders: true
    });
    expect(res.headers.get("set-cookie")).toBeNull();

    const signedIn = await signInHeaders(auth, "auto@test.com", "password123");
    expect(signedIn.get("cookie")).toBeTruthy();
  });
});
