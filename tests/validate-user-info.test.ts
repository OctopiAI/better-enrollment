import Database from "better-sqlite3";
import { describe, expect, it } from "vitest";
import {
  createInvite,
  createTestAuth,
  findInviteRow,
  findUserByEmail,
  seedAdmin,
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

type Seen = { email?: unknown; method?: string; action?: string };

// validateUserInfo refuses users created outside an endpoint, so the admin is
// seeded through a twin instance on the same database without the gate.
async function gatedAuth(): Promise<{ auth: TestAuth; headers: Headers; seen: Seen[] }> {
  const database = new Database(":memory:");
  const headers = await seedAdmin(await createTestAuth({ auth: { database } }));
  const seen: Seen[] = [];
  const auth = await createTestAuth({
    auth: {
      database,
      user: {
        validateUserInfo: ({ user, source }) => {
          seen.push({ email: user.email, method: source.method, action: source.action });
          if (String(user.email).endsWith("@blocked.com")) {
            return { error: "domain_not_allowed", errorDescription: "Domain not allowed" };
          }
        }
      }
    }
  });
  return { auth, headers, seen };
}

describe("user.validateUserInfo (Better Auth >= 1.7)", () => {
  it("private invite: the pre-created shell passes the gate with method invite", async () => {
    const { auth, headers, seen } = await gatedAuth();
    const invite = await createInvite(auth, {
      body: { type: "private", email: "ok@test.com" },
      headers
    });
    expect(seen).toContainEqual({ email: "ok@test.com", method: "invite", action: "create-user" });

    await auth.api.acceptInvite({
      body: { token: invite.token, password: "password123", name: "Invitee" }
    });
    expect((await findUserByEmail(auth, "ok@test.com"))?.emailVerified).toBe(true);
  });

  it("public invite: the redeemed user passes the gate with method invite", async () => {
    const { auth, headers, seen } = await gatedAuth();
    const invite = await createInvite(auth, { body: { type: "public" }, headers });
    await auth.api.acceptInvite({
      body: {
        token: invite.token,
        email: "public@test.com",
        password: "password123",
        name: "Public"
      }
    });
    expect(seen).toContainEqual({
      email: "public@test.com",
      method: "invite",
      action: "create-user"
    });
    expect(await findUserByEmail(auth, "public@test.com")).toBeTruthy();
  });

  it("a rejection at invite creation surfaces as the gate's error, not EMAIL_ALREADY_INVITED", async () => {
    const { auth, headers } = await gatedAuth();
    const err = await captureError(() =>
      auth.api.createInvite({ body: { type: "private", email: "x@blocked.com" }, headers })
    );
    expect(err).toMatchObject({ status: "FORBIDDEN", code: "domain_not_allowed" });
    expect(await findUserByEmail(auth, "x@blocked.com")).toBeFalsy();
  });

  it("a rejection at public redemption surfaces the gate's error and returns the use", async () => {
    const { auth, headers } = await gatedAuth();
    const invite = await createInvite(auth, { body: { type: "public", maxUses: 1 }, headers });
    const err = await captureError(() =>
      auth.api.acceptInvite({
        body: {
          token: invite.token,
          email: "y@blocked.com",
          password: "password123",
          name: "Blocked"
        }
      })
    );
    expect(err).toMatchObject({ status: "FORBIDDEN", code: "domain_not_allowed" });
    const row = await findInviteRow(auth, invite.inviteId);
    expect(row).toMatchObject({ useCount: 0, status: "pending" });
  });
});
