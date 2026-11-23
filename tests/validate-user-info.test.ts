import { readFileSync } from "node:fs";
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

// The CI floor job runs this suite on Better Auth 1.6, which has no gate.
const installed = JSON.parse(
  readFileSync(new URL("../node_modules/better-auth/package.json", import.meta.url), "utf8")
) as { version: string };
const [major, minor] = installed.version.split(".").map(Number);
const hasGate = major! > 1 || (major === 1 && minor! >= 7);

describe.runIf(hasGate)("user.validateUserInfo (Better Auth >= 1.7)", () => {
  it("private invite: the user created at redemption passes the gate with method invite", async () => {
    const { auth, headers, seen } = await gatedAuth();
    const invite = await createInvite(auth, {
      body: { type: "private", email: "ok@test.com" },
      headers
    });
    expect(seen).toEqual([]);

    await auth.api.acceptInvite({
      body: { token: invite.token, password: "password123", name: "Invitee" }
    });
    expect(seen).toContainEqual({ email: "ok@test.com", method: "invite", action: "create-user" });
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

  it("a rejection at private redemption surfaces the gate's error and keeps the invite", async () => {
    const { auth, headers } = await gatedAuth();
    const invite = await createInvite(auth, {
      body: { type: "private", email: "x@blocked.com" },
      headers
    });
    const err = await captureError(() =>
      auth.api.acceptInvite({
        body: { token: invite.token, password: "password123", name: "Blocked" }
      })
    );
    expect(err).toMatchObject({ status: "FORBIDDEN", code: "domain_not_allowed" });
    expect(await findUserByEmail(auth, "x@blocked.com")).toBeFalsy();
    const row = await findInviteRow(auth, invite.inviteId);
    expect(row).toMatchObject({ useCount: 0, status: "pending" });
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
