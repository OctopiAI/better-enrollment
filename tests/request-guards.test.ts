import { magicLink } from "better-auth/plugins";
import { describe, expect, it } from "vitest";
import {
  createInvite,
  createTestAuth,
  insertInviteRow,
  seedAdmin,
  type TestAuth
} from "./helpers";

const BASE = "http://localhost:3000/api/auth";

async function post(auth: TestAuth, path: string, body: unknown) {
  const res = await auth.handler(
    new Request(`${BASE}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: "http://localhost:3000" },
      body: JSON.stringify(body)
    })
  );
  return { status: res.status, text: await res.text() };
}

async function setup() {
  const resets: string[] = [];
  const links: string[] = [];
  const auth = await createTestAuth({
    plugins: [
      magicLink({
        disableSignUp: true,
        sendMagicLink: async ({ email }) => {
          links.push(email);
        }
      })
    ],
    auth: {
      emailAndPassword: {
        enabled: true,
        disableSignUp: true,
        sendResetPassword: async ({ user }) => {
          resets.push(user.email);
        }
      }
    }
  });
  return { auth, resets, links };
}

/** A verified account that signs in through a social provider only. */
async function socialOnlyUser(auth: TestAuth, email: string) {
  const ctx = await auth.$context;
  const user = await ctx.internalAdapter.createUser(
    { email, name: "Social", emailVerified: true },
    { method: "admin" }
  );
  await ctx.adapter.create({
    model: "account",
    data: {
      userId: user.id,
      providerId: "google",
      accountId: `g-${user.id}`,
      createdAt: new Date(),
      updatedAt: new Date()
    }
  });
  return user;
}

describe("request guards (BE-LIB-10)", () => {
  it("an established account resets its password despite an old unaccepted invite", async () => {
    const { auth, resets } = await setup();
    await socialOnlyUser(auth, "social@corp.test");
    // Invites issued to the existing account own no shell: one expired,
    // one revoked.
    const ctx = await auth.$context;
    for (const status of ["pending", "cancelled"]) {
      const row = await insertInviteRow(auth, {
        token: `t-${status}`,
        email: "social@corp.test",
        role: "user",
        preCreatedUserId: "none",
        expiresAt: new Date(Date.now() - 60_000)
      });
      await ctx.adapter.update({
        model: "invite",
        where: [{ field: "id", value: row.id as string }],
        update: { status, preCreatedUserId: null }
      });
    }
    const res = await post(auth, "/request-password-reset", { email: "social@corp.test" });
    expect(res.status).toBe(200);
    expect(resets).toEqual(["social@corp.test"]);
  });

  it("a pending invite's own user still gets the silent reply and no mail", async () => {
    const { auth, resets } = await setup();
    const adminHeaders = await seedAdmin(auth);
    await createInvite(auth, {
      body: { type: "private", email: "shell@corp.test" },
      headers: adminHeaders
    });
    const shell = await post(auth, "/request-password-reset", { email: "shell@corp.test" });
    const unknown = await post(auth, "/request-password-reset", { email: "nobody@corp.test" });
    expect(shell).toEqual(unknown);
    expect(resets).toEqual([]);
  });

  it("non-string emails get the endpoint's 400, not a 500", async () => {
    const { auth, resets, links } = await setup();
    for (const email of [12345, { $ne: "" }, ["a@b.c"]]) {
      expect((await post(auth, "/request-password-reset", { email })).status).toBe(400);
      expect((await post(auth, "/sign-in/magic-link", { email })).status).toBe(400);
    }
    expect(resets).toEqual([]);
    expect(links).toEqual([]);
  });
});
