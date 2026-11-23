import { organization } from "better-auth/plugins";
import { describe, expect, it } from "vitest";
import {
  createInvite,
  createTestAuth,
  expireInvite,
  findUserByEmail,
  seedAdmin,
  seedUser,
  signInHeaders,
  type TestAuth
} from "./helpers";

const PASS = "Uniform-Pass-6613";

// biome-ignore lint/suspicious/noExplicitAny: dynamic endpoint access
const api = (auth: TestAuth) => auth.api as any;

async function answer(p: Promise<unknown>): Promise<string | undefined> {
  try {
    return ((await p) as { action?: string }).action;
  } catch (e) {
    return (e as { body?: { code?: string } }).body?.code;
  }
}

describe("public sign-up answers every address alike", () => {
  it("a full organization refuses new and existing addresses the same way", async () => {
    const auth = await createTestAuth({
      plugins: [organization({ membershipLimit: 1 })],
      invite: { organization: {} }
    });
    await seedAdmin(auth);
    await seedUser(auth, { email: "owner@acme.com", password: PASS });
    const ownerHeaders = await signInHeaders(auth, "owner@acme.com", PASS);
    const org = await api(auth).createOrganization({
      body: { name: "Acme", slug: "acme" },
      headers: ownerHeaders
    });
    await seedUser(auth, { email: "known@corp.test", password: PASS });
    const inv = await createInvite(auth, {
      body: { type: "public", kind: "org-join", organizationId: org.id, maxUses: 5 },
      headers: ownerHeaders
    });
    const redeem = (email: string) =>
      answer(
        api(auth).redeemInvite({ body: { token: inv.token, email, password: PASS, name: "X" } })
      );
    expect(await redeem("known@corp.test")).toBe("MEMBERSHIP_LIMIT_REACHED");
    expect(await redeem("fresh@corp.test")).toBe("MEMBERSHIP_LIMIT_REACHED");
    expect(await findUserByEmail(auth, "fresh@corp.test")).toBeNull();
  });

  it("an address whose private invite expired can still use a public link", async () => {
    const verifications: string[] = [];
    const auth = await createTestAuth({
      auth: {
        emailAndPassword: { enabled: true, disableSignUp: true, requireEmailVerification: true },
        emailVerification: {
          sendVerificationEmail: async ({ user }) => {
            verifications.push(user.email);
          }
        }
      }
    });
    const headers = await seedAdmin(auth);
    const lapsed = await createInvite(auth, {
      body: { type: "private", email: "lapsed@corp.test" },
      headers
    });
    await expireInvite(auth, lapsed.inviteId);
    const pub = await createInvite(auth, { body: { type: "public", maxUses: 5 }, headers });
    const res = await api(auth).redeemInvite({
      body: { token: pub.token, email: "lapsed@corp.test", password: PASS, name: "L" }
    });
    expect(res).toEqual({ action: "CHECK_EMAIL" });
    expect(await findUserByEmail(auth, "lapsed@corp.test")).toBeTruthy();
    expect(verifications).toEqual(["lapsed@corp.test"]);
  });

  it("an existing account is mailed once per invite within the cooldown", async () => {
    for (const cooldown of [undefined, 0]) {
      const notices: string[] = [];
      const auth = await createTestAuth({
        invite: {
          existingAccountNoticeCooldown: cooldown,
          sendExistingAccountNotice: ({ email }) => {
            notices.push(email);
          }
        }
      });
      const headers = await seedAdmin(auth);
      await seedUser(auth, { email: "known@corp.test", password: PASS });
      const inv = await createInvite(auth, { body: { type: "public", maxUses: 1 }, headers });
      for (let i = 0; i < 3; i++) {
        const res = await api(auth).redeemInvite({
          body: { token: inv.token, email: "known@corp.test", password: PASS, name: "K" }
        });
        expect(res).toEqual({ action: "CHECK_EMAIL" });
      }
      expect(notices).toHaveLength(cooldown === 0 ? 3 : 1);
    }
  });
});
