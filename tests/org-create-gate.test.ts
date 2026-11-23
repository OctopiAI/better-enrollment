import { organization } from "better-auth/plugins";
import { createAccessControl } from "better-auth/plugins/access";
import {
  adminAc as appAdminAc,
  defaultStatements as appStatements
} from "better-auth/plugins/admin/access";
import { describe, expect, it } from "vitest";
import { inviteAdminAc, inviteStatements } from "../src";
import {
  createInvite,
  createTestAuth,
  seedAdmin,
  seedUser,
  signInHeaders,
  type TestAuth
} from "./helpers";

const PASS = "Org-Create-Pass-5150";

// biome-ignore lint/suspicious/noExplicitAny: dynamic endpoint access
const api = (auth: TestAuth) => auth.api as any;

async function code(p: Promise<unknown>): Promise<string | undefined> {
  try {
    await p;
    return undefined;
  } catch (e) {
    return (e as { body?: { code?: string } }).body?.code;
  }
}

async function setup(extra?: Record<string, unknown>) {
  const statement = { ...appStatements, ...inviteStatements } as const;
  const ac = createAccessControl(statement);
  const roles = {
    admin: ac.newRole({ ...appAdminAc.statements, ...inviteAdminAc.statements }),
    support: ac.newRole({ invite: ["create", "resend"] }),
    founder: ac.newRole({ invite: ["create", "manage-orgs"] }),
    user: ac.newRole({ invite: [] })
  };
  const auth = await createTestAuth({
    plugins: [organization({ allowUserToCreateOrganization: false })],
    invite: {
      ac,
      roles,
      validRoles: ["user", "support", "founder", "admin"],
      organization: {},
      ...extra
    }
  });
  const adminHeaders = await seedAdmin(auth);
  await seedUser(auth, { email: "support@test.com", password: PASS, role: "support" });
  const supportHeaders = await signInHeaders(auth, "support@test.com", PASS);
  return { auth, adminHeaders, supportHeaders };
}

describe("org-create invites need manage-orgs", () => {
  it("invite:create alone cannot create or resend one", async () => {
    const { auth, adminHeaders, supportHeaders } = await setup();
    expect(
      await code(
        api(auth).createInvite({
          body: { type: "public", kind: "org-create", maxUses: 1, presetSeatLimit: 5000 },
          headers: supportHeaders
        })
      )
    ).toBe("NOT_ALLOWED_TO_MANAGE_INVITES");
    // Plain app invites are unaffected.
    const app = await api(auth).createInvite({
      body: { type: "public", maxUses: 1 },
      headers: supportHeaders
    });
    expect(app.token).toBeTruthy();

    const link = await createInvite(auth, {
      body: { type: "public", kind: "org-create", maxUses: 1 },
      headers: adminHeaders
    });
    expect(
      await code(
        api(auth).resendInvite({ body: { inviteId: link.inviteId }, headers: supportHeaders })
      )
    ).toBe("NOT_ALLOWED_TO_MANAGE_INVITES");
  });

  it("redeeming your own org-create invite needs manage-orgs at redemption", async () => {
    // The self-redeem rule alone, without the inviter re-check in front of it.
    const { auth } = await setup({ revalidateInviterOnRedeem: false });
    const founder = await seedUser(auth, {
      email: "founder@test.com",
      password: PASS,
      role: "founder"
    });
    const headers = await signInHeaders(auth, "founder@test.com", PASS);
    const own = await createInvite(auth, {
      body: { type: "public", kind: "org-create", maxUses: 2 },
      headers
    });
    const ctx = await auth.$context;
    await ctx.adapter.update({
      model: "user",
      where: [{ field: "id", value: founder.id }],
      update: { role: "support" }
    });
    expect(
      await code(
        api(auth).redeemInvite({
          body: { token: own.token, organizationName: "Mine", organizationSlug: "mine" },
          headers
        })
      )
    ).toBe("CANNOT_REDEEM_OWN_INVITE");
  });

  it("an inviter who loses manage-orgs can no longer have its org-create invite redeemed", async () => {
    // Explicit so the test reads the same on 0.8, where the re-check is opt-in.
    const { auth } = await setup({ revalidateInviterOnRedeem: true });
    const founder = await seedUser(auth, {
      email: "founder@test.com",
      password: PASS,
      role: "founder"
    });
    const headers = await signInHeaders(auth, "founder@test.com", PASS);
    const link = await createInvite(auth, {
      body: { type: "public", kind: "org-create", maxUses: 1 },
      headers
    });
    const ctx = await auth.$context;
    await ctx.adapter.update({
      model: "user",
      where: [{ field: "id", value: founder.id }],
      update: { role: "support" }
    });
    expect(
      await code(
        api(auth).redeemInvite({
          body: {
            token: link.token,
            email: "new@test.com",
            password: PASS,
            name: "New",
            organizationName: "Theirs",
            organizationSlug: "theirs"
          }
        })
      )
    ).toBe("INVITE_REVOKED");
  });
});
