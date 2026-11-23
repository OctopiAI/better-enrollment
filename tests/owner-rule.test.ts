import { organization } from "better-auth/plugins";
import { createAccessControl } from "better-auth/plugins/access";
import {
  adminAc as orgAdminAc,
  defaultStatements as orgStatements,
  memberAc as orgMemberAc,
  ownerAc as orgOwnerAc
} from "better-auth/plugins/organization/access";
import { describe, expect, it } from "vitest";
import type { BetterEnrollmentOptions } from "../src";
import {
  createInvite,
  createTestAuth,
  findUserByEmail,
  seedAdmin,
  seedUser,
  sentInvites,
  signInHeaders,
  type TestAuth
} from "./helpers";

const PASS = "Owner-Rule-Pass-8821";

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

async function setup(config?: {
  org?: Parameters<typeof organization>[0];
  invite?: Partial<BetterEnrollmentOptions>;
}) {
  const auth = await createTestAuth({
    plugins: [organization({ ...config?.org })],
    invite: { organization: {}, ...config?.invite }
  });
  await seedAdmin(auth);
  await seedUser(auth, { email: "owner@acme.com", password: PASS });
  const ownerHeaders = await signInHeaders(auth, "owner@acme.com", PASS);
  const org = await api(auth).createOrganization({
    body: { name: "Acme", slug: "acme" },
    headers: ownerHeaders
  });
  return { auth, ownerHeaders, org };
}

async function addMember(auth: TestAuth, organizationId: string, email: string, role: string) {
  const user = await seedUser(auth, { email, password: PASS });
  const member = await api(auth).addMember({ body: { userId: user.id, organizationId, role } });
  return { user, member, headers: await signInHeaders(auth, email, PASS) };
}

async function roleIn(auth: TestAuth, organizationId: string, email: string) {
  const user = await findUserByEmail(auth, email);
  if (!user) return null;
  const ctx = await auth.$context;
  const row = await ctx.adapter.findOne<{ role: string }>({
    model: "member",
    where: [
      { field: "organizationId", value: organizationId },
      { field: "userId", value: user.id }
    ]
  });
  return row?.role ?? null;
}

describe("the owner rule covers the org plugin's creatorRole", () => {
  it("an org admin cannot invite someone as a custom creator role", async () => {
    const ac = createAccessControl(orgStatements);
    const roles = { founder: orgOwnerAc, admin: orgAdminAc, member: orgMemberAc };
    const { auth, org } = await setup({
      org: { ac, roles, creatorRole: "founder" } as never,
      invite: { organization: { ac, roles, allowOwnerInvites: true } as never }
    });
    const adm = await addMember(auth, org.id, "adm@acme.com", "admin");
    expect(
      await code(
        api(auth).createInvite({
          body: {
            kind: "org-join",
            email: "f@else.com",
            organizationId: org.id,
            organizationRole: "founder"
          },
          headers: adm.headers
        })
      )
    ).toBe("OWNER_INVITES_NOT_ALLOWED");

    // A member holding the creator role may, with allowOwnerInvites.
    const fnd = await addMember(auth, org.id, "fnd@acme.com", "founder");
    const ok = await createInvite(auth, {
      body: {
        kind: "org-join",
        email: "f@else.com",
        organizationId: org.id,
        organizationRole: "founder"
      },
      headers: fnd.headers
    });
    expect(ok.inviteId).toBeTruthy();
  });
});

describe("with a custom creatorRole, a role named owner is ordinary", () => {
  it("only the creator role may grant the creator role", async () => {
    const ac = createAccessControl(orgStatements);
    // "owner" here is just a name: an admin-like role, not the creator role.
    const roles = {
      founder: orgOwnerAc,
      owner: orgAdminAc,
      admin: orgAdminAc,
      member: orgMemberAc
    };
    const { auth, org } = await setup({
      org: { ac, roles, creatorRole: "founder" } as never,
      invite: { organization: { ac, roles, allowOwnerInvites: true } as never }
    });
    const own = await addMember(auth, org.id, "own@acme.com", "owner");
    expect(
      await code(
        api(auth).createInvite({
          body: {
            kind: "org-join",
            email: "f@else.com",
            organizationId: org.id,
            organizationRole: "founder"
          },
          headers: own.headers
        })
      )
    ).toBe("OWNER_INVITES_NOT_ALLOWED");
    // Granting "owner" follows the ordinary rule (member:update).
    const ordinary = await createInvite(auth, {
      body: {
        kind: "org-join",
        email: "o@else.com",
        organizationId: org.id,
        organizationRole: "owner"
      },
      headers: own.headers
    });
    expect(ordinary.inviteId).toBeTruthy();
  });
});

describe("an owner invite needs its creator to still be an owner", () => {
  it("demoting the creator withdraws its pending owner invites", async () => {
    const { auth, ownerHeaders, org } = await setup({
      invite: { organization: { allowOwnerInvites: true } }
    });
    const o2 = await addMember(auth, org.id, "o2@acme.com", "owner");
    await createInvite(auth, {
      body: {
        kind: "org-join",
        email: "alt@else.com",
        organizationId: org.id,
        organizationRole: "owner"
      },
      headers: o2.headers
    });
    const token = sentInvites(auth).at(-1)!.token;
    await api(auth).updateMemberRole({
      body: { memberId: o2.member.id, role: "admin", organizationId: org.id },
      headers: ownerHeaders
    });
    expect(
      await code(api(auth).redeemInvite({ body: { token, password: PASS, name: "Alt" } }))
    ).toBe("INVITE_REVOKED");
    expect(await roleIn(auth, org.id, "alt@else.com")).toBeNull();
  });

  it("redemption re-checks it when the demotion bypassed the org plugin", async () => {
    const { auth, org } = await setup({ invite: { organization: { allowOwnerInvites: true } } });
    const o2 = await addMember(auth, org.id, "o2@acme.com", "owner");
    await createInvite(auth, {
      body: {
        kind: "org-join",
        email: "alt@else.com",
        organizationId: org.id,
        organizationRole: "owner"
      },
      headers: o2.headers
    });
    const token = sentInvites(auth).at(-1)!.token;
    const ctx = await auth.$context;
    await ctx.adapter.update({
      model: "member",
      where: [{ field: "id", value: o2.member.id }],
      update: { role: "admin" }
    });
    expect(
      await code(api(auth).redeemInvite({ body: { token, password: PASS, name: "Alt" } }))
    ).toBe("INVITE_REVOKED");
    expect(await roleIn(auth, org.id, "alt@else.com")).toBeNull();
  });
});

describe("org-create founders get the org plugin's creatorRole", () => {
  it("a custom creatorRole is the founder's role, and the founder can manage the org", async () => {
    const ac = createAccessControl(orgStatements);
    const roles = { founder: orgOwnerAc, admin: orgAdminAc, member: orgMemberAc };
    const auth = await createTestAuth({
      plugins: [organization({ ac, roles, creatorRole: "founder" } as never)],
      invite: { organization: { ac, roles } as never }
    });
    const adminHeaders = await seedAdmin(auth);
    const inv = await createInvite(auth, {
      body: { kind: "org-create", email: "boss@else.com" },
      headers: adminHeaders
    });
    const redeemed = await api(auth).redeemInvite({
      body: {
        token: inv.token,
        password: PASS,
        name: "Boss",
        organizationName: "Founded",
        organizationSlug: "founded"
      }
    });
    const orgId = redeemed.organization.id as string;
    expect(await roleIn(auth, orgId, "boss@else.com")).toBe("founder");

    const bossHeaders = await signInHeaders(auth, "boss@else.com", PASS);
    expect(
      await code(
        createInvite(auth, {
          body: { kind: "org-join", email: "m@else.com", organizationId: orgId },
          headers: bossHeaders
        })
      )
    ).toBeUndefined();
    expect(
      await code(
        api(auth).updateOrganization({
          body: { organizationId: orgId, data: { name: "Renamed" } },
          headers: bossHeaders
        })
      )
    ).toBeUndefined();
  });
});
