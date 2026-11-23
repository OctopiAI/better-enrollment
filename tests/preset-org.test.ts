import { APIError } from "better-auth/api";
import { organization } from "better-auth/plugins";
import { describe, expect, it } from "vitest";
import type { BetterEnrollmentOptions } from "../src";
import type { PrivateInvitationEmailData, PublicInvitationData } from "../src/types";
import {
  createInvite,
  createTestAuth,
  findInviteRow,
  findUserByEmail,
  seedAdmin,
  seedUser,
  signInHeaders,
  type TestAuth
} from "./helpers";

// biome-ignore lint/suspicious/noExplicitAny: dynamic endpoint access
const api = (auth: TestAuth) => auth.api as any;

const PASSWORD = "invitee-pass-1234";

type OrgRow = {
  id: string;
  name: string;
  slug: string;
  type?: string | null;
  parentOrganizationId?: string | null;
  customerLimit?: number | null;
};

async function setup(invite?: Partial<BetterEnrollmentOptions>) {
  const auth = await createTestAuth({
    plugins: [
      organization({
        schema: {
          organization: {
            additionalFields: {
              type: { type: "string", required: false },
              parentOrganizationId: { type: "string", required: false },
              customerLimit: { type: "number", required: false }
            }
          }
        }
      })
    ],
    invite: { organization: {}, ...invite }
  });
  const adminHeaders = await seedAdmin(auth);
  await seedUser(auth, { email: "owner@acme.com", password: "owner-pass-123" });
  const ownerHeaders = await signInHeaders(auth, "owner@acme.com", "owner-pass-123");
  await api(auth).createOrganization({
    body: { name: "Acme", slug: "acme" },
    headers: ownerHeaders
  });
  return { auth, adminHeaders };
}

async function findOrgBySlug(auth: TestAuth, slug: string) {
  const ctx = await auth.$context;
  return await ctx.adapter.findOne<OrgRow>({
    model: "organization",
    where: [{ field: "slug", value: slug }]
  });
}

async function findOrgsByName(auth: TestAuth, name: string) {
  const ctx = await auth.$context;
  return await ctx.adapter.findMany<OrgRow>({
    model: "organization",
    where: [{ field: "name", value: name }]
  });
}

async function errCode(p: Promise<unknown>): Promise<string | undefined> {
  try {
    await p;
    return undefined;
  } catch (e) {
    const err = e as { body?: { code?: string }; code?: string };
    return err.body?.code ?? err.code;
  }
}

describe("preset organization on org-create invites", () => {
  it("stores the preset, names it in the email and get, and founds it on redeem", async () => {
    const delivered: PrivateInvitationEmailData[] = [];
    const { auth, adminHeaders } = await setup({
      sendPrivateInvitation: (data) => {
        delivered.push(data);
      }
    });
    const created = await createInvite(auth, {
      body: {
        kind: "org-create",
        email: "founder@preset.com",
        organization: { name: "Preset Co", slug: "Preset-Co" }
      },
      headers: adminHeaders
    });

    const row = await findInviteRow(auth, created.inviteId);
    expect(row?.presetOrganizationName).toBe("Preset Co");
    expect(row?.presetOrganizationSlug).toBe("preset-co");
    expect(delivered[0]?.organizationName).toBe("Preset Co");

    await api(auth).resendInvite({ body: { inviteId: created.inviteId }, headers: adminHeaders });
    expect(delivered[1]?.organizationName).toBe("Preset Co");
    const token = delivered[1]!.token;

    const info = await api(auth).getInvite({ query: { token } });
    expect(info.organizationName).toBe("Preset Co");
    expect(info.requiredFields).toEqual(["password", "name"]);

    const res = await api(auth).redeemInvite({
      body: { token, password: PASSWORD, name: "Founder" }
    });
    expect(res.organization).toMatchObject({ name: "Preset Co", slug: "preset-co" });
    const founder = await findUserByEmail(auth, "founder@preset.com");
    const ctx = await auth.$context;
    const member = await ctx.adapter.findOne<{ role: string }>({
      model: "member",
      where: [
        { field: "userId", value: founder!.id },
        { field: "organizationId", value: res.organization.id }
      ]
    });
    expect(member?.role).toBe("owner");
  });

  it("ignores organization fields sent by the redeemer", async () => {
    const { auth, adminHeaders } = await setup();
    const created = await createInvite(auth, {
      body: {
        kind: "org-create",
        email: "founder@override.com",
        organization: { name: "Fixed Name", slug: "fixed" }
      },
      headers: adminHeaders
    });
    const res = await api(auth).redeemInvite({
      body: {
        token: created.token,
        password: PASSWORD,
        name: "Founder",
        organizationName: "Hijacked",
        organizationSlug: "hijacked"
      }
    });
    expect(res.organization).toMatchObject({ name: "Fixed Name", slug: "fixed" });
    expect(await findOrgBySlug(auth, "hijacked")).toBeNull();
    expect(await findOrgsByName(auth, "Hijacked")).toHaveLength(0);
  });

  it("derives the slug from the name when none is preset", async () => {
    const { auth, adminHeaders } = await setup();
    const created = await createInvite(auth, {
      body: {
        kind: "org-create",
        email: "founder@derive.com",
        organization: { name: "  Ünïcode Café & Co!  " }
      },
      headers: adminHeaders
    });
    const res = await api(auth).redeemInvite({
      body: { token: created.token, password: PASSWORD, name: "Founder" }
    });
    expect(res.organization).toMatchObject({ name: "Ünïcode Café & Co!", slug: "unicode-cafe-co" });
  });

  it("suffixes a taken slug instead of failing, for preset and derived slugs", async () => {
    const { auth, adminHeaders } = await setup();
    const preset = await createInvite(auth, {
      body: {
        kind: "org-create",
        email: "founder1@taken.com",
        organization: { name: "Acme Two", slug: "acme" }
      },
      headers: adminHeaders
    });
    const derived = await createInvite(auth, {
      body: {
        kind: "org-create",
        email: "founder2@taken.com",
        organization: { name: "Acme" }
      },
      headers: adminHeaders
    });

    const first = await api(auth).redeemInvite({
      body: { token: preset.token, password: PASSWORD, name: "Founder" }
    });
    const second = await api(auth).redeemInvite({
      body: { token: derived.token, password: PASSWORD, name: "Founder" }
    });
    expect(first.organization.slug).toMatch(/^acme-[a-z0-9]{6}$/);
    expect(second.organization.slug).toMatch(/^acme-[a-z0-9]{6}$/);
    expect(second.organization.slug).not.toBe(first.organization.slug);
    expect((await findOrgBySlug(auth, "acme"))?.name).toBe("Acme");
  });

  it("works through createSystemInvite and carries the name on public invites", async () => {
    const delivered: PublicInvitationData[] = [];
    const { auth } = await setup({
      sendPublicInvitation: (data) => {
        delivered.push(data);
      }
    });
    const res = await auth.api.createSystemInvite({
      body: {
        kind: "org-create",
        type: "public",
        maxUses: 1,
        organization: { name: "System Co" }
      }
    });
    expect(delivered[0]?.organizationName).toBe("System Co");
    const redeemed = await api(auth).redeemInvite({
      body: { token: res.token, password: PASSWORD, name: "Founder", email: "sys@co.com" }
    });
    expect(redeemed.action).toBe("CHECK_EMAIL");
    expect(await findOrgBySlug(auth, "system-co")).toMatchObject({ name: "System Co" });
  });

  it("rejects a preset on kinds other than org-create", async () => {
    const { auth, adminHeaders } = await setup();
    expect(
      await errCode(
        auth.api.createInvite({
          body: { email: "app@test.com", organization: { name: "Nope" } },
          headers: adminHeaders
        })
      )
    ).toBe("ORG_FIELDS_NOT_ALLOWED");
  });

  it("keeps the founder-entered flow when no preset is given", async () => {
    const { auth, adminHeaders } = await setup();
    const created = await createInvite(auth, {
      body: { kind: "org-create", email: "founder@classic.com" },
      headers: adminHeaders
    });
    const info = await api(auth).getInvite({ query: { token: created.token } });
    expect(info.organizationName).toBeNull();
    expect(info.requiredFields).toContain("organizationSlug");
    expect(
      await errCode(
        api(auth).redeemInvite({
          body: {
            token: created.token,
            password: PASSWORD,
            name: "Founder",
            organizationName: "Acme Again",
            organizationSlug: "acme"
          }
        })
      )
    ).toBe("ORG_SLUG_TAKEN");
  });
});

describe("organization.beforeOrgCreate", () => {
  it("merges returned fields into the org row; invite-owned fields win", async () => {
    const calls: { inviteId: string; email: string; organization: unknown }[] = [];
    const { auth, adminHeaders } = await setup({
      organization: {
        beforeOrgCreate: ({ invite, user, organization }) => {
          calls.push({ inviteId: invite.id, email: user.email, organization });
          return {
            type: "customer",
            parentOrganizationId: "msp-1",
            customerLimit: 5,
            name: "Overridden",
            slug: "overridden",
            seatLimit: 99
          };
        }
      }
    });
    const created = await createInvite(auth, {
      body: {
        kind: "org-create",
        email: "founder@hook.com",
        presetSeatLimit: 4,
        organization: { name: "Hooked" }
      },
      headers: adminHeaders
    });
    await api(auth).redeemInvite({
      body: { token: created.token, password: PASSWORD, name: "Founder" }
    });

    expect(calls).toEqual([
      {
        inviteId: created.inviteId,
        email: "founder@hook.com",
        organization: { name: "Hooked", slug: "hooked" }
      }
    ]);
    const org = await findOrgBySlug(auth, "hooked");
    expect(org).toMatchObject({
      name: "Hooked",
      type: "customer",
      parentOrganizationId: "msp-1",
      customerLimit: 5,
      seatLimit: 4
    });
    expect(await findOrgBySlug(auth, "overridden")).toBeNull();
  });

  it("receives the founder-entered name and slug without a preset", async () => {
    const seen: unknown[] = [];
    const { auth, adminHeaders } = await setup({
      organization: {
        beforeOrgCreate: ({ organization }) => {
          seen.push(organization);
        }
      }
    });
    const created = await createInvite(auth, {
      body: { kind: "org-create", email: "founder@plain.com" },
      headers: adminHeaders
    });
    await api(auth).redeemInvite({
      body: {
        token: created.token,
        password: PASSWORD,
        name: "Founder",
        organizationName: "Plain",
        organizationSlug: "plain"
      }
    });
    expect(seen).toEqual([{ name: "Plain", slug: "plain" }]);
  });

  it("a throw on private sign-up leaves the invite pending and the shell inert", async () => {
    let refuse = true;
    const { auth, adminHeaders } = await setup({
      organization: {
        beforeOrgCreate: () => {
          if (refuse) {
            throw new APIError("FORBIDDEN", { code: "NOT_ISSUED", message: "Not ours" });
          }
          return { type: "msp" };
        }
      }
    });
    const created = await createInvite(auth, {
      body: { kind: "org-create", email: "founder@refused.com", organization: { name: "Refused" } },
      headers: adminHeaders
    });
    const redeem = () =>
      api(auth).redeemInvite({
        body: { token: created.token, password: PASSWORD, name: "Founder" }
      });

    expect(await errCode(redeem())).toBe("NOT_ISSUED");
    const row = await findInviteRow(auth, created.inviteId);
    expect(row?.status).toBe("pending");
    expect(row?.useCount).toBe(0);
    expect(await findOrgBySlug(auth, "refused")).toBeNull();
    // The account created for the attempt is gone again.
    expect(await findUserByEmail(auth, "founder@refused.com")).toBeNull();

    refuse = false;
    const res = await redeem();
    expect(res.organization.slug).toBe("refused");
    expect((await findOrgBySlug(auth, "refused"))?.type).toBe("msp");
  });

  it("a throw on public sign-up removes the new user and returns the use", async () => {
    let refuse = true;
    const { auth, adminHeaders } = await setup({
      organization: {
        beforeOrgCreate: () => {
          if (refuse) throw new APIError("FORBIDDEN", { code: "NOT_ISSUED" });
        }
      }
    });
    const created = await createInvite(auth, {
      body: { kind: "org-create", type: "public", maxUses: 1, organization: { name: "Pub" } },
      headers: adminHeaders
    });
    const redeem = () =>
      api(auth).redeemInvite({
        body: { token: created.token, password: PASSWORD, name: "Founder", email: "p@pub.com" }
      });

    expect(await errCode(redeem())).toBe("NOT_ISSUED");
    const row = await findInviteRow(auth, created.inviteId);
    expect(row?.status).toBe("pending");
    expect(row?.useCount).toBe(0);
    expect(await findUserByEmail(auth, "p@pub.com")).toBeFalsy();

    refuse = false;
    expect((await redeem()).action).toBe("CHECK_EMAIL");
    expect(await findOrgBySlug(auth, "pub")).toBeTruthy();
  });

  it("a throw on a signed-in activation leaves the invite pending", async () => {
    const { auth, adminHeaders } = await setup({
      organization: {
        beforeOrgCreate: () => {
          throw new APIError("FORBIDDEN", { code: "NOT_ISSUED" });
        }
      }
    });
    await seedUser(auth, { email: "existing@act.com", password: "existing-pass-123" });
    const headers = await signInHeaders(auth, "existing@act.com", "existing-pass-123");
    const created = await createInvite(auth, {
      body: { kind: "org-create", email: "existing@act.com", organization: { name: "Act" } },
      headers: adminHeaders
    });
    expect(await errCode(api(auth).redeemInvite({ body: { token: created.token }, headers }))).toBe(
      "NOT_ISSUED"
    );
    const row = await findInviteRow(auth, created.inviteId);
    expect(row?.status).toBe("pending");
    expect(row?.useCount).toBe(0);
    expect(await findOrgBySlug(auth, "act")).toBeNull();
  });
});
