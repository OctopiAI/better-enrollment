import { organization } from "better-auth/plugins";
import { describe, expect, it } from "vitest";
import type { BetterEnrollmentOptions } from "../src";
import { roleGate } from "../src";
import {
  createInvite,
  createTestAuth,
  expireInvite,
  findInviteRow,
  findUserByEmail,
  seedAdmin,
  seedUser,
  signInHeaders,
  type TestAuth
} from "./helpers";

type OrgPluginConfig = Parameters<typeof organization>[0];

// Plugins passed as a dynamic array lose endpoint type inference, so tests
// go through an untyped accessor; runtime behavior is what is under test.
// biome-ignore lint/suspicious/noExplicitAny: dynamic endpoint access
const api = (auth: TestAuth) => auth.api as any;

async function createOrgAuth(config?: {
  invite?: Partial<BetterEnrollmentOptions>;
  org?: OrgPluginConfig;
  open?: boolean;
}) {
  return createTestAuth({
    plugins: [
      organization({
        teams: { enabled: true },
        dynamicAccessControl: { enabled: true },
        ...config?.org
      })
    ],
    invite: {
      ...(config?.open ? { mode: "open" as const } : {}),
      organization: {},
      ...config?.invite
    },
    ...(config?.open ? { auth: { emailAndPassword: { enabled: true, disableSignUp: false } } } : {})
  });
}

async function setupOrg(config?: {
  invite?: Partial<BetterEnrollmentOptions>;
  org?: OrgPluginConfig;
  open?: boolean;
}) {
  const auth = await createOrgAuth(config);
  const adminHeaders = await seedAdmin(auth);
  const owner = await seedUser(auth, {
    email: "owner@acme.com",
    password: "owner-pass-123",
    name: "Owner"
  });
  const ownerHeaders = await signInHeaders(auth, "owner@acme.com", "owner-pass-123");
  const org = await api(auth).createOrganization({
    body: { name: "Acme", slug: "acme" },
    headers: ownerHeaders
  });
  return { auth, adminHeaders, owner, ownerHeaders, org };
}

async function addOrgMember(
  auth: TestAuth,
  organizationId: string,
  email: string,
  role = "member"
) {
  const user = await seedUser(auth, { email, password: "member-pass-123" });
  await api(auth).addMember({
    body: { userId: user.id, organizationId, role }
  });
  const headers = await signInHeaders(auth, email, "member-pass-123");
  return { user, headers };
}

async function getMemberRow(auth: TestAuth, userId: string, organizationId: string) {
  const ctx = await auth.$context;
  return await ctx.adapter.findOne<{
    id: string;
    role: string;
    organizationId: string;
  }>({
    model: "member",
    where: [
      { field: "userId", value: userId },
      { field: "organizationId", value: organizationId }
    ]
  });
}

async function addDynamicRole(
  auth: TestAuth,
  organizationId: string,
  role: string,
  actions: string[]
) {
  const ctx = await auth.$context;
  await ctx.adapter.create({
    model: "organizationRole",
    data: {
      organizationId,
      role,
      permission: JSON.stringify({ invitation: actions }),
      createdAt: new Date(),
      updatedAt: new Date()
    }
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

const PASSWORD = "invitee-pass-1234";

describe("org-join creation gate", () => {
  it("owner and delegated roles create org invites; plain members cannot", async () => {
    const { auth, org, ownerHeaders } = await setupOrg();

    const created = await createInvite(auth, {
      body: {
        kind: "org-join",
        email: "new1@acme.com",
        organizationId: org.id
      },
      headers: ownerHeaders
    });
    expect(created.token).toBeTruthy();
    const row = await findInviteRow(auth, created.inviteId);
    expect(row?.kind).toBe("org-join");
    expect(row?.organizationId).toBe(org.id);

    const member = await addOrgMember(auth, org.id, "plain@acme.com");
    expect(
      await errCode(
        createInvite(auth, {
          body: {
            kind: "org-join",
            email: "new2@acme.com",
            organizationId: org.id
          },
          headers: member.headers
        })
      )
    ).toBe("ORG_INVITE_NOT_ALLOWED");

    // Delegation through a dynamic-AC custom role.
    await addDynamicRole(auth, org.id, "recruiter", ["create"]);
    const recruiter = await addOrgMember(auth, org.id, "recruiter@acme.com", "recruiter");
    const delegated = await createInvite(auth, {
      body: {
        kind: "org-join",
        email: "new3@acme.com",
        organizationId: org.id
      },
      headers: recruiter.headers
    });
    expect(delegated.token).toBeTruthy();
  });

  it("org-join invites cannot set an app role and always carry the default", async () => {
    const { auth, org, ownerHeaders } = await setupOrg();
    // The app role is an admin-only field; an org owner passing one
    // would otherwise be able to mint app admins.
    expect(
      await errCode(
        createInvite(auth, {
          body: {
            kind: "org-join",
            email: "escalate@acme.com",
            organizationId: org.id,
            role: "admin"
          },
          headers: ownerHeaders
        })
      )
    ).toBe("ROLE_NOT_ALLOWED_FOR_ORG_JOIN");

    const created = await createInvite(auth, {
      body: {
        kind: "org-join",
        email: "default@acme.com",
        organizationId: org.id
      },
      headers: ownerHeaders
    });
    expect((await findInviteRow(auth, created.inviteId))?.role).toBe("user");
  });

  it("canCreateOrgInvites override replaces the permission check", async () => {
    const { auth, org, ownerHeaders } = await setupOrg({
      invite: {
        organization: {
          canCreateOrgInvites: (member) => member.role === "member"
        }
      }
    });
    // Owner is denied by the override.
    expect(
      await errCode(
        createInvite(auth, {
          body: {
            kind: "org-join",
            email: "a@acme.com",
            organizationId: org.id
          },
          headers: ownerHeaders
        })
      )
    ).toBe("ORG_INVITE_NOT_ALLOWED");
    // A plain member is allowed by it.
    const member = await addOrgMember(auth, org.id, "m@acme.com");
    const created = await createInvite(auth, {
      body: {
        kind: "org-join",
        email: "b@acme.com",
        organizationId: org.id
      },
      headers: member.headers
    });
    expect(created.token).toBeTruthy();
  });

  it("app admins cannot create org-join invites but keep app and org-create", async () => {
    const { auth, org, adminHeaders } = await setupOrg();
    expect(
      await errCode(
        createInvite(auth, {
          body: {
            kind: "org-join",
            email: "x@acme.com",
            organizationId: org.id
          },
          headers: adminHeaders
        })
      )
    ).toBe("ORG_INVITE_NOT_ALLOWED");

    const appInvite = await createInvite(auth, {
      body: { email: "manager@test.com", role: "admin" },
      headers: adminHeaders
    });
    expect(appInvite.token).toBeTruthy();
    expect((await findInviteRow(auth, appInvite.inviteId))?.kind).toBe("app");

    const orgCreate = await createInvite(auth, {
      body: {
        kind: "org-create",
        email: "founder@test.com",
        presetSeatLimit: 5
      },
      headers: adminHeaders
    });
    expect(orgCreate.token).toBeTruthy();
    expect((await findInviteRow(auth, orgCreate.inviteId))?.presetSeatLimit).toBe(5);
  });

  it("delegated members cannot mint app or org-create invites", async () => {
    const { auth, org } = await setupOrg();
    await addDynamicRole(auth, org.id, "recruiter", ["create"]);
    const recruiter = await addOrgMember(auth, org.id, "recruiter@acme.com", "recruiter");
    expect(
      await errCode(
        createInvite(auth, {
          body: { email: "app@test.com" },
          headers: recruiter.headers
        })
      )
    ).toBe("NOT_ALLOWED_TO_MANAGE_INVITES");
    expect(
      await errCode(
        createInvite(auth, {
          body: { kind: "org-create", email: "founder@test.com" },
          headers: recruiter.headers
        })
      )
    ).toBe("NOT_ALLOWED_TO_MANAGE_INVITES");
  });

  it("cross-org isolation: unknown org and foreign org return the same FORBIDDEN", async () => {
    const { auth, ownerHeaders } = await setupOrg();
    await seedUser(auth, {
      email: "other@corp.com",
      password: "other-pass-123"
    });
    const otherHeaders = await signInHeaders(auth, "other@corp.com", "other-pass-123");
    const otherOrg = await api(auth).createOrganization({
      body: { name: "Corp", slug: "corp" },
      headers: otherHeaders
    });

    // Owner of Acme cannot act on Corp.
    const foreign = await errCode(
      createInvite(auth, {
        body: {
          kind: "org-join",
          email: "x@corp.com",
          organizationId: otherOrg.id
        },
        headers: ownerHeaders
      })
    );
    // Nonexistent org: identical error, no enumeration.
    const unknown = await errCode(
      createInvite(auth, {
        body: {
          kind: "org-join",
          email: "y@corp.com",
          organizationId: "does-not-exist"
        },
        headers: ownerHeaders
      })
    );
    expect(foreign).toBe("ORG_INVITE_NOT_ALLOWED");
    expect(unknown).toBe("ORG_INVITE_NOT_ALLOWED");
  });

  it("validates organizationRole and blocks owner invites by default", async () => {
    const { auth, org, ownerHeaders } = await setupOrg();
    expect(
      await errCode(
        createInvite(auth, {
          body: {
            kind: "org-join",
            email: "a@acme.com",
            organizationId: org.id,
            organizationRole: "ghost-role"
          },
          headers: ownerHeaders
        })
      )
    ).toBe("INVALID_ORG_ROLE");
    expect(
      await errCode(
        createInvite(auth, {
          body: {
            kind: "org-join",
            email: "b@acme.com",
            organizationId: org.id,
            organizationRole: "owner"
          },
          headers: ownerHeaders
        })
      )
    ).toBe("OWNER_INVITES_NOT_ALLOWED");
  });

  it("allowOwnerInvites permits owner invites for the org's owner only", async () => {
    const { auth, org, ownerHeaders } = await setupOrg({
      invite: { organization: { allowOwnerInvites: true } }
    });
    const created = await createInvite(auth, {
      body: {
        kind: "org-join",
        email: "co-owner@acme.com",
        organizationId: org.id,
        organizationRole: "owner"
      },
      headers: ownerHeaders
    });
    expect(created.token).toBeTruthy();

    const orgAdmin = await addOrgMember(auth, org.id, "oa@acme.com", "admin");
    expect(
      await errCode(
        createInvite(auth, {
          body: {
            kind: "org-join",
            email: "co-owner2@acme.com",
            organizationId: org.id,
            organizationRole: "owner"
          },
          headers: orgAdmin.headers
        })
      )
    ).toBe("OWNER_INVITES_NOT_ALLOWED");
  });
});

describe("org-join redemption (invite-only)", () => {
  it("accept joins the org, sets active organization, keeps app and org roles separate", async () => {
    const { auth, org, ownerHeaders } = await setupOrg();
    const created = await createInvite(auth, {
      body: {
        kind: "org-join",
        email: "joiner@acme.com",
        organizationId: org.id
      },
      headers: ownerHeaders
    });
    const res = await api(auth).redeemInvite({
      body: { token: created.token, password: PASSWORD, name: "Joiner" }
    });
    expect(res.organization?.id).toBe(org.id);
    expect(res.organization?.name).toBe("Acme");

    const user = await findUserByEmail(auth, "joiner@acme.com");
    expect(user?.emailVerified).toBe(true);
    expect((user as { role?: string })?.role).toBe("user");

    const member = await getMemberRow(auth, user!.id, org.id);
    expect(member?.role).toBe("member");

    const ctx = await auth.$context;
    const session = await ctx.adapter.findOne<{
      activeOrganizationId: string | null;
    }>({
      model: "session",
      where: [{ field: "token", value: res.token }]
    });
    expect(session?.activeOrganizationId).toBe(org.id);
  });

  it("team invites add the member to the team; wrong-org teams are rejected at create", async () => {
    const { auth, org, ownerHeaders } = await setupOrg();
    const team = await api(auth).createTeam({
      body: { name: "Engineering", organizationId: org.id },
      headers: ownerHeaders
    });

    const withTeam = await createInvite(auth, {
      body: {
        kind: "org-join",
        email: "eng@acme.com",
        organizationId: org.id,
        teamId: team.id
      },
      headers: ownerHeaders
    });
    await api(auth).redeemInvite({
      body: { token: withTeam.token, password: PASSWORD }
    });
    const user = await findUserByEmail(auth, "eng@acme.com");
    const ctx = await auth.$context;
    const teamMember = await ctx.adapter.findOne<{ id: string }>({
      model: "teamMember",
      where: [
        { field: "teamId", value: team.id },
        { field: "userId", value: user!.id }
      ]
    });
    expect(teamMember).toBeTruthy();

    // A team belonging to a different org is rejected.
    const otherOrg = await api(auth).createOrganization({
      body: { name: "Second", slug: "second" },
      headers: ownerHeaders
    });
    expect(
      await errCode(
        createInvite(auth, {
          body: {
            kind: "org-join",
            email: "x@acme.com",
            organizationId: otherOrg.id,
            teamId: team.id
          },
          headers: ownerHeaders
        })
      )
    ).toBe("TEAM_NOT_FOUND");
  });

  it("redemption-time revalidation: deleted team is skipped, deleted dynamic role degrades", async () => {
    const { auth, org, ownerHeaders } = await setupOrg();
    const team = await api(auth).createTeam({
      body: { name: "Ops", organizationId: org.id },
      headers: ownerHeaders
    });
    await addDynamicRole(auth, org.id, "contractor", []);

    const created = await createInvite(auth, {
      body: {
        kind: "org-join",
        email: "late@acme.com",
        organizationId: org.id,
        organizationRole: "contractor",
        teamId: team.id
      },
      headers: ownerHeaders
    });

    // Team and dynamic role both vanish before redemption.
    const ctx = await auth.$context;
    await ctx.adapter.delete({
      model: "team",
      where: [{ field: "id", value: team.id }]
    });
    await ctx.adapter.delete({
      model: "organizationRole",
      where: [{ field: "role", value: "contractor" }]
    });

    await api(auth).redeemInvite({
      body: { token: created.token, password: PASSWORD }
    });
    const user = await findUserByEmail(auth, "late@acme.com");
    const member = await getMemberRow(auth, user!.id, org.id);
    expect(member?.role).toBe("member");
    const teamMember = await ctx.adapter.findOne({
      model: "teamMember",
      where: [{ field: "userId", value: user!.id }]
    });
    expect(teamMember).toBeNull();
  });

  it("org deletion kills its invites", async () => {
    const { auth, org, ownerHeaders, adminHeaders } = await setupOrg();
    const created = await createInvite(auth, {
      body: {
        kind: "org-join",
        email: "orphan@acme.com",
        organizationId: org.id
      },
      headers: ownerHeaders
    });
    await api(auth).deleteOrg({
      body: { organizationId: org.id },
      headers: adminHeaders
    });
    expect(await findInviteRow(auth, created.inviteId)).toBeNull();
    expect(
      await errCode(
        api(auth).redeemInvite({
          body: { token: created.token, password: PASSWORD }
        })
      )
    ).toBe("INVITE_NOT_FOUND");
  });
});

describe("seat limits", () => {
  it("only app admins set seat limits", async () => {
    const { auth, org, ownerHeaders, adminHeaders } = await setupOrg();
    expect(
      await errCode(
        api(auth).setOrgSeatLimit({
          body: { organizationId: org.id, seatLimit: 3 },
          headers: ownerHeaders
        })
      )
    ).toBe("NOT_ALLOWED_TO_MANAGE_INVITES");
    const res = await api(auth).setOrgSeatLimit({
      body: { organizationId: org.id, seatLimit: 3 },
      headers: adminHeaders
    });
    expect(res.seatLimit).toBe(3);
  });

  it("reservation math blocks over-inviting and frees on revoke", async () => {
    const { auth, org, ownerHeaders, adminHeaders } = await setupOrg();
    await api(auth).setOrgSeatLimit({
      body: { organizationId: org.id, seatLimit: 2 },
      headers: adminHeaders
    });

    // Owner occupies 1 seat; a private invite reserves the second.
    const first = await createInvite(auth, {
      body: {
        kind: "org-join",
        email: "one@acme.com",
        organizationId: org.id
      },
      headers: ownerHeaders
    });
    const usage = await api(auth).orgInviteUsage({
      query: { organizationId: org.id },
      headers: ownerHeaders
    });
    expect(usage).toMatchObject({
      seatLimit: 2,
      members: 1,
      pendingReserved: 1,
      remaining: 0
    });

    expect(
      await errCode(
        createInvite(auth, {
          body: {
            kind: "org-join",
            email: "two@acme.com",
            organizationId: org.id
          },
          headers: ownerHeaders
        })
      )
    ).toBe("SEAT_LIMIT_REACHED");

    // Unlimited public invites are unsound with a seat limit.
    expect(
      await errCode(
        createInvite(auth, {
          body: { kind: "org-join", type: "public", organizationId: org.id },
          headers: ownerHeaders
        })
      )
    ).toBe("PUBLIC_ORG_INVITE_REQUIRES_MAX_USES");

    // Revoking releases the reservation.
    await api(auth).revokeInvite({
      body: { inviteId: first.inviteId },
      headers: ownerHeaders
    });
    const second = await createInvite(auth, {
      body: {
        kind: "org-join",
        email: "two@acme.com",
        organizationId: org.id
      },
      headers: ownerHeaders
    });
    expect(second.token).toBeTruthy();
  });

  it("expired reservations are released lazily", async () => {
    const { auth, org, ownerHeaders, adminHeaders } = await setupOrg();
    await api(auth).setOrgSeatLimit({
      body: { organizationId: org.id, seatLimit: 2 },
      headers: adminHeaders
    });
    const first = await createInvite(auth, {
      body: {
        kind: "org-join",
        email: "one@acme.com",
        organizationId: org.id
      },
      headers: ownerHeaders
    });
    await expireInvite(auth, first.inviteId);
    const second = await createInvite(auth, {
      body: {
        kind: "org-join",
        email: "two@acme.com",
        organizationId: org.id
      },
      headers: ownerHeaders
    });
    expect(second.token).toBeTruthy();
  });

  it("accept-time guard catches out-of-band member growth", async () => {
    let seatHookFired = 0;
    const { auth, org, ownerHeaders, adminHeaders } = await setupOrg({
      invite: {
        organization: {
          onSeatLimitReached: () => {
            seatHookFired++;
          }
        }
      }
    });
    await api(auth).setOrgSeatLimit({
      body: { organizationId: org.id, seatLimit: 2 },
      headers: adminHeaders
    });
    const created = await createInvite(auth, {
      body: {
        kind: "org-join",
        email: "late@acme.com",
        organizationId: org.id
      },
      headers: ownerHeaders
    });
    // The org plugin's own addMember bypasses invite reservations.
    await addOrgMember(auth, org.id, "direct@acme.com");
    expect(
      await errCode(
        api(auth).redeemInvite({
          body: { token: created.token, password: PASSWORD }
        })
      )
    ).toBe("SEAT_LIMIT_REACHED");
    expect(seatHookFired).toBeGreaterThan(0);
    // The claim was rolled back: the invite is still pending.
    expect((await findInviteRow(auth, created.inviteId))?.status).toBe("pending");
  });

  it("parallel redemptions never exceed the invite cap: exactly one member row", async () => {
    const { auth, org, ownerHeaders, adminHeaders } = await setupOrg();
    await api(auth).setOrgSeatLimit({
      body: { organizationId: org.id, seatLimit: 5 },
      headers: adminHeaders
    });
    const created = await createInvite(auth, {
      body: {
        kind: "org-join",
        type: "public",
        organizationId: org.id,
        maxUses: 1
      },
      headers: ownerHeaders
    });
    const results = await Promise.allSettled([
      api(auth).redeemInvite({
        body: {
          token: created.token,
          password: PASSWORD,
          email: "race1@acme.com"
        }
      }),
      api(auth).redeemInvite({
        body: {
          token: created.token,
          password: PASSWORD,
          email: "race2@acme.com"
        }
      })
    ]);
    const ok = results.filter((r) => r.status === "fulfilled");
    expect(ok.length).toBe(1);
    const ctx = await auth.$context;
    const members = await ctx.adapter.count({
      model: "member",
      where: [{ field: "organizationId", value: org.id }]
    });
    expect(members).toBe(2); // owner + exactly one invitee
  });

  it("resolveSeatLimit outranks the stored field", async () => {
    const { auth, org, ownerHeaders, adminHeaders } = await setupOrg({
      invite: {
        organization: { resolveSeatLimit: () => 1 }
      }
    });
    // Stored limit says 5, subscription callback says 1: callback wins.
    await api(auth).setOrgSeatLimit({
      body: { organizationId: org.id, seatLimit: 5 },
      headers: adminHeaders
    });
    expect(
      await errCode(
        createInvite(auth, {
          body: {
            kind: "org-join",
            email: "no-seat@acme.com",
            organizationId: org.id
          },
          headers: ownerHeaders
        })
      )
    ).toBe("SEAT_LIMIT_REACHED");
  });
});

describe("org-create", () => {
  it("founds the org on redeem: creator role, preset seat limit, active org", async () => {
    const { auth, adminHeaders } = await setupOrg();
    const created = await createInvite(auth, {
      body: {
        kind: "org-create",
        email: "founder@newco.com",
        presetSeatLimit: 3
      },
      headers: adminHeaders
    });
    const res = await api(auth).redeemInvite({
      body: {
        token: created.token,
        password: PASSWORD,
        organizationName: "NewCo",
        organizationSlug: "NewCo"
      }
    });
    expect(res.organization?.name).toBe("NewCo");
    expect(res.organization?.slug).toBe("newco");

    const ctx = await auth.$context;
    const org = await ctx.adapter.findOne<{
      id: string;
      seatLimit: number | null;
    }>({
      model: "organization",
      where: [{ field: "slug", value: "newco" }]
    });
    expect(org?.seatLimit).toBe(3);

    const founder = await findUserByEmail(auth, "founder@newco.com");
    const member = await getMemberRow(auth, founder!.id, org!.id);
    expect(member?.role).toBe("owner");

    const session = await ctx.adapter.findOne<{
      activeOrganizationId: string | null;
    }>({
      model: "session",
      where: [{ field: "token", value: res.token }]
    });
    expect(session?.activeOrganizationId).toBe(org!.id);
  });

  it("slug conflicts fail cleanly with nothing partially created", async () => {
    const { auth, adminHeaders } = await setupOrg();
    const created = await createInvite(auth, {
      body: { kind: "org-create", email: "founder@dup.com" },
      headers: adminHeaders
    });
    expect(
      await errCode(
        api(auth).redeemInvite({
          body: {
            token: created.token,
            password: PASSWORD,
            organizationName: "Acme Again",
            organizationSlug: "acme" // taken by setupOrg
          }
        })
      )
    ).toBe("ORG_SLUG_TAKEN");
    // Precheck runs before the claim: the invite survives for a retry.
    expect((await findInviteRow(auth, created.inviteId))?.status).toBe("pending");
    expect(
      await errCode(
        api(auth).redeemInvite({
          body: { token: created.token, password: PASSWORD }
        })
      )
    ).toBe("ORG_INFO_REQUIRED");
  });

  it("check-slug: token-gated availability mirrors the org plugin's check", async () => {
    const { auth, adminHeaders } = await setupOrg();
    const created = await createInvite(auth, {
      body: { kind: "org-create", email: "founder@slugcheck.com" },
      headers: adminHeaders
    });

    const free = await api(auth).checkInviteSlug({
      query: { token: created.token, slug: "Fresh-Slug" }
    });
    expect(free.status).toBe(true);

    expect(
      await errCode(
        api(auth).checkInviteSlug({
          query: { token: created.token, slug: "acme" } // taken by setupOrg
        })
      )
    ).toBe("ORG_SLUG_TAKEN");

    // Only a pending org-create token unlocks the check.
    expect(
      await errCode(
        api(auth).checkInviteSlug({
          query: { token: "garbage-token", slug: "whatever" }
        })
      )
    ).toBe("INVITE_NOT_FOUND");
    const appInvite = await createInvite(auth, {
      body: { kind: "app", email: "plain@slugcheck.com" },
      headers: adminHeaders
    });
    expect(
      await errCode(
        api(auth).checkInviteSlug({
          query: { token: appInvite.token, slug: "whatever" }
        })
      )
    ).toBe("INVITE_NOT_FOUND");
  });

  it("public org-create invites found a separate org per use", async () => {
    const { auth, adminHeaders } = await setupOrg();
    const created = await createInvite(auth, {
      body: { kind: "org-create", type: "public", maxUses: 2 },
      headers: adminHeaders
    });
    await api(auth).redeemInvite({
      body: {
        token: created.token,
        password: PASSWORD,
        email: "f1@a.com",
        organizationName: "Alpha",
        organizationSlug: "alpha"
      }
    });
    await api(auth).redeemInvite({
      body: {
        token: created.token,
        password: PASSWORD,
        email: "f2@b.com",
        organizationName: "Beta",
        organizationSlug: "beta"
      }
    });
    const ctx = await auth.$context;
    const orgs = await ctx.adapter.count({ model: "organization" });
    expect(orgs).toBe(3); // acme + alpha + beta
  });

  it("bypasses allowUserToCreateOrganization: the invite is the authorization", async () => {
    // No seed org here: the closed gate would block setupOrg itself.
    const auth = await createOrgAuth({
      org: { allowUserToCreateOrganization: () => false }
    });
    const adminHeaders = await seedAdmin(auth);
    const created = await createInvite(auth, {
      body: { kind: "org-create", email: "gated@newco.com" },
      headers: adminHeaders
    });
    const res = await api(auth).redeemInvite({
      body: {
        token: created.token,
        password: PASSWORD,
        organizationName: "Gated",
        organizationSlug: "gated"
      }
    });
    expect(res.organization?.slug).toBe("gated");
  });

  it("parallel slug race: loser is fully cleaned up and can retry", async () => {
    const { auth, adminHeaders } = await setupOrg();
    const created = await createInvite(auth, {
      body: { kind: "org-create", type: "public", maxUses: 2 },
      headers: adminHeaders
    });
    const redeem = (email: string, slug: string) =>
      api(auth).redeemInvite({
        body: {
          token: created.token,
          password: PASSWORD,
          email,
          organizationName: "Race Co",
          organizationSlug: slug
        }
      });
    const results = await Promise.allSettled([
      redeem("a@race.com", "race-co"),
      redeem("b@race.com", "race-co")
    ]);
    expect(results.filter((r) => r.status === "fulfilled").length).toBe(1);
    expect(results.filter((r) => r.status === "rejected").length).toBe(1);

    // Whether the loser died at the precheck or in the unique-constraint
    // race, its half-created user must be gone and the email reusable.
    const loserEmail = results[0].status === "rejected" ? "a@race.com" : "b@race.com";
    expect(await findUserByEmail(auth, loserEmail)).toBeFalsy();

    // The rolled-back claim leaves a use available for the retry.
    const retry = await api(auth).redeemInvite({
      body: {
        token: created.token,
        password: PASSWORD,
        email: loserEmail,
        organizationName: "Race Co Two",
        organizationSlug: "race-co-2"
      }
    });
    expect(retry.organization?.slug).toBe("race-co-2");
  });
});

describe("uniform redemption flow", () => {
  it("get drives a single invite page: kind, org name, nextAction, requiredFields", async () => {
    const { auth, org, ownerHeaders, adminHeaders } = await setupOrg();
    const orgJoin = await createInvite(auth, {
      body: {
        kind: "org-join",
        email: "page@acme.com",
        organizationId: org.id
      },
      headers: ownerHeaders
    });
    const info = await api(auth).getInvite({
      query: { token: orgJoin.token }
    });
    expect(info.kind).toBe("org-join");
    expect(info.organizationName).toBe("Acme");
    expect(info.nextAction).toBe("SIGN_UP");
    expect(info.requiredFields).toEqual(["password"]);

    const orgCreate = await createInvite(auth, {
      body: { kind: "org-create", type: "public", maxUses: 3 },
      headers: adminHeaders
    });
    const info2 = await api(auth).getInvite({
      query: { token: orgCreate.token }
    });
    expect(info2.requiredFields).toEqual([
      "password",
      "email",
      "organizationName",
      "organizationSlug"
    ]);
  });

  it("open mode: nextAction is SIGN_IN without a session, CONFIRM with one", async () => {
    const { auth, org, ownerHeaders } = await setupOrg({ open: true });
    const created = await createInvite(auth, {
      body: {
        kind: "org-join",
        email: "existing@acme.com",
        organizationId: org.id
      },
      headers: ownerHeaders
    });
    const anon = await api(auth).getInvite({
      query: { token: created.token }
    });
    expect(anon.nextAction).toBe("SIGN_IN");
    expect(anon.requiredFields).toEqual([]);

    await seedUser(auth, {
      email: "existing@acme.com",
      password: PASSWORD
    });
    const headers = await signInHeaders(auth, "existing@acme.com", PASSWORD);
    const authed = await api(auth).getInvite({
      query: { token: created.token },
      headers
    });
    expect(authed.nextAction).toBe("CONFIRM");
  });

  it("open mode redeem activates: joins the org, app role stays as-is", async () => {
    const { auth, org, ownerHeaders } = await setupOrg({ open: true });
    const created = await createInvite(auth, {
      body: {
        kind: "org-join",
        email: "activator@acme.com",
        organizationId: org.id
      },
      headers: ownerHeaders
    });
    const user = await seedUser(auth, {
      email: "activator@acme.com",
      password: PASSWORD,
      role: "user"
    });
    const headers = await signInHeaders(auth, "activator@acme.com", PASSWORD);
    const res = await api(auth).redeemInvite({
      body: { token: created.token },
      headers
    });
    expect(res.action).toBe("ACCEPTED");
    expect(res.role).toBe("user");
    const member = await getMemberRow(auth, user.id, org.id);
    expect(member?.role).toBe("member");
  });

  it("open mode: an existing member gets org roles merged, no duplicate row, no seat", async () => {
    const { auth, org, ownerHeaders, adminHeaders } = await setupOrg({
      open: true
    });
    await api(auth).setOrgSeatLimit({
      body: { organizationId: org.id, seatLimit: 2 },
      headers: adminHeaders
    });
    const existing = await addOrgMember(auth, org.id, "already@acme.com");
    // Org is now full (owner + member); inviting the existing member is
    // still fine because they consume no seat... except the reservation,
    // which we free by keeping the org large enough for the invite.
    await api(auth).setOrgSeatLimit({
      body: { organizationId: org.id, seatLimit: 3 },
      headers: adminHeaders
    });
    await addDynamicRole(auth, org.id, "billing", []);
    const created = await createInvite(auth, {
      body: {
        kind: "org-join",
        email: "already@acme.com",
        organizationId: org.id,
        organizationRole: "billing"
      },
      headers: ownerHeaders
    });
    const res = await api(auth).redeemInvite({
      body: { token: created.token },
      headers: existing.headers
    });
    expect(res.action).toBe("ACCEPTED");
    const member = await getMemberRow(auth, existing.user.id, org.id);
    expect(member?.role).toBe("member,billing");
    const ctx = await auth.$context;
    const count = await ctx.adapter.count({
      model: "member",
      where: [{ field: "organizationId", value: org.id }]
    });
    expect(count).toBe(2);
  });
});

describe("platform controls", () => {
  it("disable freezes the org: no create, no redeem, no set-active; enable restores", async () => {
    const events: string[] = [];
    const { auth, org, ownerHeaders, adminHeaders } = await setupOrg({
      invite: {
        organization: {
          onOrgDisabled: () => {
            events.push("disabled");
          },
          onOrgEnabled: () => {
            events.push("enabled");
          }
        }
      }
    });
    const pending = await createInvite(auth, {
      body: {
        kind: "org-join",
        email: "frozen@acme.com",
        organizationId: org.id
      },
      headers: ownerHeaders
    });

    await api(auth).disableOrg({
      body: { organizationId: org.id },
      headers: adminHeaders
    });
    expect(events).toContain("disabled");

    expect(
      await errCode(
        createInvite(auth, {
          body: {
            kind: "org-join",
            email: "nope@acme.com",
            organizationId: org.id
          },
          headers: ownerHeaders
        })
      )
    ).toBe("ORG_DISABLED");
    expect(
      await errCode(
        api(auth).redeemInvite({
          body: { token: pending.token, password: PASSWORD }
        })
      )
    ).toBe("ORG_DISABLED");
    expect(
      await errCode(
        api(auth).setActiveOrganization({
          body: { organizationId: org.id },
          headers: ownerHeaders
        })
      )
    ).toBe("ORG_DISABLED");

    await api(auth).enableOrg({
      body: { organizationId: org.id },
      headers: adminHeaders
    });
    expect(events).toContain("enabled");
    const res = await api(auth).redeemInvite({
      body: { token: pending.token, password: PASSWORD }
    });
    expect(res.organization?.id).toBe(org.id);
  });

  it("delete removes the org, memberships, teams, and invites; users keep accounts", async () => {
    let deletedEvent: { bannedMembers: number } | null = null;
    const { auth, org, ownerHeaders, adminHeaders, owner } = await setupOrg({
      invite: {
        organization: {
          onOrgDeleted: (data) => {
            deletedEvent = { bannedMembers: data.bannedMembers };
          }
        }
      }
    });
    await api(auth).createTeam({
      body: { name: "Team", organizationId: org.id },
      headers: ownerHeaders
    });
    const member = await addOrgMember(auth, org.id, "m@acme.com");
    await createInvite(auth, {
      body: {
        kind: "org-join",
        email: "pending@acme.com",
        organizationId: org.id
      },
      headers: ownerHeaders
    });

    const res = await api(auth).deleteOrg({
      body: { organizationId: org.id },
      headers: adminHeaders
    });
    expect(res.deleted).toBe(true);
    expect(res.bannedMembers).toBe(0);
    expect(deletedEvent).toEqual({ bannedMembers: 0 });

    const ctx = await auth.$context;
    expect(
      await ctx.adapter.findOne({
        model: "organization",
        where: [{ field: "id", value: org.id }]
      })
    ).toBeNull();
    expect(
      await ctx.adapter.count({
        model: "member",
        where: [{ field: "organizationId", value: org.id }]
      })
    ).toBe(0);
    expect(
      await ctx.adapter.count({
        model: "invite",
        where: [{ field: "organizationId", value: org.id }]
      })
    ).toBe(0);

    // Member accounts are untouched by default.
    const ownerUser = (await findUserByEmail(auth, owner.email)) as {
      banned?: boolean | null;
    } | null;
    const memberUser = (await findUserByEmail(auth, member.user.email)) as {
      banned?: boolean | null;
    } | null;
    expect(ownerUser?.banned ?? false).toBeFalsy();
    expect(memberUser?.banned ?? false).toBeFalsy();
  });

  it("banMembers bans every member including the owner and revokes sessions", async () => {
    const { auth, org, adminHeaders, owner } = await setupOrg();
    const member = await addOrgMember(auth, org.id, "m@acme.com");
    const res = await api(auth).disableOrg({
      body: { organizationId: org.id, banMembers: true },
      headers: adminHeaders
    });
    expect(res.bannedMembers).toBe(2);

    const ownerUser = (await findUserByEmail(auth, owner.email)) as {
      banned?: boolean | null;
    } | null;
    const memberUser = (await findUserByEmail(auth, member.user.email)) as {
      banned?: boolean | null;
    } | null;
    expect(ownerUser?.banned).toBe(true);
    expect(memberUser?.banned).toBe(true);

    const ctx = await auth.$context;
    expect(
      await ctx.adapter.count({
        model: "session",
        where: [{ field: "userId", value: owner.id }]
      })
    ).toBe(0);
  });

  it("banning an inviter revokes their pending invites; banned users cannot redeem", async () => {
    const { auth, org, ownerHeaders, adminHeaders, owner } = await setupOrg();
    const pending = await createInvite(auth, {
      body: {
        kind: "org-join",
        email: "victim@acme.com",
        organizationId: org.id
      },
      headers: ownerHeaders
    });

    await api(auth).banUser({
      body: { userId: owner.id },
      headers: adminHeaders
    });
    expect((await findInviteRow(auth, pending.inviteId))?.status).toBe("cancelled");

    // A pre-created user banned directly cannot accept their invite.
    const other = await createInvite(auth, {
      body: { email: "banned-invitee@test.com" },
      headers: adminHeaders
    });
    const invitee = await findUserByEmail(auth, "banned-invitee@test.com");
    const ctx = await auth.$context;
    await ctx.adapter.update({
      model: "user",
      where: [{ field: "id", value: invitee!.id }],
      update: { banned: true }
    });
    expect(
      await errCode(
        api(auth).redeemInvite({
          body: { token: other.token, password: PASSWORD }
        })
      )
    ).toBe("USER_BANNED");
  });

  it("deleting an inviter removes pending invites; accepted invites keep the audit trail", async () => {
    const { auth, org, ownerHeaders, adminHeaders, owner } = await setupOrg();
    const accepted = await createInvite(auth, {
      body: {
        kind: "org-join",
        email: "kept@acme.com",
        organizationId: org.id
      },
      headers: ownerHeaders
    });
    await api(auth).redeemInvite({
      body: { token: accepted.token, password: PASSWORD }
    });
    const pending = await createInvite(auth, {
      body: {
        kind: "org-join",
        email: "gone@acme.com",
        organizationId: org.id
      },
      headers: ownerHeaders
    });

    await api(auth).removeUser({
      body: { userId: owner.id },
      headers: adminHeaders
    });

    expect(await findInviteRow(auth, pending.inviteId)).toBeNull();
    const kept = await findInviteRow(auth, accepted.inviteId);
    expect(kept?.status).toBe("accepted");
    expect(kept?.inviterEmail).toBe(owner.email);
  });
});

describe("org gating and compatibility", () => {
  it("org kinds are rejected when the organization block is not configured", async () => {
    const auth = await createTestAuth({
      plugins: [organization()]
    });
    const adminHeaders = await seedAdmin(auth);
    expect(
      await errCode(
        createInvite(auth, {
          body: {
            kind: "org-join",
            email: "x@test.com",
            organizationId: "whatever"
          },
          headers: adminHeaders
        })
      )
    ).toBe("ORG_FEATURES_DISABLED");
  });

  it("plugin init throws when organization options are set without the org plugin", async () => {
    await expect(createTestAuth({ invite: { organization: {} } })).rejects.toThrow(
      /organization plugin is not registered/
    );
  });

  it("plain app invites are unaffected by org integration", async () => {
    const { auth, adminHeaders } = await setupOrg();
    const created = await createInvite(auth, {
      body: { email: "plain@test.com", role: "partner" },
      headers: adminHeaders
    });
    const res = await api(auth).redeemInvite({
      body: { token: created.token, password: PASSWORD, name: "Plain" }
    });
    expect(res.organization).toBeNull();
    const user = await findUserByEmail(auth, "plain@test.com");
    expect((user as { role?: string } | null)?.role).toBe("partner");
    const ctx = await auth.$context;
    const member = await ctx.adapter.findOne({
      model: "member",
      where: [{ field: "userId", value: user!.id }]
    });
    expect(member).toBeNull();
  });

  it("roleGate drives allowUserToCreateOrganization", async () => {
    const auth = await createOrgAuth({
      org: {
        allowUserToCreateOrganization: roleGate(["admin", "org-creator"])
      }
    });
    await seedUser(auth, {
      email: "pleb@test.com",
      password: "pleb-pass-1234",
      role: "user"
    });
    const plebHeaders = await signInHeaders(auth, "pleb@test.com", "pleb-pass-1234");
    await expect(
      api(auth).createOrganization({
        body: { name: "Nope", slug: "nope" },
        headers: plebHeaders
      })
    ).rejects.toThrow();

    // Admin grants the role at runtime; the gate now opens.
    const ctx = await auth.$context;
    const pleb = await findUserByEmail(auth, "pleb@test.com");
    await ctx.adapter.update({
      model: "user",
      where: [{ field: "id", value: pleb!.id }],
      update: { role: "user,org-creator" }
    });
    const created = await api(auth).createOrganization({
      body: { name: "Yep", slug: "yep" },
      headers: plebHeaders
    });
    expect(created?.slug).toBe("yep");
  });
});

describe("existing-user activation invites (invite-only)", () => {
  it("org-join invite to an existing account skips pre-creation and redeems as activation", async () => {
    const { auth, ownerHeaders, org } = await setupOrg();
    const existing = await seedUser(auth, {
      email: "veteran@app.com",
      password: PASSWORD,
      name: "Veteran"
    });
    const created = await createInvite(auth, {
      body: { kind: "org-join", email: "veteran@app.com", organizationId: org.id },
      headers: ownerHeaders
    });
    expect((await findInviteRow(auth, created.inviteId))?.preCreatedUserId).toBeFalsy();

    const anon = await api(auth).getInvite({ query: { token: created.token } });
    expect(anon.nextAction).toBe("SIGN_IN");
    expect(anon.requiredFields).toEqual([]);

    const headers = await signInHeaders(auth, "veteran@app.com", PASSWORD);
    const signedIn = await api(auth).getInvite({
      query: { token: created.token },
      headers
    });
    expect(signedIn.nextAction).toBe("CONFIRM");

    const res = await api(auth).redeemInvite({
      body: { token: created.token },
      headers
    });
    expect(res.action).toBe("ACCEPTED");
    expect(res.organization?.id).toBe(org.id);
    expect(await getMemberRow(auth, existing.id, org.id)).toBeTruthy();
    expect((await findInviteRow(auth, created.inviteId))?.status).toBe("accepted");
  });

  it("activation enforces the private-invite email guard", async () => {
    const { auth, ownerHeaders, org } = await setupOrg();
    await seedUser(auth, { email: "target@app.com", password: PASSWORD });
    await seedUser(auth, { email: "sneak@app.com", password: PASSWORD });
    const created = await createInvite(auth, {
      body: { kind: "org-join", email: "target@app.com", organizationId: org.id },
      headers: ownerHeaders
    });
    const sneakHeaders = await signInHeaders(auth, "sneak@app.com", PASSWORD);
    expect(
      await errCode(
        api(auth).redeemInvite({
          body: { token: created.token },
          headers: sneakHeaders
        })
      )
    ).toBe("EMAIL_MISMATCH");
  });

  it("app-kind invite to an existing user still conflicts", async () => {
    const { auth, adminHeaders } = await setupOrg();
    await seedUser(auth, { email: "already@app.com", password: PASSWORD });
    expect(
      await errCode(
        createInvite(auth, {
          body: { kind: "app", email: "already@app.com" },
          headers: adminHeaders
        })
      )
    ).toBe("USER_ALREADY_EXISTS");
  });

  it("signed-in user redeeming a public org invite activates instead of conflicting", async () => {
    const { auth, ownerHeaders, org } = await setupOrg();
    const existing = await seedUser(auth, {
      email: "wanderer@app.com",
      password: PASSWORD
    });
    const created = await createInvite(auth, {
      body: {
        kind: "org-join",
        type: "public",
        organizationId: org.id,
        maxUses: 5
      },
      headers: ownerHeaders
    });
    const headers = await signInHeaders(auth, "wanderer@app.com", PASSWORD);
    const info = await api(auth).getInvite({
      query: { token: created.token },
      headers
    });
    expect(info.nextAction).toBe("CONFIRM");
    const res = await api(auth).redeemInvite({
      body: { token: created.token },
      headers
    });
    expect(res.action).toBe("ACCEPTED");
    expect(await getMemberRow(auth, existing.id, org.id)).toBeTruthy();
  });
});
