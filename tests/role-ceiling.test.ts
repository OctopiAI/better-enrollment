import { admin, organization } from "better-auth/plugins";
import { createAccessControl } from "better-auth/plugins/access";
import { adminAc, defaultStatements, userAc } from "better-auth/plugins/admin/access";
import { describe, expect, it } from "vitest";
import { type BetterEnrollmentOptions, inviteAdminAc, inviteStatements } from "../src";
import {
  createInvite,
  createTestAuth,
  findUserByEmail,
  seedAdmin,
  seedUser,
  signInHeaders,
  type TestAuth
} from "./helpers";

const PASS = "Ceiling-Pass-4821";

const statement = { ...defaultStatements, ...inviteStatements } as const;
const ac = createAccessControl(statement);
const roles = {
  admin: ac.newRole({ ...adminAc.statements, ...inviteAdminAc.statements }),
  support: ac.newRole({ invite: ["create", "resend"] }),
  partner: ac.newRole({ ...userAc.statements, invite: [] }),
  user: ac.newRole({ ...userAc.statements, invite: [] })
};

// biome-ignore lint/suspicious/noExplicitAny: dynamic endpoint access
const api = (auth: TestAuth) => auth.api as any;

async function code(p: Promise<unknown>): Promise<string | undefined> {
  try {
    await p;
    return undefined;
  } catch (e) {
    return (e as { body?: { code?: string } }).body?.code ?? "THREW";
  }
}

async function appAuth(
  mode: "invite-only" | "open",
  invite?: Partial<BetterEnrollmentOptions>
) {
  // The admin plugin gets the same roles, as the docs prescribe.
  const auth = await createTestAuth({
    withoutAdmin: true,
    plugins: [admin({ ac, roles })],
    invite: { mode, ac, roles, validRoles: ["user", "partner", "support", "admin"], ...invite },
    auth: { emailAndPassword: { enabled: true, disableSignUp: mode === "invite-only" } }
  });
  const adminHeaders = await seedAdmin(auth);
  await seedUser(auth, { email: "support@test.com", password: PASS, role: "support" });
  const support = await signInHeaders(auth, "support@test.com", PASS);
  return { auth, adminHeaders, support };
}

describe("app role ceiling (BE-LIB-02)", () => {
  for (const mode of ["invite-only", "open"] as const) {
    it(`${mode}: invite:create alone grants only the default role`, async () => {
      const { auth, support } = await appAuth(mode);
      expect(
        await code(
          api(auth).createInvite({ body: { type: "public", role: "admin" }, headers: support })
        )
      ).toBe("ROLE_NOT_GRANTABLE");
      const plain = await api(auth).createInvite({
        body: { type: "public", maxUses: 1 },
        headers: support
      });
      expect(plain.token).toBeTruthy();
      // Its own default-role link adds nothing it may not assign.
      expect((await api(auth).redeemInvite({ body: { token: plain.token }, headers: support })).action).toBe(
        "ACCEPTED"
      );
      expect(((await findUserByEmail(auth, "support@test.com")) as { role?: string }).role).not.toContain(
        "admin"
      );
    });
  }

  it("every role in a comma list must be grantable", async () => {
    const { auth, support } = await appAuth("invite-only", { validRoles: undefined });
    expect(
      await code(
        api(auth).createInvite({ body: { type: "public", role: "user,admin" }, headers: support })
      )
    ).toBe("ROLE_NOT_GRANTABLE");
    expect(
      await code(
        api(auth).createInvite({ body: { type: "public", role: " admin " }, headers: support })
      )
    ).toBe("ROLE_NOT_GRANTABLE");
  });

  it("grantableRoles delegates granting to others, never to oneself", async () => {
    const { auth, support } = await appAuth("open", { grantableRoles: { support: ["partner"] } });
    expect(
      await code(
        api(auth).createInvite({ body: { type: "public", role: "admin" }, headers: support })
      )
    ).toBe("ROLE_NOT_GRANTABLE");
    const partner = await api(auth).createInvite({
      body: { type: "public", role: "partner", maxUses: 2 },
      headers: support
    });
    expect(
      await code(api(auth).redeemInvite({ body: { token: partner.token }, headers: support }))
    ).toBe("CANNOT_REDEEM_OWN_INVITE");

    await seedUser(auth, { email: "other@test.com", password: PASS });
    const other = await signInHeaders(auth, "other@test.com", PASS);
    expect((await api(auth).redeemInvite({ body: { token: partner.token }, headers: other })).action).toBe(
      "ACCEPTED"
    );
  });

  it("a user:set-role holder may grant and self-redeem any role", async () => {
    const { auth, adminHeaders } = await appAuth("open");
    const inv = await api(auth).createInvite({
      body: { type: "public", role: "partner", maxUses: 1 },
      headers: adminHeaders
    });
    expect((await api(auth).redeemInvite({ body: { token: inv.token }, headers: adminHeaders })).action).toBe(
      "ACCEPTED"
    );
  });

  it("canGrantRole overrides the ceiling", async () => {
    const { auth, support } = await appAuth("invite-only", {
      canGrantRole: (_user, role) => role === "partner"
    });
    expect(
      (await api(auth).createInvite({ body: { type: "public", role: "partner" }, headers: support }))
        .token
    ).toBeTruthy();
    expect(
      await code(api(auth).createInvite({ body: { type: "public", role: "admin" }, headers: support }))
    ).toBe("ROLE_NOT_GRANTABLE");
  });

  it("resending a public link requires the right to grant it; private resend does not", async () => {
    const { auth, adminHeaders, support } = await appAuth("invite-only");
    const pub = await api(auth).createInvite({
      body: { type: "public", role: "admin", maxUses: 1 },
      headers: adminHeaders
    });
    expect(
      await code(api(auth).resendInvite({ body: { inviteId: pub.inviteId }, headers: support }))
    ).toBe("ROLE_NOT_GRANTABLE");
    const priv = await createInvite(auth, {
      body: { type: "private", email: "staff@test.com", role: "admin" },
      headers: adminHeaders
    });
    const resent = await api(auth).resendInvite({
      body: { inviteId: priv.inviteId },
      headers: support
    });
    expect(resent.token).toBeUndefined();
  });

  it("default setup (admin plugin defaults, adminRoles gate) is unchanged for admins", async () => {
    const auth = await createTestAuth({ invite: { mode: "open" }, auth: { emailAndPassword: { enabled: true } } });
    const adminHeaders = await seedAdmin(auth);
    const inv = await api(auth).createInvite({
      body: { type: "public", role: "partner" },
      headers: adminHeaders
    });
    expect(inv.token).toBeTruthy();
  });
});

describe("grantableRolesCheck (startup)", () => {
  const strong = ac.newRole({ ...userAc.statements, user: ["list"], invite: [] });

  async function build(
    grantableRoles: Record<string, string[]>,
    grantableRolesCheck?: "warn" | "error" | "off"
  ) {
    const warnings: string[] = [];
    const rolesWithStrong = { ...roles, strong };
    await createTestAuth({
      withoutAdmin: true,
      plugins: [admin({ ac, roles: rolesWithStrong })],
      invite: { ac, roles: rolesWithStrong, grantableRoles, grantableRolesCheck },
      auth: {
        logger: {
          log: (level: string, message: string) => {
            if (level === "warn") warnings.push(message);
          }
        }
      }
    });
    return warnings.filter((w) => w.includes("grantable role"));
  }

  it("a subset role passes silently", async () => {
    expect(await build({ admin: ["partner"] })).toEqual([]);
  });

  it("a role with permissions the holder lacks is reported", async () => {
    const [warning] = await build({ support: ["strong"] }, "warn");
    expect(warning).toContain("support -> strong");
    expect(warning).toContain("user:list");
  });

  it("an undeclared role is reported as unverifiable", async () => {
    const [warning] = await build({ support: ["ghost"] }, "warn");
    expect(warning).toContain("cannot verify");
  });

  it('"error" (the default) refuses to start; "off" stays silent', async () => {
    await expect(build({ support: ["strong"] })).rejects.toThrow("support -> strong");
    await expect(build({ support: ["strong"] }, "error")).rejects.toThrow("support -> strong");
    expect(await build({ support: ["strong"] }, "off")).toEqual([]);
  });
});

describe("org role ceiling (BE-LIB-05)", () => {
  const orgAc = createAccessControl({
    invitation: ["create", "cancel"],
    member: ["update"]
  } as const);
  const orgRoles = {
    owner: orgAc.newRole({ invitation: ["create", "cancel"], member: ["update"] }),
    admin: orgAc.newRole({ invitation: ["create", "cancel"], member: ["update"] }),
    recruiter: orgAc.newRole({ invitation: ["create"] }),
    member: orgAc.newRole({ invitation: [] })
  };

  async function orgAuth(extra?: Record<string, unknown>) {
    const auth = await createTestAuth({
      plugins: [organization({ ac: orgAc, roles: orgRoles } as never)],
      // Some cases grant past the holder on purpose; the startup check has its own tests.
      invite: {
        mode: "open",
        grantableRolesCheck: "warn",
        organization: { ac: orgAc, roles: orgRoles, ...extra }
      },
      auth: { emailAndPassword: { enabled: true } }
    });
    const adminHeaders = await seedAdmin(auth);
    await seedUser(auth, { email: "owner@acme.com", password: PASS });
    const ownerHeaders = await signInHeaders(auth, "owner@acme.com", PASS);
    const org = await api(auth).createOrganization({
      body: { name: "Acme", slug: "acme" },
      headers: ownerHeaders
    });
    const recruiter = await seedUser(auth, { email: "recruiter@acme.com", password: PASS });
    await api(auth).addMember({
      body: { userId: recruiter.id, organizationId: org.id, role: "recruiter" }
    });
    const recruiterHeaders = await signInHeaders(auth, "recruiter@acme.com", PASS);
    return { auth, adminHeaders, ownerHeaders, org, recruiterHeaders };
  }

  it("invitation:create alone grants only the default org role", async () => {
    const { auth, org, recruiterHeaders } = await orgAuth();
    expect(
      await code(
        api(auth).createInvite({
          body: {
            kind: "org-join",
            email: "recruiter@acme.com",
            organizationId: org.id,
            organizationRole: "admin"
          },
          headers: recruiterHeaders
        })
      )
    ).toBe("ORG_ROLE_NOT_GRANTABLE");
    const plain = await api(auth).createInvite({
      body: { kind: "org-join", type: "public", organizationId: org.id, maxUses: 3 },
      headers: recruiterHeaders
    });
    expect(plain.token).toBeTruthy();
  });

  it("org grantableRoles delegates to others, never to oneself", async () => {
    const { auth, org, recruiterHeaders } = await orgAuth({
      grantableRoles: { recruiter: ["admin"] }
    });
    const inv = await createInvite(auth, {
      body: {
        kind: "org-join",
        email: "recruiter@acme.com",
        organizationId: org.id,
        organizationRole: "admin"
      },
      headers: recruiterHeaders
    });
    expect(
      await code(api(auth).redeemInvite({ body: { token: inv.token }, headers: recruiterHeaders }))
    ).toBe("CANNOT_REDEEM_OWN_INVITE");
  });

  it("public org links: recruiters and app admins cannot resend an admin link to themselves", async () => {
    const { auth, adminHeaders, ownerHeaders, org, recruiterHeaders } = await orgAuth();
    const link = await api(auth).createInvite({
      body: {
        kind: "org-join",
        type: "public",
        organizationId: org.id,
        organizationRole: "admin",
        maxUses: 2
      },
      headers: ownerHeaders
    });
    expect(
      await code(api(auth).resendInvite({ body: { inviteId: link.inviteId }, headers: recruiterHeaders }))
    ).toBe("ORG_ROLE_NOT_GRANTABLE");
    expect(
      await code(api(auth).resendInvite({ body: { inviteId: link.inviteId }, headers: adminHeaders }))
    ).toBe("ORG_ROLE_NOT_GRANTABLE");
    // The owner may.
    expect(
      (await api(auth).resendInvite({ body: { inviteId: link.inviteId }, headers: ownerHeaders })).token
    ).toBeTruthy();
  });

  it("canGrantOrgRole overrides the org ceiling", async () => {
    const { auth, org, recruiterHeaders } = await orgAuth({
      canGrantOrgRole: (_m: unknown, _o: unknown, role: string) => role === "admin"
    });
    const inv = await api(auth).createInvite({
      body: {
        kind: "org-join",
        type: "public",
        organizationId: org.id,
        organizationRole: "admin",
        maxUses: 1
      },
      headers: recruiterHeaders
    });
    expect(inv.token).toBeTruthy();
  });
});
