import { createAccessControl } from "better-auth/plugins/access";
import { adminAc, defaultStatements } from "better-auth/plugins/admin/access";
import { organization } from "better-auth/plugins";
import { describe, expect, it } from "vitest";
import { inviteAdminAc, inviteStatements, type BetterEnrollmentOptions } from "../src";
import {
  createInvite,
  createTestAuth,
  seedAdmin,
  seedUser,
  signInHeaders,
  type TestAuth
} from "./helpers";

// The shared permissions file an app would pass to both admin() and
// betterEnrollment(): admin statements plus the invite resource.
const statement = { ...defaultStatements, ...inviteStatements } as const;
const ac = createAccessControl(statement);
const adminRole = ac.newRole({ ...adminAc.statements, ...inviteAdminAc.statements });
const supportRole = ac.newRole({ invite: ["create", "list"] });
const userRole = ac.newRole({ invite: [] });
const roles = { admin: adminRole, support: supportRole, user: userRole };

// biome-ignore lint/suspicious/noExplicitAny: dynamic endpoint access
const api = (auth: TestAuth) => auth.api as any;

async function errCode(p: Promise<unknown>): Promise<string | undefined> {
  try {
    await p;
    return undefined;
  } catch (e) {
    const err = e as { body?: { code?: string }; code?: string };
    return err.body?.code ?? err.code;
  }
}

async function acAuth(invite?: Partial<BetterEnrollmentOptions>) {
  return createTestAuth({
    invite: { ac, roles, validRoles: ["user", "partner", "admin", "support"], ...invite }
  });
}

async function seedSupport(auth: TestAuth) {
  await seedUser(auth, {
    email: "support@test.com",
    password: "support-pass-123",
    role: "support"
  });
  return signInHeaders(auth, "support@test.com", "support-pass-123");
}

describe("app-level access control (admin plugin AC file)", () => {
  it("grants per-action permissions from the shared roles record", async () => {
    const auth = await acAuth();
    const supportHeaders = await seedSupport(auth);

    // invite:create and invite:list are granted.
    const created = await createInvite(auth, {
      body: { type: "private", email: "invitee@test.com", role: "user" },
      headers: supportHeaders
    });
    expect(created.inviteId).toBeTruthy();
    const list = await auth.api.listInvites({ query: {}, headers: supportHeaders });
    expect(list.total).toBe(1);

    // invite:resend, invite:cancel, and invite:delete are not.
    expect(
      await errCode(
        auth.api.resendInvite({ body: { inviteId: created.inviteId }, headers: supportHeaders })
      )
    ).toBe("NOT_ALLOWED_TO_MANAGE_INVITES");
    expect(
      await errCode(
        auth.api.revokeInvite({ body: { inviteId: created.inviteId }, headers: supportHeaders })
      )
    ).toBe("NOT_ALLOWED_TO_MANAGE_INVITES");
    expect(
      await errCode(
        auth.api.deleteInvite({ body: { inviteId: created.inviteId }, headers: supportHeaders })
      )
    ).toBe("NOT_ALLOWED_TO_MANAGE_INVITES");
  });

  it("keeps full management for a role granted every invite action", async () => {
    const auth = await acAuth();
    const adminHeaders = await seedAdmin(auth);
    const created = await createInvite(auth, {
      body: { type: "private", email: "invitee@test.com", role: "user" },
      headers: adminHeaders
    });
    const revoked = await auth.api.revokeInvite({
      body: { inviteId: created.inviteId },
      headers: adminHeaders
    });
    expect(revoked.revoked).toBe(true);
  });

  it("denies a role with no invite grants", async () => {
    const auth = await acAuth();
    await seedUser(auth, { email: "plain@test.com", password: "plain-pass-123", role: "user" });
    const headers = await signInHeaders(auth, "plain@test.com", "plain-pass-123");
    expect(
      await errCode(
        auth.api.createInvite({
          body: { type: "private", email: "x@test.com", role: "user" },
          headers
        })
      )
    ).toBe("NOT_ALLOWED_TO_MANAGE_INVITES");
  });

  it("takes priority over canManageInvites and adminRoles", async () => {
    const auth = await acAuth({
      canManageInvites: () => true,
      adminRoles: ["support"]
    });
    const supportHeaders = await seedSupport(auth);
    // The roles record gives support no invite:cancel; the legacy options
    // that would allow it are ignored.
    const created = await createInvite(auth, {
      body: { type: "private", email: "invitee@test.com", role: "user" },
      headers: supportHeaders
    });
    expect(
      await errCode(
        auth.api.revokeInvite({ body: { inviteId: created.inviteId }, headers: supportHeaders })
      )
    ).toBe("NOT_ALLOWED_TO_MANAGE_INVITES");
  });

  it("still honors the adminUserIds bypass, mirroring the admin plugin", async () => {
    // The options object keeps the array by reference, so the id can be
    // granted after the user exists.
    const adminUserIds: string[] = [];
    const auth = await acAuth({ adminUserIds });
    const user = await seedUser(auth, {
      email: "bypass@test.com",
      password: "bypass-pass-123",
      role: "user"
    });
    adminUserIds.push(user.id);
    const headers = await signInHeaders(auth, "bypass@test.com", "bypass-pass-123");
    const created = await createInvite(auth, {
      body: { type: "private", email: "invitee@test.com", role: "user" },
      headers
    });
    expect(created.inviteId).toBeTruthy();
  });

  it("falls back to defaultInviteRoles when only ac is provided", async () => {
    const auth = await createTestAuth({
      invite: { ac, validRoles: ["user", "admin"] }
    });
    const adminHeaders = await seedAdmin(auth);
    const created = await createInvite(auth, {
      body: { type: "private", email: "invitee@test.com", role: "user" },
      headers: adminHeaders
    });
    expect(created.inviteId).toBeTruthy();
    await seedUser(auth, { email: "plain@test.com", password: "plain-pass-123", role: "user" });
    const plainHeaders = await signInHeaders(auth, "plain@test.com", "plain-pass-123");
    expect(
      await errCode(
        auth.api.createInvite({
          body: { type: "private", email: "y@test.com", role: "user" },
          headers: plainHeaders
        })
      )
    ).toBe("NOT_ALLOWED_TO_MANAGE_INVITES");
  });

  it("authorizes against a custom resource name via permissionResource", async () => {
    const customStatement = {
      enrollment: ["create", "resend", "list", "cancel", "delete"]
    } as const;
    const customAcFile = createAccessControl(customStatement);
    const customRoles = {
      enroller: customAcFile.newRole({ enrollment: ["create", "list"] })
    };
    const auth = await createTestAuth({
      invite: {
        ac: customAcFile,
        roles: customRoles,
        permissionResource: "enrollment",
        validRoles: ["user", "enroller"]
      }
    });
    await seedUser(auth, { email: "enr@test.com", password: "enroll-pass-123", role: "enroller" });
    const headers = await signInHeaders(auth, "enr@test.com", "enroll-pass-123");
    const created = await createInvite(auth, {
      body: { type: "private", email: "invitee@test.com", role: "user" },
      headers
    });
    expect(created.inviteId).toBeTruthy();
    expect(
      await errCode(auth.api.revokeInvite({ body: { inviteId: created.inviteId }, headers }))
    ).toBe("NOT_ALLOWED_TO_MANAGE_INVITES");
  });

  it("leaves the legacy adminRoles gate untouched when no AC is passed", async () => {
    const auth = await createTestAuth({
      invite: { adminRoles: ["ops"], validRoles: ["user", "ops"] }
    });
    await seedUser(auth, { email: "ops@test.com", password: "ops-pass-1234", role: "ops" });
    const headers = await signInHeaders(auth, "ops@test.com", "ops-pass-1234");
    const created = await createInvite(auth, {
      body: { type: "private", email: "invitee@test.com", role: "user" },
      headers
    });
    expect(created.inviteId).toBeTruthy();
  });
});

describe("app-level access control with org platform endpoints", () => {
  it("gates platform org controls on invite:manage-orgs", async () => {
    const auth = await createTestAuth({
      plugins: [organization()],
      invite: { ac, roles, organization: {}, validRoles: ["user", "admin", "support"] }
    });
    const adminHeaders = await seedAdmin(auth);
    const supportHeaders = await seedSupport(auth);
    const owner = await seedUser(auth, {
      email: "owner@acme.com",
      password: "owner-pass-123"
    });
    void owner;
    const ownerHeaders = await signInHeaders(auth, "owner@acme.com", "owner-pass-123");
    const org = await api(auth).createOrganization({
      body: { name: "Acme", slug: "acme" },
      headers: ownerHeaders
    });

    // support holds create/list but not manage-orgs.
    expect(
      await errCode(
        api(auth).setOrgSeatLimit({
          body: { organizationId: org.id, seatLimit: 5 },
          headers: supportHeaders
        })
      )
    ).toBe("NOT_ALLOWED_TO_MANAGE_INVITES");

    const set = await api(auth).setOrgSeatLimit({
      body: { organizationId: org.id, seatLimit: 5 },
      headers: adminHeaders
    });
    expect(set.seatLimit).toBe(5);
  });
});

describe("org-level access control (org plugin AC file)", () => {
  const orgStatement = { invitation: ["create", "cancel"] } as const;
  const orgAcFile = createAccessControl(orgStatement);
  const orgRoles = {
    // Deliberately no owner entry: a provided record replaces the
    // defaults, exactly like the org plugin's own hasPermission.
    inviter: orgAcFile.newRole({ invitation: ["create"] }),
    member: orgAcFile.newRole({ invitation: [] })
  };

  async function setup() {
    const auth = await createTestAuth({
      plugins: [organization()],
      invite: {
        organization: { ac: orgAcFile, roles: orgRoles },
        validRoles: ["user", "admin"]
      }
    });
    await seedAdmin(auth);
    await seedUser(auth, { email: "owner@acme.com", password: "owner-pass-123" });
    const ownerHeaders = await signInHeaders(auth, "owner@acme.com", "owner-pass-123");
    const org = await api(auth).createOrganization({
      body: { name: "Acme", slug: "acme" },
      headers: ownerHeaders
    });
    return { auth, org, ownerHeaders };
  }

  async function addMember(auth: TestAuth, organizationId: string, email: string, role: string) {
    const user = await seedUser(auth, { email, password: "member-pass-123" });
    await api(auth).addMember({ body: { userId: user.id, organizationId, role } });
    return signInHeaders(auth, email, "member-pass-123");
  }

  it("a provided roles record replaces the built-in owner/admin defaults", async () => {
    const { auth, org, ownerHeaders } = await setup();
    // The owner role is absent from the record, so even the owner is denied.
    expect(
      await errCode(
        auth.api.createInvite({
          body: { type: "private", kind: "org-join", email: "a@acme.com", organizationId: org.id },
          headers: ownerHeaders
        })
      )
    ).toBe("ORG_INVITE_NOT_ALLOWED");
  });

  it("grants org-join creation to a custom role with invitation:create", async () => {
    const { auth, org } = await setup();
    const inviterHeaders = await addMember(auth, org.id, "inviter@acme.com", "inviter");
    const created = await createInvite(auth, {
      body: { type: "private", kind: "org-join", email: "b@acme.com", organizationId: org.id },
      headers: inviterHeaders
    });
    expect(created.inviteId).toBeTruthy();

    // invitation:cancel is not granted, so revoke is denied.
    expect(
      await errCode(
        auth.api.revokeInvite({ body: { inviteId: created.inviteId }, headers: inviterHeaders })
      )
    ).toBe("ORG_INVITE_NOT_ALLOWED");

    const memberHeaders = await addMember(auth, org.id, "plain@acme.com", "member");
    expect(
      await errCode(
        auth.api.createInvite({
          body: { type: "private", kind: "org-join", email: "c@acme.com", organizationId: org.id },
          headers: memberHeaders
        })
      )
    ).toBe("ORG_INVITE_NOT_ALLOWED");
  });
});
