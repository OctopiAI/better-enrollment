import { organization } from "better-auth/plugins";
import { describe, expect, it, vi } from "vitest";
import type { InvitesCancelledData } from "../src";
import {
  createInvite,
  createTestAuth,
  findInviteRow,
  seedAdmin,
  seedUser,
  signInHeaders,
  type TestAuth
} from "./helpers";

const PASS = "Lifecycle-Pass-5530";

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

async function setup(invite?: Record<string, unknown>) {
  const events: InvitesCancelledData[] = [];
  const auth = await createTestAuth({
    plugins: [organization()],
    invite: {
      mode: "open",
      organization: {},
      onInvitesCancelled: (d: InvitesCancelledData) => {
        events.push(d);
      },
      ...invite
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
  const lead = await seedUser(auth, { email: "lead@acme.com", password: PASS });
  await api(auth).addMember({ body: { userId: lead.id, organizationId: org.id, role: "admin" } });
  const leadHeaders = await signInHeaders(auth, "lead@acme.com", PASS);
  await seedUser(auth, { email: "friend@else.com", password: PASS });
  const friendHeaders = await signInHeaders(auth, "friend@else.com", PASS);
  return { auth, events, adminHeaders, ownerHeaders, org, lead, leadHeaders, friendHeaders };
}

async function orgLink(auth: TestAuth, orgId: string, headers: Headers, role = "admin") {
  return await api(auth).createInvite({
    body: { kind: "org-join", type: "public", organizationId: orgId, organizationRole: role, maxUses: 5 },
    headers
  });
}

describe("invites follow their inviter (BE-LIB-04)", () => {
  it("removing a member cancels its org links; nobody can redeem them", async () => {
    const { auth, events, ownerHeaders, org, lead, leadHeaders, friendHeaders } = await setup();
    const link = await orgLink(auth, org.id, leadHeaders);
    await api(auth).removeMember({
      body: { memberIdOrEmail: "lead@acme.com", organizationId: org.id },
      headers: ownerHeaders
    });
    expect((await findInviteRow(auth, link.inviteId))?.status).toBe("cancelled");
    expect(await code(api(auth).redeemInvite({ body: { token: link.token }, headers: friendHeaders }))).toBe(
      "INVITE_REVOKED"
    );
    expect(events).toContainEqual(
      expect.objectContaining({
        reason: "inviter-removed-from-org",
        inviteIds: [link.inviteId],
        userId: lead.id,
        organizationId: org.id,
        deleted: false
      })
    );
  });

  it("leaving cancels the leaver's org links", async () => {
    const { auth, events, org, leadHeaders } = await setup();
    const link = await orgLink(auth, org.id, leadHeaders);
    await api(auth).leaveOrganization({ body: { organizationId: org.id }, headers: leadHeaders });
    expect((await findInviteRow(auth, link.inviteId))?.status).toBe("cancelled");
    expect(events.at(-1)?.reason).toBe("inviter-left-org");
  });

  it("a role change cancels only what the new role may no longer create or grant", async () => {
    const { auth, ownerHeaders, org, lead, leadHeaders } = await setup();
    const adminLink = await orgLink(auth, org.id, leadHeaders, "admin");
    const memberLink = await orgLink(auth, org.id, leadHeaders, "member");
    // Still admin: nothing changes.
    await api(auth).updateMemberRole({
      body: { memberId: (await memberOf(auth, lead.id, org.id)).id, role: "admin", organizationId: org.id },
      headers: ownerHeaders
    });
    expect((await findInviteRow(auth, adminLink.inviteId))?.status).toBe("pending");
    // Demoted to member: no invitation:create, both go.
    await api(auth).updateMemberRole({
      body: { memberId: (await memberOf(auth, lead.id, org.id)).id, role: "member", organizationId: org.id },
      headers: ownerHeaders
    });
    expect((await findInviteRow(auth, adminLink.inviteId))?.status).toBe("cancelled");
    expect((await findInviteRow(auth, memberLink.inviteId))?.status).toBe("cancelled");
  });

  it("a ban from any admin path cancels the inviter's invites", async () => {
    const { auth, events, adminHeaders, org, lead, leadHeaders } = await setup();
    const link = await orgLink(auth, org.id, leadHeaders);
    await api(auth).adminUpdateUser({
      body: { userId: lead.id, data: { banned: true } },
      headers: adminHeaders
    });
    expect((await findInviteRow(auth, link.inviteId))?.status).toBe("cancelled");
    expect(events.at(-1)).toMatchObject({ reason: "inviter-banned", userId: lead.id });
  });

  it("banMembers cancels the banned members' invites", async () => {
    const { auth, adminHeaders, org, leadHeaders } = await setup();
    const link = await orgLink(auth, org.id, leadHeaders);
    await api(auth).disableOrg({
      body: { organizationId: org.id, banMembers: true },
      headers: adminHeaders
    });
    expect((await findInviteRow(auth, link.inviteId))?.status).toBe("cancelled");
  });

  it("deleting an inviter removes all its pending invites, past 100", async () => {
    const { auth, events, adminHeaders } = await setup();
    const staff = await seedUser(auth, { email: "staff@test.com", password: PASS, role: "admin" });
    const staffHeaders = await signInHeaders(auth, "staff@test.com", PASS);
    for (let i = 0; i < 130; i++) {
      await api(auth).createInvite({ body: { type: "public", maxUses: 1 }, headers: staffHeaders });
    }
    await api(auth).removeUser({ body: { userId: staff.id }, headers: adminHeaders });
    const ctx = await auth.$context;
    expect(
      await ctx.adapter.count({
        model: "invite",
        where: [{ field: "createdByUserId", value: staff.id }]
      })
    ).toBe(0);
    const deleted = events.filter((e) => e.reason === "inviter-deleted");
    expect(deleted.every((e) => e.deleted)).toBe(true);
    expect(deleted.reduce((n, e) => n + e.inviteIds.length, 0)).toBe(130);
  });

  it("deleting an invitee's account cancels invites addressed to it", async () => {
    const { auth, events, adminHeaders, org, leadHeaders, friendHeaders } = await setup();
    const friend = await auth.api.getSession({ headers: friendHeaders });
    const inv = await createInvite(auth, {
      body: { kind: "org-join", email: "friend@else.com", organizationId: org.id },
      headers: leadHeaders
    });
    await api(auth).removeUser({ body: { userId: friend!.user.id }, headers: adminHeaders });
    expect((await findInviteRow(auth, inv.inviteId))?.status).toBe("cancelled");
    expect(events.at(-1)?.reason).toBe("invitee-deleted");
  });

  it("the redemption backstop withdraws invites whose creator was banned behind the hooks' back", async () => {
    const { auth, events, org, lead, leadHeaders, friendHeaders } = await setup();
    const link = await orgLink(auth, org.id, leadHeaders);
    const ctx = await auth.$context;
    await ctx.adapter.update({
      model: "user",
      where: [{ field: "id", value: lead.id }],
      update: { banned: true }
    });
    const got = await api(auth).getInvite({ query: { token: link.token } });
    expect(got.nextAction).toBeNull();
    expect(await code(api(auth).redeemInvite({ body: { token: link.token }, headers: friendHeaders }))).toBe(
      "INVITE_REVOKED"
    );
    expect(events.at(-1)?.reason).toBe("inviter-inactive");
  });

  it("redemption withdraws invites whose creator lost its rights, unless revalidateInviterOnRedeem is false", async () => {
    for (const strict of [false, true]) {
      const { auth, org, lead, leadHeaders, friendHeaders } = await setup(
        strict ? {} : { revalidateInviterOnRedeem: false }
      );
      const link = await orgLink(auth, org.id, leadHeaders);
      const ctx = await auth.$context;
      await ctx.adapter.update({
        model: "member",
        where: [{ field: "userId", value: lead.id }],
        update: { role: "member" }
      });
      const res = await code(
        api(auth).redeemInvite({ body: { token: link.token }, headers: friendHeaders })
      );
      expect(res).toBe(strict ? "INVITE_REVOKED" : undefined);
    }
  });

  it("system invites attributed to a member do not depend on its org rights", async () => {
    const { auth, events, ownerHeaders, org, lead, friendHeaders } = await setup();
    const link = await api(auth).createSystemInvite({
      body: {
        kind: "org-join",
        type: "public",
        organizationId: org.id,
        maxUses: 5,
        inviter: { name: "Lead", email: "lead@acme.com", userId: lead.id }
      }
    });
    expect((await findInviteRow(auth, link.inviteId))?.createdBySystem).toBe(true);
    await api(auth).removeMember({
      body: { memberIdOrEmail: "lead@acme.com", organizationId: org.id },
      headers: ownerHeaders
    });
    expect(events).toEqual([]);
    const res = await api(auth).redeemInvite({ body: { token: link.token }, headers: friendHeaders });
    expect(res.action).toBe("ACCEPTED");
  });

  it("no false positives: unrelated updates and deletions leave invites alone, at no query cost", async () => {
    const { auth, events, adminHeaders, org, lead, leadHeaders } = await setup();
    const link = await orgLink(auth, org.id, leadHeaders);
    const ctx = await auth.$context;
    const spy = vi.spyOn(ctx.adapter, "findMany");
    await api(auth).adminUpdateUser({
      body: { userId: lead.id, data: { name: "Renamed" } },
      headers: adminHeaders
    });
    const inviteReads = spy.mock.calls.filter(([arg]) => arg.model === "invite");
    spy.mockRestore();
    expect(inviteReads.length).toBe(0);

    const other = await seedUser(auth, { email: "other@else.com", password: PASS });
    await api(auth).removeUser({ body: { userId: other.id }, headers: adminHeaders });
    expect((await findInviteRow(auth, link.inviteId))?.status).toBe("pending");
    expect(events).toEqual([]);
  });

  it("removing one invite's shell never cancels the same address's other invites", async () => {
    const { auth, adminHeaders, org, leadHeaders } = await setup({
      mode: "invite-only",
      allowOpenSignup: true
    });
    const app = await createInvite(auth, {
      body: { type: "private", email: "new@else.com" },
      headers: adminHeaders
    });
    const join = await createInvite(auth, {
      body: { kind: "org-join", email: "new@else.com", organizationId: org.id },
      headers: leadHeaders
    });
    await api(auth).revokeInvite({ body: { inviteId: app.inviteId }, headers: adminHeaders });
    expect((await findInviteRow(auth, join.inviteId))?.status).toBe("pending");
  });
});

async function memberOf(auth: TestAuth, userId: string, organizationId: string) {
  const ctx = await auth.$context;
  return (await ctx.adapter.findOne<{ id: string }>({
    model: "member",
    where: [
      { field: "userId", value: userId },
      { field: "organizationId", value: organizationId }
    ]
  }))!;
}
