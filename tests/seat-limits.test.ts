import { APIError } from "better-auth/api";
import { organization } from "better-auth/plugins";
import { describe, expect, it, vi } from "vitest";
import {
  createInvite,
  createTestAuth,
  expireInvite,
  findInviteRow,
  seedUser,
  signInHeaders,
  type TestAuth
} from "./helpers";

const PASS = "Seats-Pass-6612";

// biome-ignore lint/suspicious/noExplicitAny: dynamic endpoint access
const api = (auth: TestAuth) => auth.api as any;

async function code(p: Promise<unknown>): Promise<string | undefined> {
  try {
    await p;
    return undefined;
  } catch (e) {
    const err = e as { body?: { code?: string }; status?: string };
    return err.body?.code ?? err.status ?? "THREW";
  }
}

async function setup(cfg?: {
  invite?: Record<string, unknown>;
  org?: Record<string, unknown>;
}) {
  const auth = await createTestAuth({
    plugins: [organization({ ...cfg?.org } as never)],
    invite: { mode: "open", organization: { ...cfg?.invite } },
    auth: { emailAndPassword: { enabled: true } }
  });
  await seedUser(auth, { email: "owner@acme.com", password: PASS });
  const ownerHeaders = await signInHeaders(auth, "owner@acme.com", PASS);
  const org = await api(auth).createOrganization({
    body: { name: "Acme", slug: "acme" },
    headers: ownerHeaders
  });
  return { auth, ownerHeaders, org };
}

async function members(auth: TestAuth, organizationId: string) {
  const ctx = await auth.$context;
  return await ctx.adapter.count({
    model: "member",
    where: [{ field: "organizationId", value: organizationId }]
  });
}

async function joinAs(auth: TestAuth, email: string) {
  await seedUser(auth, { email, password: PASS });
  return await signInHeaders(auth, email, PASS);
}

describe("seat limits (BE-LIB-06)", () => {
  it("parallel invite creation never reserves past the limit", async () => {
    const { auth, ownerHeaders, org } = await setup({ invite: { defaultSeatLimit: 2 } });
    const results = await Promise.allSettled(
      [1, 2, 3, 4, 5].map((i) =>
        api(auth).createInvite({
          body: { kind: "org-join", email: `p${i}@new.com`, organizationId: org.id },
          headers: ownerHeaders
        })
      )
    );
    expect(results.filter((r) => r.status === "fulfilled").length).toBeLessThanOrEqual(1);
    const usage = await api(auth).orgInviteUsage({
      query: { organizationId: org.id },
      headers: ownerHeaders
    });
    expect(usage.members + usage.pendingReserved).toBeLessThanOrEqual(2);
  });

  it("parallel redemptions never add members past the limit", async () => {
    const { auth, ownerHeaders, org } = await setup({ invite: { defaultSeatLimit: 3 } });
    const link = await api(auth).createInvite({
      body: { kind: "org-join", type: "public", organizationId: org.id, maxUses: 2 },
      headers: ownerHeaders
    });
    // Out-of-band growth fills the org behind the reservation's back.
    const ctx = await auth.$context;
    const extra = await seedUser(auth, { email: "side@acme.com" });
    await ctx.adapter.create({
      model: "member",
      data: { organizationId: org.id, userId: extra.id, role: "member", createdAt: new Date() }
    });
    const joiners = await Promise.all([joinAs(auth, "a@new.com"), joinAs(auth, "b@new.com")]);
    await Promise.allSettled(
      joiners.map((headers) => api(auth).redeemInvite({ body: { token: link.token }, headers }))
    );
    expect(await members(auth, org.id)).toBeLessThanOrEqual(3);
  });

  it("the org plugin's own invitations respect the seat limit", async () => {
    const { auth, ownerHeaders, org } = await setup({ invite: { defaultSeatLimit: 2 } });
    const invitee = await joinAs(auth, "native@new.com");
    const invitation = await api(auth).createInvitation({
      body: { email: "native@new.com", role: "member", organizationId: org.id },
      headers: ownerHeaders
    });
    // The org fills up before the invitation is accepted.
    await createInvite(auth, {
      body: { kind: "org-join", email: "first@new.com", organizationId: org.id },
      headers: ownerHeaders
    });
    expect(
      await code(
        api(auth).acceptInvitation({ body: { invitationId: invitation.id }, headers: invitee })
      )
    ).toBe("SEAT_LIMIT_REACHED");
    expect(
      await code(
        api(auth).createInvitation({
          body: { email: "late@new.com", role: "member", organizationId: org.id },
          headers: ownerHeaders
        })
      )
    ).toBe("SEAT_LIMIT_REACHED");
    expect(await members(auth, org.id)).toBe(1);
  });

  it("enforceSeatLimitOnOrgPlugin: false restores the old org plugin behavior", async () => {
    const { auth, ownerHeaders, org } = await setup({
      invite: { defaultSeatLimit: 1, enforceSeatLimitOnOrgPlugin: false }
    });
    const invitee = await joinAs(auth, "native@new.com");
    const invitation = await api(auth).createInvitation({
      body: { email: "native@new.com", role: "member", organizationId: org.id },
      headers: ownerHeaders
    });
    await api(auth).acceptInvitation({ body: { invitationId: invitation.id }, headers: invitee });
    expect(await members(auth, org.id)).toBe(2);
  });

  it("orgs without a limit: no seat queries, org plugin invitations untouched", async () => {
    const { auth, ownerHeaders, org } = await setup();
    const ctx = await auth.$context;
    const spy = vi.spyOn(ctx.adapter, "count");
    await createInvite(auth, {
      body: { kind: "org-join", email: "free@new.com", organizationId: org.id },
      headers: ownerHeaders
    });
    const invitee = await joinAs(auth, "native@new.com");
    const invitation = await api(auth).createInvitation({
      body: { email: "native@new.com", role: "member", organizationId: org.id },
      headers: ownerHeaders
    });
    const seatCounts = spy.mock.calls.filter(([arg]) => arg.model === "member").length;
    spy.mockRestore();
    expect(seatCounts).toBe(0);
    await api(auth).acceptInvitation({ body: { invitationId: invitation.id }, headers: invitee });
    expect(await members(auth, org.id)).toBe(2);
  });

  it("reviving an expired invite past the limit is undone", async () => {
    const { auth, ownerHeaders, org } = await setup({ invite: { defaultSeatLimit: 2 } });
    const old = await createInvite(auth, {
      body: { kind: "org-join", email: "old@new.com", organizationId: org.id },
      headers: ownerHeaders
    });
    await expireInvite(auth, old.inviteId);
    await createInvite(auth, {
      body: { kind: "org-join", email: "new@new.com", organizationId: org.id },
      headers: ownerHeaders
    });
    expect(
      await code(api(auth).resendInvite({ body: { inviteId: old.inviteId }, headers: ownerHeaders }))
    ).toBe("SEAT_LIMIT_REACHED");
    const row = await findInviteRow(auth, old.inviteId);
    expect(new Date(row?.expiresAt as string).getTime()).toBeLessThan(Date.now());
  });

  describe("org plugin rules (opt-in)", () => {
    it("runOrgPluginHooks: beforeAddMember can refuse, afterAddMember runs; off by default", async () => {
      for (const on of [false, true]) {
        const after = vi.fn();
        const { auth, ownerHeaders, org } = await setup({
          invite: { runOrgPluginHooks: on },
          org: {
            organizationHooks: {
              beforeAddMember: async ({ user }: { user: { email: string } }) => {
                if (user.email.startsWith("blocked")) {
                  throw new APIError("FORBIDDEN", { message: "app rule" });
                }
              },
              afterAddMember: after
            }
          }
        });
        // The org plugin's own createOrganization already called it once.
        after.mockClear();
        const link = await api(auth).createInvite({
          body: { kind: "org-join", type: "public", organizationId: org.id, maxUses: 5 },
          headers: ownerHeaders
        });
        const ok = await joinAs(auth, "ok@new.com");
        await api(auth).redeemInvite({ body: { token: link.token }, headers: ok });
        const blocked = await joinAs(auth, "blocked@new.com");
        const res = await code(
          api(auth).redeemInvite({ body: { token: link.token }, headers: blocked })
        );
        expect(res).toBe(on ? "FORBIDDEN" : undefined);
        expect(after).toHaveBeenCalledTimes(on ? 1 : 0);
        expect((await findInviteRow(auth, link.inviteId))?.useCount).toBe(on ? 1 : 2);
      }
    });

    it("respectMembershipLimit applies the org plugin's membershipLimit; off by default", async () => {
      for (const on of [false, true]) {
        const { auth, ownerHeaders, org } = await setup({
          invite: { respectMembershipLimit: on },
          org: { membershipLimit: 2 }
        });
        const link = await api(auth).createInvite({
          body: { kind: "org-join", type: "public", organizationId: org.id, maxUses: 5 },
          headers: ownerHeaders
        });
        await api(auth).redeemInvite({
          body: { token: link.token },
          headers: await joinAs(auth, "one@new.com")
        });
        const third = await code(
          api(auth).redeemInvite({
            body: { token: link.token },
            headers: await joinAs(auth, "two@new.com")
          })
        );
        expect(third).toBe(on ? "MEMBERSHIP_LIMIT_REACHED" : undefined);
        expect(await members(auth, org.id)).toBe(on ? 2 : 3);
      }
    });
  });
});
