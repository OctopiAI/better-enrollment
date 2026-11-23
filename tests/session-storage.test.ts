import { organization } from "better-auth/plugins";
import { describe, expect, it, vi } from "vitest";
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

const PASS = "Storage-Pass-7731";

// biome-ignore lint/suspicious/noExplicitAny: dynamic endpoint access
const api = (auth: TestAuth) => auth.api as any;

/** In-memory secondary storage, the shape Redis-backed apps use. */
function memoryStorage() {
  const store = new Map<string, string>();
  return {
    get: async (key: string) => store.get(key) ?? null,
    set: async (key: string, value: string) => {
      store.set(key, value);
    },
    delete: async (key: string) => {
      store.delete(key);
    }
  };
}

type Storage = "database" | "secondary" | "secondary+database";
const STORAGES: Storage[] = ["database", "secondary", "secondary+database"];

async function setup(storage: Storage, invite?: Record<string, unknown>) {
  const auth = await createTestAuth({
    plugins: [organization()],
    invite: { organization: {}, ...invite },
    auth: {
      ...(storage === "database" ? {} : { secondaryStorage: memoryStorage() }),
      ...(storage === "secondary+database" ? { session: { storeSessionInDatabase: true } } : {})
    } as never
  });
  const adminHeaders = await seedAdmin(auth);
  await seedUser(auth, { email: "owner@acme.com", password: PASS });
  const ownerHeaders = await signInHeaders(auth, "owner@acme.com", PASS);
  const org = await api(auth).createOrganization({
    body: { name: "Acme", slug: "acme" },
    headers: ownerHeaders
  });
  const m = await seedUser(auth, { email: "m@acme.com", password: PASS });
  await api(auth).addMember({ body: { userId: m.id, organizationId: org.id, role: "member" } });
  const memberHeaders = await signInHeaders(auth, "m@acme.com", PASS);
  await seedUser(auth, { email: "outsider@else.com", password: PASS });
  const outsiderHeaders = await signInHeaders(auth, "outsider@else.com", PASS);
  return { auth, adminHeaders, ownerHeaders, memberHeaders, outsiderHeaders, org };
}

describe("session storage (BE-LIB-03)", () => {
  for (const storage of STORAGES) {
    it(`${storage}: banMembers ends every member session and only those`, async () => {
      const { auth, adminHeaders, ownerHeaders, memberHeaders, outsiderHeaders, org } =
        await setup(storage);
      const res = await api(auth).disableOrg({
        body: { organizationId: org.id, banMembers: true },
        headers: adminHeaders
      });
      expect(res.bannedMembers).toBe(2);
      expect(await auth.api.getSession({ headers: memberHeaders })).toBeNull();
      expect(await auth.api.getSession({ headers: ownerHeaders })).toBeNull();
      expect(await auth.api.getSession({ headers: outsiderHeaders })).not.toBeNull();
      expect(await auth.api.getSession({ headers: adminHeaders })).not.toBeNull();
    });

    it(`${storage}: deleteOrg with banMembers completes`, async () => {
      const { auth, adminHeaders, memberHeaders, org } = await setup(storage);
      await api(auth).deleteOrg({
        body: { organizationId: org.id, banMembers: true },
        headers: adminHeaders
      });
      const ctx = await auth.$context;
      expect(
        await ctx.adapter.findOne({
          model: "organization",
          where: [{ field: "id", value: org.id }]
        })
      ).toBeNull();
      expect(await auth.api.getSession({ headers: memberHeaders })).toBeNull();
    });

    it(`${storage}: deleteOrg clears the deleted org from active sessions`, async () => {
      const { auth, adminHeaders, ownerHeaders, outsiderHeaders, org } = await setup(storage);
      await api(auth).setActiveOrganization({
        body: { organizationId: org.id },
        headers: ownerHeaders
      });
      await api(auth).deleteOrg({ body: { organizationId: org.id }, headers: adminHeaders });
      const owner = await auth.api.getSession({ headers: ownerHeaders });
      expect(owner).not.toBeNull();
      expect((owner?.session as { activeOrganizationId?: string | null }).activeOrganizationId ?? null).toBeNull();
      expect(await auth.api.getSession({ headers: outsiderHeaders })).not.toBeNull();
    });

    it(`${storage}: invite delete and expiry cleanup work on invites that own a shell`, async () => {
      const { auth, adminHeaders } = await setup(storage, { mode: "invite-only" });
      const a = await createInvite(auth, {
        body: { type: "private", email: "a@new.com" },
        headers: adminHeaders
      });
      await api(auth).deleteInvite({ body: { inviteId: a.inviteId }, headers: adminHeaders });
      expect(await findUserByEmail(auth, "a@new.com")).toBeFalsy();
      const b = await createInvite(auth, {
        body: { type: "private", email: "b@new.com" },
        headers: adminHeaders
      });
      await expireInvite(auth, b.inviteId);
      expect(await api(auth).cleanupExpiredInvites({ body: {} })).toEqual({ deleted: 1 });
      expect(await findUserByEmail(auth, "b@new.com")).toBeFalsy();
    });

    it(`${storage}: a failed passwordless redemption leaves no session`, async () => {
      const { auth, adminHeaders } = await setup(storage, {
        mode: "invite-only",
        passwordless: true,
        onInviteAccepted: () => {
          throw new Error("app hook failed");
        }
      });
      const inv = await createInvite(auth, {
        body: { type: "private", email: "late@new.com" },
        headers: adminHeaders
      });
      const ctx = await auth.$context;
      const minted = vi.spyOn(ctx.internalAdapter, "createSession");
      await expect(
        api(auth).redeemInvite({ body: { token: inv.token, name: "Late" } })
      ).rejects.toThrow();
      const userId = minted.mock.calls[0]![0] as string;
      expect(await ctx.internalAdapter.listSessions(userId)).toEqual([]);
      expect(await findUserByEmail(auth, "late@new.com")).toBeNull();
    });
  }

  it("database only: one session delete per page, not one per member", async () => {
    const { auth, adminHeaders, org } = await setup("database");
    for (let i = 0; i < 5; i++) {
      const u = await seedUser(auth, { email: `extra${i}@acme.com` });
      await api(auth).addMember({ body: { userId: u.id, organizationId: org.id, role: "member" } });
    }
    const ctx = await auth.$context;
    const spy = vi.spyOn(ctx.adapter, "deleteMany");
    await api(auth).disableOrg({
      body: { organizationId: org.id, banMembers: true },
      headers: adminHeaders
    });
    const sessionDeletes = spy.mock.calls.filter(([arg]) => arg.model === "session");
    spy.mockRestore();
    expect(sessionDeletes.length).toBe(1);
  });
});
