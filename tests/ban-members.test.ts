import { organization } from "better-auth/plugins";
import { describe, expect, it } from "vitest";
import {
  createTestAuth,
  findUserByEmail,
  seedAdmin,
  seedUser,
  signInHeaders,
  type TestAuth
} from "./helpers";

const PASS = "BanMembers-Pass-8841";

// biome-ignore lint/suspicious/noExplicitAny: dynamic endpoint access
const api = (auth: TestAuth) => auth.api as any;

async function banned(auth: TestAuth, email: string) {
  return ((await findUserByEmail(auth, email)) as { banned?: boolean | null })?.banned === true;
}

async function setup() {
  const auth = await createTestAuth({
    plugins: [organization()],
    invite: { mode: "open", organization: {} },
    auth: { emailAndPassword: { enabled: true } }
  });
  const adminHeaders = await seedAdmin(auth);
  const admin = await findUserByEmail(auth, "admin@test.com");
  await seedUser(auth, { email: "owner@acme.com", password: PASS });
  const ownerHeaders = await signInHeaders(auth, "owner@acme.com", PASS);
  const org = await api(auth).createOrganization({
    body: { name: "Acme", slug: "acme" },
    headers: ownerHeaders
  });
  const add = async (userId: string, role = "member") =>
    api(auth).addMember({ body: { userId, organizationId: org.id, role } });
  // The acting admin and a second platform admin joined the org to investigate it.
  await add(admin!.id, "admin");
  const staff = await seedUser(auth, { email: "staff@test.com", password: PASS, role: "admin" });
  await add(staff.id, "admin");
  const m = await seedUser(auth, { email: "m@acme.com", password: PASS });
  await add(m.id);
  return { auth, adminHeaders, org };
}

describe("banMembers and platform staff (BE-LIB-08)", () => {
  it("never bans the caller or other platform admins, and reports them", async () => {
    const { auth, adminHeaders, org } = await setup();
    const res = await api(auth).disableOrg({
      body: { organizationId: org.id, banMembers: true },
      headers: adminHeaders
    });
    expect(res).toMatchObject({ bannedMembers: 2, skippedMembers: 2 });
    expect(await banned(auth, "admin@test.com")).toBe(false);
    expect(await banned(auth, "staff@test.com")).toBe(false);
    expect(await banned(auth, "owner@acme.com")).toBe(true);
    expect(await banned(auth, "m@acme.com")).toBe(true);
    // The caller can still act.
    expect(await auth.api.getSession({ headers: adminHeaders })).not.toBeNull();
  });

  it("enableOrg keeps bans by default and lifts exactly this org's with unbanMembers", async () => {
    const { auth, adminHeaders, org } = await setup();
    await api(auth).disableOrg({
      body: { organizationId: org.id, banMembers: true },
      headers: adminHeaders
    });
    // A ban for another reason must survive the unban.
    const ctx = await auth.$context;
    const m = await findUserByEmail(auth, "m@acme.com");
    await ctx.adapter.update({
      model: "user",
      where: [{ field: "id", value: m!.id }],
      update: { banReason: "spam" }
    });

    const kept = await api(auth).enableOrg({
      body: { organizationId: org.id },
      headers: adminHeaders
    });
    expect(kept.unbannedMembers).toBe(0);
    expect(await banned(auth, "owner@acme.com")).toBe(true);

    await api(auth).disableOrg({ body: { organizationId: org.id }, headers: adminHeaders });
    const lifted = await api(auth).enableOrg({
      body: { organizationId: org.id, unbanMembers: true },
      headers: adminHeaders
    });
    expect(lifted.unbannedMembers).toBe(1);
    expect(await banned(auth, "owner@acme.com")).toBe(false);
    expect(await banned(auth, "m@acme.com")).toBe(true);
  });
});
