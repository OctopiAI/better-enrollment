import { organization } from "better-auth/plugins";
import { describe, expect, it } from "vitest";
import {
  createInvite,
  createTestAuth,
  seedAdmin,
  seedUser,
  signInHeaders,
  type TestAuth
} from "./helpers";

const PASS = "Probe-Pass-7731";

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

/** One pending, one revoked, one accepted invite, plus an id that does not exist. */
async function inviteStates(
  auth: TestAuth,
  headers: Headers,
  body: Record<string, unknown>,
  prefix = ""
) {
  const email = (s: string) => `${prefix}${s}@new.test`;
  const pending = await createInvite(auth, { body: { ...body, email: email("p") }, headers });
  const revoked = await createInvite(auth, { body: { ...body, email: email("r") }, headers });
  await auth.api.revokeInvite({ body: { inviteId: revoked.inviteId }, headers });
  const accepted = await createInvite(auth, { body: { ...body, email: email("a") }, headers });
  await auth.api.redeemInvite({ body: { token: accepted.token, password: PASS, name: "A" } });
  return [pending.inviteId, revoked.inviteId, accepted.inviteId, "no-such-invite"];
}

async function probe(auth: TestAuth, ids: string[], headers: Headers) {
  const codes = new Set<string | undefined>();
  for (const inviteId of ids) {
    codes.add(await code(auth.api.resendInvite({ body: { inviteId }, headers })));
    codes.add(await code(auth.api.revokeInvite({ body: { inviteId }, headers })));
    codes.add(await code(auth.api.deleteInvite({ body: { inviteId }, headers })));
    codes.add(await code(api(auth).listInviteUses({ query: { inviteId }, headers })));
  }
  return [...codes];
}

describe("probe resistance (BE-LIB-13)", () => {
  it("without orgs, a non-admin gets one answer for every invite id and state", async () => {
    const auth = await createTestAuth();
    const adminHeaders = await seedAdmin(auth);
    const ids = await inviteStates(auth, adminHeaders, { type: "private" });
    await seedUser(auth, { email: "plain@corp.test", password: PASS });
    const plain = await signInHeaders(auth, "plain@corp.test", PASS);
    expect(await probe(auth, ids, plain)).toEqual(["NOT_ALLOWED_TO_MANAGE_INVITES"]);
  });

  it("with orgs, outsiders and members without rights get one answer everywhere", async () => {
    const auth = await createTestAuth({
      plugins: [organization()],
      invite: { organization: {} }
    });
    const adminHeaders = await seedAdmin(auth);
    await seedUser(auth, { email: "owner@a.test", password: PASS });
    const owner = await signInHeaders(auth, "owner@a.test", PASS);
    const orgA = await api(auth).createOrganization({ body: { name: "A", slug: "a" }, headers: owner });
    const orgIds = await inviteStates(auth, owner, { kind: "org-join", organizationId: orgA.id });
    const appIds = (await inviteStates(auth, adminHeaders, { type: "private" }, "app-")).slice(0, 3);

    const plainMember = await seedUser(auth, { email: "member@a.test", password: PASS });
    await api(auth).addMember({ body: { userId: plainMember.id, organizationId: orgA.id, role: "member" } });
    const member = await signInHeaders(auth, "member@a.test", PASS);
    await seedUser(auth, { email: "owner@b.test", password: PASS });
    const otherOwner = await signInHeaders(auth, "owner@b.test", PASS);
    await api(auth).createOrganization({ body: { name: "B", slug: "b" }, headers: otherOwner });

    for (const headers of [member, otherOwner]) {
      expect(await probe(auth, [...orgIds, ...appIds], headers)).toEqual(["ORG_INVITE_NOT_ALLOWED"]);
    }
  });

  it("org inviters do not see internal user ids in the list; app admins do", async () => {
    const auth = await createTestAuth({
      plugins: [organization()],
      invite: { organization: {} }
    });
    const adminHeaders = await seedAdmin(auth);
    await seedUser(auth, { email: "owner@a.test", password: PASS });
    const owner = await signInHeaders(auth, "owner@a.test", PASS);
    const org = await api(auth).createOrganization({ body: { name: "A", slug: "a" }, headers: owner });
    await seedUser(auth, { email: "existing@corp.test", password: PASS });
    await createInvite(auth, {
      body: { kind: "org-join", email: "existing@corp.test", organizationId: org.id },
      headers: owner
    });
    await createInvite(auth, {
      body: { kind: "org-join", email: "fresh@corp.test", organizationId: org.id },
      headers: owner
    });
    const hidden = ["preCreatedUserId", "createdByUserId", "revokedByUserId"];
    const asOwner = await auth.api.listInvites({ query: { organizationId: org.id }, headers: owner });
    for (const row of asOwner.invites) {
      for (const key of hidden) expect(row).not.toHaveProperty(key);
    }
    const asAdmin = await auth.api.listInvites({ query: { organizationId: org.id }, headers: adminHeaders });
    for (const row of asAdmin.invites) {
      for (const key of hidden) expect(row).toHaveProperty(key);
    }
  });

  it("warns at startup when public links could register addresses without verification", async () => {
    const build = async (requireEmailVerification: boolean) => {
      const warnings: string[] = [];
      await createTestAuth({
        auth: {
          emailAndPassword: { enabled: true, disableSignUp: true, requireEmailVerification },
          logger: {
            log: (level: string, message: string) => {
              if (level === "warn") warnings.push(message);
            }
          }
        }
      });
      return warnings.filter((w) => w.includes("requireEmailVerification"));
    };
    expect(await build(false)).toHaveLength(1);
    expect(await build(true)).toHaveLength(0);
  });
});
