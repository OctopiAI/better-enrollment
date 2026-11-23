import { organization } from "better-auth/plugins";
import { describe, expect, it } from "vitest";
import type { BetterEnrollmentOptions } from "../src/types";
import {
  addLegacyShell,
  createInvite,
  createTestAuth,
  findInviteRow,
  findUserByEmail,
  seedAdmin,
  seedUser,
  signInHeaders,
  type TestAuth
} from "./helpers";

const PASS = "Rollback-Pass-4471";

// biome-ignore lint/suspicious/noExplicitAny: dynamic endpoint access
const api = (auth: TestAuth) => auth.api as any;

async function code(p: Promise<unknown>): Promise<string | undefined> {
  try {
    await p;
    return undefined;
  } catch (e) {
    const err = e as { body?: { code?: string; message?: string }; status?: string; message?: string };
    return err.body?.code ?? err.body?.message ?? err.message ?? err.status ?? "THREW";
  }
}

/** onInviteAccepted throws while `fail.on` is set: the last step of every redemption. */
function failingHook() {
  const fail = { on: false };
  const onInviteAccepted: BetterEnrollmentOptions["onInviteAccepted"] = async () => {
    if (fail.on) throw new Error("hook refused");
  };
  return { fail, onInviteAccepted };
}

async function setup(config?: { invite?: Partial<BetterEnrollmentOptions>; open?: boolean }) {
  const auth = await createTestAuth({
    plugins: [organization({ teams: { enabled: true } })],
    invite: {
      ...(config?.open ? { mode: "open" as const } : {}),
      ...config?.invite,
      organization: { ...config?.invite?.organization }
    },
    ...(config?.open ? { auth: { emailAndPassword: { enabled: true, disableSignUp: false } } } : {})
  });
  const adminHeaders = await seedAdmin(auth);
  await seedUser(auth, { email: "owner@acme.com", password: PASS });
  const ownerHeaders = await signInHeaders(auth, "owner@acme.com", PASS);
  const org = await api(auth).createOrganization({
    body: { name: "Acme", slug: "acme" },
    headers: ownerHeaders
  });
  return { auth, adminHeaders, ownerHeaders, org };
}

async function rows(auth: TestAuth, model: string, field: string, value: string) {
  const ctx = await auth.$context;
  return await ctx.adapter.findMany<Record<string, unknown>>({
    model,
    where: [{ field, value }]
  });
}

async function signInStatus(auth: TestAuth, email: string, password: string) {
  const res = await auth.handler(
    new Request("http://localhost:3000/api/auth/sign-in/email", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password })
    })
  );
  return res.status;
}

describe("failed redemptions leave nothing behind (BE-LIB-09)", () => {
  it("a seat refusal writes no login, no verification and no use; a retry then succeeds", async () => {
    const { auth, ownerHeaders, org } = await setup({
      invite: { organization: { defaultSeatLimit: 2 } }
    });
    const inv = await createInvite(auth, {
      body: { kind: "org-join", email: "late@new.com", organizationId: org.id },
      headers: ownerHeaders
    });
    const filler = await seedUser(auth, { email: "filler@acme.com" });
    const member = await api(auth).addMember({
      body: { userId: filler.id, organizationId: org.id, role: "member" }
    });

    const refused = await code(
      api(auth).redeemInvite({ body: { token: inv.token, password: PASS, name: "Late" } })
    );
    expect(refused).toBe("SEAT_LIMIT_REACHED");
    expect(await findUserByEmail(auth, "late@new.com")).toBeNull();
    expect(await signInStatus(auth, "late@new.com", PASS)).toBe(401);
    expect(await rows(auth, "inviteUse", "inviteId", inv.inviteId)).toHaveLength(0);
    const row = await findInviteRow(auth, inv.inviteId);
    expect(row?.status).toBe("pending");
    expect(row?.useCount).toBe(0);

    await api(auth).removeMember({
      body: { memberIdOrEmail: member.id, organizationId: org.id },
      headers: ownerHeaders
    });
    const ok = await api(auth).redeemInvite({
      body: { token: inv.token, password: PASS, name: "Late" }
    });
    expect(ok.action).toBe("ACCEPTED");
    expect(await signInStatus(auth, "late@new.com", PASS)).toBe(200);
  });

  it("a failure at the last step undoes the member, the login, the use and the user fields", async () => {
    const { fail, onInviteAccepted } = failingHook();
    const { auth, ownerHeaders, org } = await setup({ invite: { onInviteAccepted } });
    const inv = await createInvite(auth, {
      body: { kind: "org-join", email: "undo@new.com", organizationId: org.id },
      headers: ownerHeaders
    });
    const members = (await rows(auth, "member", "organizationId", org.id)).length;
    const accounts = (await rows(auth, "account", "providerId", "credential")).length;
    fail.on = true;
    expect(
      await code(api(auth).redeemInvite({ body: { token: inv.token, password: PASS, name: "Undo" } }))
    ).toBe("hook refused");

    expect(await findUserByEmail(auth, "undo@new.com")).toBeNull();
    expect(await rows(auth, "account", "providerId", "credential")).toHaveLength(accounts);
    expect(await rows(auth, "member", "organizationId", org.id)).toHaveLength(members);
    expect(await rows(auth, "inviteUse", "inviteId", inv.inviteId)).toHaveLength(0);
    expect((await findInviteRow(auth, inv.inviteId))?.status).toBe("pending");

    fail.on = false;
    const ok = await api(auth).redeemInvite({
      body: { token: inv.token, password: PASS, name: "Undo" }
    });
    expect(ok.action).toBe("ACCEPTED");
  });

  it("a failed org-create removes the organization it founded", async () => {
    const { fail, onInviteAccepted } = failingHook();
    const { auth, adminHeaders } = await setup({ invite: { onInviteAccepted } });
    const inv = await createInvite(auth, {
      body: { kind: "org-create", email: "founder@newco.com" },
      headers: adminHeaders
    });
    fail.on = true;
    const body = {
      token: inv.token,
      password: PASS,
      name: "Founder",
      organizationName: "NewCo",
      organizationSlug: "newco"
    };
    expect(await code(api(auth).redeemInvite({ body }))).toBe("hook refused");
    expect(await rows(auth, "organization", "slug", "newco")).toHaveLength(0);
    expect(await findUserByEmail(auth, "founder@newco.com")).toBeNull();

    fail.on = false;
    const ok = await api(auth).redeemInvite({ body });
    expect(ok.organization?.slug).toBe("newco");
  });

  it("a failed public sign-up deletes the user and returns the use", async () => {
    const { fail, onInviteAccepted } = failingHook();
    const { auth, adminHeaders } = await setup({ invite: { onInviteAccepted } });
    const inv = await createInvite(auth, {
      body: { type: "public", kind: "org-create", maxUses: 1 },
      headers: adminHeaders
    });
    fail.on = true;
    const body = {
      token: inv.token,
      email: "pub@new.com",
      password: PASS,
      name: "Pub",
      organizationName: "PubCo",
      organizationSlug: "pubco"
    };
    expect(await code(api(auth).redeemInvite({ body }))).toBe("hook refused");
    expect(await findUserByEmail(auth, "pub@new.com")).toBeNull();
    expect(await rows(auth, "organization", "slug", "pubco")).toHaveLength(0);
    const row = await findInviteRow(auth, inv.inviteId);
    expect(row?.useCount).toBe(0);
    expect(row?.status).toBe("pending");
  });

  it("a failed activation keeps the old role and adds no member", async () => {
    const { fail, onInviteAccepted } = failingHook();
    const { auth, ownerHeaders, org } = await setup({ open: true, invite: { onInviteAccepted } });
    await seedUser(auth, { email: "joiner@new.com", password: PASS });
    const headers = await signInHeaders(auth, "joiner@new.com", PASS);
    const inv = await createInvite(auth, {
      body: { type: "public", kind: "org-join", organizationId: org.id, maxUses: 5 },
      headers: ownerHeaders
    });
    const before = await findUserByEmail(auth, "joiner@new.com");
    fail.on = true;
    expect(await code(api(auth).redeemInvite({ body: { token: inv.token }, headers }))).toBe(
      "hook refused"
    );
    const after = await findUserByEmail(auth, "joiner@new.com");
    expect((after as { role?: string } | null)?.role).toBe((before as { role?: string } | null)?.role);
    expect(await rows(auth, "member", "userId", after!.id)).toHaveLength(0);
    expect((await findInviteRow(auth, inv.inviteId))?.useCount).toBe(0);
  });

  it("an own shell that already holds a login asks for sign-in, then activates", async () => {
    const { auth, ownerHeaders, org } = await setup();
    const inv = await createInvite(auth, {
      body: { kind: "org-join", email: "residue@new.com", organizationId: org.id },
      headers: ownerHeaders
    });
    // What a failed 0.x attempt left on a pre-created user.
    const ctx = await auth.$context;
    const shell = await addLegacyShell(auth, inv.inviteId);
    await ctx.adapter.create({
      model: "account",
      data: {
        userId: shell!.id,
        providerId: "credential",
        accountId: shell!.id,
        password: await ctx.password.hash(PASS),
        createdAt: new Date(),
        updatedAt: new Date()
      }
    });
    await ctx.adapter.update({
      model: "user",
      where: [{ field: "id", value: shell!.id }],
      update: { emailVerified: true, name: "Residue" }
    });

    const info = await api(auth).getInvite({ query: { token: inv.token } });
    expect(info.nextAction).toBe("SIGN_IN");
    const takeover = await api(auth).redeemInvite({
      body: { token: inv.token, password: "Other-Pass-0000", name: "X" }
    });
    expect(takeover.action).toBe("SIGN_IN_REQUIRED");
    expect(await signInStatus(auth, "residue@new.com", "Other-Pass-0000")).toBe(401);

    const headers = await signInHeaders(auth, "residue@new.com", PASS);
    const ok = await api(auth).redeemInvite({ body: { token: inv.token }, headers });
    expect(ok.action).toBe("ACCEPTED");
    expect(await rows(auth, "member", "userId", shell!.id)).toHaveLength(1);
  });
});
