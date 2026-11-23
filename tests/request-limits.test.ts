import { describe, expect, it } from "vitest";
import type { BetterEnrollmentOptions } from "../src/types";
import {
  createInvite,
  createTestAuth,
  seedAdmin,
  sentInvites,
  type TestAuth
} from "./helpers";

const BASE = "http://localhost:3000/api/auth";
const YEAR = 365 * 24 * 60 * 60;

async function code(p: Promise<unknown>): Promise<string | undefined> {
  try {
    await p;
    return undefined;
  } catch (e) {
    return (e as { body?: { code?: string } }).body?.code ?? "THREW";
  }
}

async function setup(invite?: Partial<BetterEnrollmentOptions>) {
  const auth = await createTestAuth({ invite: { resendCooldown: 60, ...invite } });
  const adminHeaders = await seedAdmin(auth);
  return { auth, adminHeaders };
}

/** Moves the invite's last send into the past, as if time had passed. */
async function age(auth: TestAuth, inviteId: string, seconds: number) {
  const ctx = await auth.$context;
  await ctx.adapter.update({
    model: "invite",
    where: [{ field: "id", value: inviteId }],
    update: { updatedAt: new Date(Date.now() - seconds * 1000) }
  });
}

describe("invite sending limits (BE-LIB-11)", () => {
  it("a private invite is sent at most once per cooldown", async () => {
    const { auth, adminHeaders } = await setup();
    const inv = await createInvite(auth, {
      body: { type: "private", email: "target@corp.test" },
      headers: adminHeaders
    });
    const resend = () =>
      auth.api.resendInvite({ body: { inviteId: inv.inviteId }, headers: adminHeaders });
    expect(await code(resend())).toBe("RESEND_TOO_SOON");
    expect(sentInvites(auth)).toHaveLength(1);

    await age(auth, inv.inviteId, 61);
    const results = await Promise.allSettled([resend(), resend(), resend()]);
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    expect(sentInvites(auth)).toHaveLength(2);
  });

  it("resendCooldown: 0 turns the cooldown off; public invites never had one", async () => {
    const off = await setup({ resendCooldown: 0 });
    const priv = await createInvite(off.auth, {
      body: { type: "private", email: "a@corp.test" },
      headers: off.adminHeaders
    });
    await off.auth.api.resendInvite({ body: { inviteId: priv.inviteId }, headers: off.adminHeaders });

    const on = await setup();
    const pub = await createInvite(on.auth, {
      body: { type: "public" },
      headers: on.adminHeaders
    });
    await on.auth.api.resendInvite({ body: { inviteId: pub.inviteId }, headers: on.adminHeaders });
  });

  it("caps a requested lifetime and rejects one that is not a date", async () => {
    const { auth, adminHeaders } = await setup();
    const create = (expiresIn: number, email: string) =>
      auth.api.createInvite({ body: { type: "private", email, expiresIn }, headers: adminHeaders });
    expect(await code(create(100 * YEAR, "century@corp.test"))).toBe("EXPIRES_IN_TOO_LONG");
    const ok = await create(YEAR, "year@corp.test");
    await age(auth, ok.inviteId, 61);
    expect(
      await code(
        auth.api.resendInvite({
          body: { inviteId: ok.inviteId, expiresIn: 2 * YEAR },
          headers: adminHeaders
        })
      )
    ).toBe("EXPIRES_IN_TOO_LONG");

    const uncapped = await setup({ maxExpiresIn: null });
    const long = await uncapped.auth.api.createInvite({
      body: { type: "private", email: "long@corp.test", expiresIn: 2 * YEAR },
      headers: uncapped.adminHeaders
    });
    expect(long.expiresAt).toBeTruthy();
    expect(
      await code(
        uncapped.auth.api.createInvite({
          body: { type: "private", email: "overflow@corp.test", expiresIn: 9e12 },
          headers: uncapped.adminHeaders
        })
      )
    ).toBe("EXPIRES_IN_TOO_LONG");
  });

  it("caps a public invite's uses", async () => {
    const { auth, adminHeaders } = await setup();
    expect(
      await code(
        auth.api.createInvite({ body: { type: "public", maxUses: 10_001 }, headers: adminHeaders })
      )
    ).toBe("MAX_USES_TOO_HIGH");
    await auth.api.createInvite({ body: { type: "public", maxUses: 10_000 }, headers: adminHeaders });
    const uncapped = await setup({ maxPublicUses: null });
    await uncapped.auth.api.createInvite({
      body: { type: "public", maxUses: 1_000_000 },
      headers: uncapped.adminHeaders
    });
  });

  it("create and resend are rate limited per client over HTTP", async () => {
    const auth = await createTestAuth({
      invite: { resendCooldown: 0 },
      auth: { rateLimit: { enabled: true } } as never
    });
    const headers = new Headers(await seedAdmin(auth));
    headers.set("x-forwarded-for", "203.0.113.9");
    headers.set("content-type", "application/json");
    headers.set("origin", "http://localhost:3000");
    const post = (path: string, body: unknown) =>
      auth.handler(
        new Request(`${BASE}${path}`, { method: "POST", headers, body: JSON.stringify(body) })
      );
    const created: number[] = [];
    for (let i = 0; i < 21; i++) {
      created.push((await post("/invite/create", { type: "public" })).status);
    }
    expect(created.filter((s) => s === 200)).toHaveLength(20);
    expect(created[20]).toBe(429);

    const pub = await auth.api.createInvite({ body: { type: "public" }, headers });
    const resent: number[] = [];
    for (let i = 0; i < 11; i++) {
      resent.push((await post("/invite/resend", { inviteId: pub.inviteId })).status);
    }
    expect(resent.filter((s) => s === 200)).toHaveLength(10);
    expect(resent[10]).toBe(429);
  });
});
