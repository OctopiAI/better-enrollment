import { organization } from "better-auth/plugins";
import { describe, expect, it } from "vitest";
import {
  createTestAuth,
  insertInviteRow,
  seedAdmin,
  seedUser,
  signInHeaders,
  type TestAuth
} from "./helpers";

const PASS = "Paged-Pass-2208";
const BASE = "http://localhost:3000/api/auth";

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

/** Records `n` uses on an invite, oldest first, and sets its useCount. */
async function recordUses(
  auth: TestAuth,
  inviteId: string,
  n: number,
  at: (i: number) => Date = (i) => new Date(Date.UTC(2026, 0, 1, 0, 0, i))
) {
  const ctx = await auth.$context;
  for (let i = 0; i < n; i++) {
    await ctx.adapter.create({
      model: "inviteUse",
      data: { inviteId, usedByUserId: "u", inviteeEmail: `u${i}@x.test`, usedAt: at(i) }
    });
  }
  await ctx.adapter.update({
    model: "invite",
    where: [{ field: "id", value: inviteId }],
    update: { useCount: n }
  });
}

describe("reads past 100 rows (BE-LIB-12)", () => {
  it("the list shows every use below the page budget and flags cut-short invites", async () => {
    const auth = await createTestAuth();
    const headers = await seedAdmin(auth);
    const busy = await auth.api.createInvite({ body: { type: "public" }, headers });
    await recordUses(auth, busy.inviteId, 120);
    let list = await auth.api.listInvites({ query: {}, headers });
    let row = list.invites.find((i) => i.id === busy.inviteId)!;
    expect(row.uses).toHaveLength(120);
    expect(row.usesTruncated).toBe(false);

    const quiet = await auth.api.createInvite({ body: { type: "public" }, headers });
    await recordUses(auth, busy.inviteId, 1000);
    await recordUses(auth, quiet.inviteId, 2, (i) => new Date(Date.UTC(2027, 0, 1, 0, 0, i)));
    list = await auth.api.listInvites({ query: {}, headers });
    row = list.invites.find((i) => i.id === busy.inviteId)!;
    const quietRow = list.invites.find((i) => i.id === quiet.inviteId)!;
    expect(row.usesTruncated).toBe(true);
    expect(quietRow.uses).toHaveLength(2);
    expect(quietRow.usesTruncated).toBe(false);
  });

  it("/invite/uses pages one invite's whole trail, newest first, ties included", async () => {
    const auth = await createTestAuth();
    const headers = await seedAdmin(auth);
    const inv = await auth.api.createInvite({ body: { type: "public" }, headers });
    // Every third use shares its instant with the next one.
    await recordUses(auth, inv.inviteId, 120, (i) => new Date(Date.UTC(2026, 0, 1, 0, 0, Math.floor(i / 3) * 3)));
    const seen: { id: string; usedAt: string | Date }[] = [];
    let cursor: string | undefined;
    const sizes: number[] = [];
    do {
      const page = await api(auth).listInviteUses({
        query: { inviteId: inv.inviteId, limit: 50, ...(cursor ? { cursor } : {}) },
        headers
      });
      sizes.push(page.uses.length);
      seen.push(...page.uses);
      cursor = page.nextCursor ?? undefined;
    } while (cursor);
    expect(sizes).toEqual([50, 50, 20]);
    expect(new Set(seen.map((u) => u.id)).size).toBe(120);
    const times = seen.map((u) => new Date(u.usedAt).getTime());
    expect(times).toEqual([...times].sort((a, b) => b - a));
  });

  it("/invite/uses reveals nothing to callers who may not list", async () => {
    const auth = await createTestAuth();
    const headers = await seedAdmin(auth);
    const inv = await auth.api.createInvite({ body: { type: "public" }, headers });
    await seedUser(auth, { email: "plain@corp.test", password: PASS });
    const plain = await signInHeaders(auth, "plain@corp.test", PASS);
    const known = await code(api(auth).listInviteUses({ query: { inviteId: inv.inviteId }, headers: plain }));
    const unknown = await code(api(auth).listInviteUses({ query: { inviteId: "nope" }, headers: plain }));
    expect(known).toBe("NOT_ALLOWED_TO_MANAGE_INVITES");
    expect(unknown).toBe(known);
    expect(await code(api(auth).listInviteUses({ query: { inviteId: "nope" }, headers }))).toBe(
      "INVITE_NOT_FOUND"
    );
  });

  it("the reset guard finds a shell's invite behind 150 other invites to the address", async () => {
    const resets: string[] = [];
    const auth = await createTestAuth({
      auth: {
        emailAndPassword: {
          enabled: true,
          disableSignUp: true,
          sendResetPassword: async ({ user }) => {
            resets.push(user.email);
          }
        }
      }
    });
    const ctx = await auth.$context;
    for (let i = 0; i < 150; i++) {
      const row = await insertInviteRow(auth, {
        token: `filler-${i}`,
        email: "deep@corp.test",
        role: "user",
        preCreatedUserId: "none"
      });
      await ctx.adapter.update({
        model: "invite",
        where: [{ field: "id", value: row.id as string }],
        update: { status: "cancelled", preCreatedUserId: null }
      });
    }
    await insertInviteRow(auth, { token: "owner", email: "deep@corp.test", role: "user" });
    const res = await auth.handler(
      new Request(`${BASE}/request-password-reset`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: "http://localhost:3000" },
        body: JSON.stringify({ email: "deep@corp.test" })
      })
    );
    expect(res.status).toBe(200);
    expect(resets).toEqual([]);
  });

  it("an org's custom role past the 100th is still a valid invite role", async () => {
    const auth = await createTestAuth({
      plugins: [organization({ dynamicAccessControl: { enabled: true } })],
      invite: { organization: {} }
    });
    await seedUser(auth, { email: "owner@acme.test", password: PASS });
    const owner = await signInHeaders(auth, "owner@acme.test", PASS);
    const org = await api(auth).createOrganization({ body: { name: "Acme", slug: "acme" }, headers: owner });
    const ctx = await auth.$context;
    for (let i = 0; i < 120; i++) {
      await ctx.adapter.create({
        model: "organizationRole",
        data: {
          organizationId: org.id,
          role: `custom-${i}`,
          permission: JSON.stringify({ invitation: [] }),
          createdAt: new Date(),
          updatedAt: new Date()
        }
      });
    }
    const res = await api(auth).createInvite({
      body: { kind: "org-join", email: "late@new.test", organizationId: org.id, organizationRole: "custom-119" },
      headers: owner
    });
    expect(res.inviteId).toBeTruthy();
  });
});
