import { organization } from "better-auth/plugins";
import Database from "better-sqlite3";
import { describe, expect, it } from "vitest";
import {
  cookieHeaders,
  createTestAuth,
  findUserByEmail,
  insertInviteRow,
  seedAdmin,
  seedUser,
  signInHeaders,
  type TestAuth
} from "./helpers";

const PASS = "Harden-Pass-3391";

async function code(p: Promise<unknown>): Promise<string | undefined> {
  try {
    await p;
    return undefined;
  } catch (e) {
    return (e as { body?: { code?: string } }).body?.code ?? "THREW";
  }
}

async function pendingFor(auth: TestAuth, email: string) {
  const ctx = await auth.$context;
  return await ctx.adapter.count({
    model: "invite",
    where: [
      { field: "email", value: email },
      { field: "status", value: "pending" }
    ]
  });
}

describe("BE-LIB-16 hardening", () => {
  it("(a) parallel creates never leave two pending invites in one scope", async () => {
    const auth = await createTestAuth({
      invite: { mode: "open" },
      auth: { emailAndPassword: { enabled: true, disableSignUp: false } }
    });
    const headers = await seedAdmin(auth);
    const results = await Promise.allSettled(
      [1, 2, 3, 4, 5].map(() =>
        auth.api.createInvite({ body: { type: "private", email: "race@corp.test" }, headers })
      )
    );
    expect(results.filter((r) => r.status === "fulfilled").length).toBeLessThanOrEqual(1);
    expect(await pendingFor(auth, "race@corp.test")).toBeLessThanOrEqual(1);
    // A refused attempt leaves nothing behind, so a retry goes through.
    if ((await pendingFor(auth, "race@corp.test")) === 0) {
      await auth.api.createInvite({ body: { type: "private", email: "race@corp.test" }, headers });
    }
    expect(await pendingFor(auth, "race@corp.test")).toBe(1);
  });

  it("(b) activation reads ban state from the database, not the cookie cache", async () => {
    const auth = await createTestAuth({
      invite: { mode: "open" },
      auth: {
        emailAndPassword: { enabled: true, disableSignUp: false },
        session: { cookieCache: { enabled: true, maxAge: 300 } }
      }
    });
    const admin = await seedAdmin(auth);
    await seedUser(auth, { email: "cached@corp.test", password: PASS });
    const signedIn = await signInHeaders(auth, "cached@corp.test", PASS);
    // The first session read issues the cache cookie; keep both.
    const read = await auth.api.getSession({ headers: signedIn, returnHeaders: true });
    const headers = new Headers({
      cookie: [signedIn.get("cookie"), cookieHeaders(read.headers).get("cookie")]
        .filter(Boolean)
        .join("; ")
    });
    expect(headers.get("cookie")).toContain("session_data");
    const user = await findUserByEmail(auth, "cached@corp.test");
    const ctx = await auth.$context;
    await ctx.adapter.update({
      model: "user",
      where: [{ field: "id", value: user!.id }],
      update: { banned: true }
    });
    const inv = await auth.api.createInvite({ body: { type: "public" }, headers: admin });
    expect(await code(auth.api.redeemInvite({ body: { token: inv.token! }, headers }))).toBe(
      "USER_BANNED"
    );
  });

  it("(c) deleting an org removes its custom roles, even without enforced foreign keys", async () => {
    // Databases that do not cascade (MongoDB, Prisma relationMode "prisma").
    const database = new Database(":memory:");
    database.pragma("foreign_keys = OFF");
    const auth = await createTestAuth({
      plugins: [organization({ dynamicAccessControl: { enabled: true } })],
      invite: { organization: {} },
      auth: { database }
    });
    const admin = await seedAdmin(auth);
    await seedUser(auth, { email: "owner@a.test", password: PASS });
    const owner = await signInHeaders(auth, "owner@a.test", PASS);
    // biome-ignore lint/suspicious/noExplicitAny: dynamic endpoint access
    const anyApi = auth.api as any;
    const org = await anyApi.createOrganization({ body: { name: "A", slug: "a" }, headers: owner });
    const ctx = await auth.$context;
    await ctx.adapter.create({
      model: "organizationRole",
      data: {
        organizationId: org.id,
        role: "recruiter",
        permission: JSON.stringify({ invitation: ["create"] }),
        createdAt: new Date(),
        updatedAt: new Date()
      }
    });
    await anyApi.deleteOrg({ body: { organizationId: org.id }, headers: admin });
    const left = await ctx.adapter.count({
      model: "organizationRole",
      where: [{ field: "organizationId", value: org.id }]
    });
    expect(left).toBe(0);
  });

  it("(f, g) warns at startup about request-derived link hosts and unhashed tokens", async () => {
    const warningsFor = async (auth: Record<string, unknown>, invite: Record<string, unknown>) => {
      const warnings: string[] = [];
      await createTestAuth({
        invite,
        auth: {
          ...auth,
          logger: {
            log: (level: string, message: string) => {
              if (level === "warn") warnings.push(message);
            }
          }
        }
      });
      return warnings.filter((w) => w.startsWith("better-enrollment"));
    };
    const host = (w: string[]) => w.filter((m) => m.includes("buildInviteUrl"));
    const hash = (w: string[]) => w.filter((m) => m.includes("hashTokens"));
    const saved = process.env.BETTER_AUTH_URL;
    delete process.env.BETTER_AUTH_URL;
    try {
      expect(host(await warningsFor({ baseURL: undefined }, {}))).toHaveLength(1);
      expect(
        host(await warningsFor({ baseURL: undefined }, { buildInviteUrl: () => "https://x.test" }))
      ).toHaveLength(0);
    } finally {
      if (saved !== undefined) process.env.BETTER_AUTH_URL = saved;
    }
    expect(host(await warningsFor({}, {}))).toHaveLength(0);
    expect(hash(await warningsFor({}, { hashTokens: false }))).toHaveLength(1);
    expect(hash(await warningsFor({}, {}))).toHaveLength(0);
  });

  it("fragment links and POST lookups keep the token out of URLs", async () => {
    const auth = await createTestAuth({ invite: { linkStyle: "fragment" } });
    const admin = await seedAdmin(auth);
    const inv = await auth.api.createInvite({ body: { type: "public" }, headers: admin });
    expect(inv.url).toBe(`http://localhost:3000/invite#token=${encodeURIComponent(inv.token!)}`);
    const byPost = await auth.api.lookupInvite({ body: { token: inv.token! } });
    const byGet = await auth.api.getInvite({ query: { token: inv.token! } });
    expect(byPost).toEqual(byGet);
    expect(byPost.nextAction).toBe("SIGN_UP");

    const res = await auth.handler(
      new Request("http://localhost:3000/api/auth/invite/lookup", {
        method: "POST",
        headers: { "content-type": "application/json", origin: "http://localhost:3000" },
        body: JSON.stringify({ token: inv.token })
      })
    );
    expect(res.status).toBe(200);
    expect(res.url).not.toContain(inv.token!);

    const query = await createTestAuth();
    const queryAdmin = await seedAdmin(query);
    const plain = await query.api.createInvite({ body: { type: "public" }, headers: queryAdmin });
    expect(plain.url).toContain("/invite?token=");
  });

  it("(e) publicInviteRoles limits what public links grant, old links included", async () => {
    const auth = await createTestAuth({
      plugins: [organization()],
      invite: { publicInviteRoles: ["user"], organization: { publicInviteRoles: ["member"] } }
    });
    const admin = await seedAdmin(auth);
    // biome-ignore lint/suspicious/noExplicitAny: dynamic endpoint access
    const anyApi = auth.api as any;
    expect(
      await code(anyApi.createInvite({ body: { type: "public", role: "admin" }, headers: admin }))
    ).toBe("ROLE_NOT_ALLOWED_FOR_PUBLIC_INVITE");
    await anyApi.createInvite({ body: { type: "public", role: "user" }, headers: admin });
    await anyApi.createInvite({
      body: { type: "private", role: "admin", email: "staff@corp.test" },
      headers: admin
    });

    // A link issued before the option was set no longer redeems.
    await insertInviteRow(auth, { token: "old-admin-link", type: "public", role: "admin" });
    expect(
      await code(
        anyApi.redeemInvite({
          body: { token: "old-admin-link", email: "x@corp.test", password: PASS, name: "X" }
        })
      )
    ).toBe("ROLE_NOT_ALLOWED_FOR_PUBLIC_INVITE");

    await seedUser(auth, { email: "owner@a.test", password: PASS });
    const owner = await signInHeaders(auth, "owner@a.test", PASS);
    const org = await anyApi.createOrganization({ body: { name: "A", slug: "a" }, headers: owner });
    expect(
      await code(
        anyApi.createInvite({
          body: { type: "public", kind: "org-join", organizationId: org.id, organizationRole: "admin", maxUses: 5 },
          headers: owner
        })
      )
    ).toBe("ROLE_NOT_ALLOWED_FOR_PUBLIC_INVITE");
    await anyApi.createInvite({
      body: { type: "public", kind: "org-join", organizationId: org.id, maxUses: 5 },
      headers: owner
    });
  });
});
