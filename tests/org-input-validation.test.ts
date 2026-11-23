import { createAuthClient } from "better-auth/client";
import { organization } from "better-auth/plugins";
import { describe, expect, it } from "vitest";
import { betterEnrollmentClient, isValidOrgSlug } from "../src/client";
import { createInvite, createTestAuth, findInviteRow, seedAdmin, type TestAuth } from "./helpers";

const PASS = "OrgInput-Pass-5150";

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

async function setup() {
  const auth = await createTestAuth({ plugins: [organization()], invite: { organization: {} } });
  const adminHeaders = await seedAdmin(auth);
  return { auth, adminHeaders };
}

/** A client whose network is this test's auth handler, counting requests. */
function clientFor(auth: TestAuth) {
  const sent = { count: 0 };
  const client = createAuthClient({
    baseURL: "http://localhost:3000",
    plugins: [betterEnrollmentClient()],
    fetchOptions: {
      customFetchImpl: async (input, init) => {
        sent.count++;
        return auth.handler(new Request(input, init));
      }
    }
  });
  return { client, sent };
}

describe("org name and slug rules (BE-LIB-16 d)", () => {
  it("the server rejects a malformed org-create redemption without using the invite", async () => {
    const { auth, adminHeaders } = await setup();
    const inv = await createInvite(auth, {
      body: { kind: "org-create", email: "founder@new.test" },
      headers: adminHeaders
    });
    const redeem = (organizationName: string, organizationSlug: string) =>
      api(auth).redeemInvite({
        body: { token: inv.token, password: PASS, name: "F", organizationName, organizationSlug }
      });
    expect(await code(redeem("Acme", "acme_corp"))).toBe("INVALID_ORG_SLUG");
    expect(await code(redeem("Acme", "-acme"))).toBe("INVALID_ORG_SLUG");
    expect(await code(redeem("Acme", "a".repeat(49)))).toBe("INVALID_ORG_SLUG");
    expect(await code(redeem("Acme\nCorp", "acme"))).toBe("INVALID_ORG_NAME");
    expect((await findInviteRow(auth, inv.inviteId))?.useCount).toBe(0);

    // Case and surrounding space are normalized, as before.
    const ok = await redeem("  Acme Corp ", " Acme-Corp ");
    expect(ok.organization.slug).toBe("acme-corp");
  });

  it("preset organizations and check-slug follow the same rules", async () => {
    const { auth, adminHeaders } = await setup();
    const preset = (organization: { name: string; slug?: string }) =>
      api(auth).createInvite({
        body: { kind: "org-create", email: `p${Math.random()}@new.test`, organization },
        headers: adminHeaders
      });
    expect(await code(preset({ name: "Acme", slug: "acme corp" }))).toBe("INVALID_ORG_SLUG");
    expect(await code(preset({ name: "Acme\u0000" }))).toBe("INVALID_ORG_NAME");

    const inv = await createInvite(auth, {
      body: { kind: "org-create", email: "slug@new.test" },
      headers: adminHeaders
    });
    expect(
      await code(api(auth).checkInviteSlug({ query: { token: inv.token, slug: "no_underscores" } }))
    ).toBe("INVALID_ORG_SLUG");
  });

  it("a taken preset slug gets a suffix that still fits the rule", async () => {
    const { auth, adminHeaders } = await setup();
    const long = "a".repeat(48);
    const first = await createInvite(auth, {
      body: { kind: "org-create", email: "one@new.test", organization: { name: "A", slug: long } },
      headers: adminHeaders
    });
    const second = await createInvite(auth, {
      body: { kind: "org-create", email: "two@new.test", organization: { name: "A", slug: long } },
      headers: adminHeaders
    });
    await api(auth).redeemInvite({ body: { token: first.token, password: PASS, name: "One" } });
    const res = await api(auth).redeemInvite({ body: { token: second.token, password: PASS, name: "Two" } });
    expect(res.organization.slug).not.toBe(long);
    expect(isValidOrgSlug(res.organization.slug)).toBe(true);
  });

  it("the client answers malformed input itself, with the server's error, and sends valid input", async () => {
    const { auth, adminHeaders } = await setup();
    const inv = await createInvite(auth, {
      body: { kind: "org-create", email: "client@new.test" },
      headers: adminHeaders
    });
    const { client, sent } = clientFor(auth);

    const bad = await client.invite.redeem({
      token: inv.token,
      password: PASS,
      name: "C",
      organizationName: "Acme",
      organizationSlug: "acme_corp"
    });
    expect(bad.error?.status).toBe(422);
    expect((bad.error as { code?: string } | null)?.code).toBe("INVALID_ORG_SLUG");
    const badCheck = await client.invite.checkSlug({ query: { token: inv.token, slug: "Bad Slug" } });
    expect((badCheck.error as { code?: string } | null)?.code).toBe("INVALID_ORG_SLUG");
    expect(sent.count).toBe(0);

    const badPost = await client.invite.verifySlug({ token: inv.token, slug: "Bad Slug" });
    expect((badPost.error as { code?: string } | null)?.code).toBe("INVALID_ORG_SLUG");
    expect(sent.count).toBe(0);

    const good = await client.invite.checkSlug({ query: { token: inv.token, slug: "acme" } });
    expect(good.error).toBeNull();
    const goodPost = await client.invite.verifySlug({ token: inv.token, slug: "acme" });
    expect(goodPost.error).toBeNull();
    const lookedUp = await client.invite.lookup({ token: inv.token });
    expect(lookedUp.data?.kind).toBe("org-create");
    expect(sent.count).toBe(3);
  });
});
