import { organization } from "better-auth/plugins";
import { describe, expect, it } from "vitest";
import { createTestAuth, seedAdmin, seedUser, signInHeaders, type TestAuth } from "./helpers";

const PASS = "Disabled-Pass-2290";

// biome-ignore lint/suspicious/noExplicitAny: dynamic endpoint access
const api = (auth: TestAuth) => auth.api as any;

async function get(auth: TestAuth, path: string, headers: Headers) {
  const h = new Headers(headers);
  h.set("origin", "http://localhost:3000");
  const res = await auth.handler(
    new Request(`http://localhost:3000/api/auth${path}`, { method: "GET", headers: h })
  );
  return res.status;
}

async function setup() {
  const auth = await createTestAuth({
    plugins: [organization()],
    invite: { mode: "open", organization: {} },
    auth: { emailAndPassword: { enabled: true } }
  });
  const adminHeaders = await seedAdmin(auth);
  await seedUser(auth, { email: "owner@acme.com", password: PASS });
  const ownerHeaders = await signInHeaders(auth, "owner@acme.com", PASS);
  const acme = await api(auth).createOrganization({
    body: { name: "Acme", slug: "acme" },
    headers: ownerHeaders
  });
  const beta = await api(auth).createOrganization({
    body: { name: "Beta", slug: "beta" },
    headers: ownerHeaders
  });
  await api(auth).disableOrg({ body: { organizationId: acme.id }, headers: adminHeaders });
  return { auth, ownerHeaders, acme, beta };
}

describe("disabled organizations (BE-LIB-07)", () => {
  it("a decoy organizationId cannot hide a disabled org's slug", async () => {
    const { auth, ownerHeaders, beta } = await setup();
    for (const path of ["/organization/get-full-organization", "/organization/list-members"]) {
      expect(
        await get(auth, `${path}?organizationId=anything&organizationSlug=acme`, ownerHeaders)
      ).toBe(403);
      // A real, enabled id as the decoy does not help either.
      expect(
        await get(auth, `${path}?organizationId=${beta.id}&organizationSlug=acme`, ownerHeaders)
      ).toBe(403);
    }
  });

  it("no false positives: enabled orgs stay readable by id, slug, or both", async () => {
    const { auth, ownerHeaders, beta } = await setup();
    expect(
      await get(auth, `/organization/get-full-organization?organizationSlug=beta`, ownerHeaders)
    ).toBe(200);
    expect(
      await get(
        auth,
        `/organization/get-full-organization?organizationId=${beta.id}&organizationSlug=beta`,
        ownerHeaders
      )
    ).toBe(200);
    expect(await get(auth, "/organization/list", ownerHeaders)).toBe(200);
  });

  it("invitations by id, teams by teamId and the invitee's own list are covered too", async () => {
    const auth = await createTestAuth({
      plugins: [organization({ teams: { enabled: true } })],
      invite: { mode: "open", organization: {} },
      auth: { emailAndPassword: { enabled: true } }
    });
    const adminHeaders = await seedAdmin(auth);
    const owner = await seedUser(auth, { email: "owner@acme.com", password: PASS });
    await seedUser(auth, { email: "guest@else.com", password: PASS });
    const ownerHeaders = await signInHeaders(auth, "owner@acme.com", PASS);
    const guestHeaders = await signInHeaders(auth, "guest@else.com", PASS);
    const ids: Record<string, { invitation: string; team: string }> = {};
    for (const slug of ["acme", "beta"]) {
      const org = await api(auth).createOrganization({
        body: { name: slug, slug },
        headers: ownerHeaders
      });
      const invitation = await api(auth).createInvitation({
        body: { email: "guest@else.com", role: "member", organizationId: org.id },
        headers: ownerHeaders
      });
      const team = await api(auth).createTeam({
        body: { name: `${slug} team`, organizationId: org.id },
        headers: ownerHeaders
      });
      await api(auth).addTeamMember({
        body: { teamId: team.id, userId: owner.id },
        headers: ownerHeaders
      });
      ids[slug] = { invitation: invitation.id, team: team.id };
      if (slug === "acme") {
        await api(auth).disableOrg({ body: { organizationId: org.id }, headers: adminHeaders });
      }
    }
    const invitation = (slug: string) =>
      get(auth, `/organization/get-invitation?id=${ids[slug]!.invitation}`, guestHeaders);
    const team = (slug: string) =>
      get(auth, `/organization/list-team-members?teamId=${ids[slug]!.team}`, ownerHeaders);
    expect(await invitation("acme")).toBe(403);
    expect(await team("acme")).toBe(403);
    expect(await invitation("beta")).toBe(200);
    expect(await team("beta")).toBe(200);

    // The invitee's own list leaves out the disabled org's invitation.
    const h = new Headers(guestHeaders);
    h.set("origin", "http://localhost:3000");
    const res = await auth.handler(
      new Request("http://localhost:3000/api/auth/organization/list-user-invitations", {
        headers: h
      })
    );
    expect(res.status).toBe(200);
    const listed = (await res.json()) as { id: string }[];
    expect(listed.map((i) => i.id)).toEqual([ids.beta!.invitation]);
  });
});
