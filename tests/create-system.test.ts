import { describe, expect, it } from "vitest";
import type { Invite, PrivateInvitationEmailData } from "../src/types";
import type { User } from "better-auth";
import { createTestAuth, findInviteRow, findUserByEmail, seedUser } from "./helpers";

async function captureError(fn: () => Promise<unknown>) {
  try {
    await fn();
    return null;
  } catch (e) {
    const err = e as { status?: string; body?: { message?: string; code?: string } };
    return { status: err.status, message: err.body?.message, code: err.body?.code };
  }
}

describe("system invite creation (server-only, no session)", () => {
  it("creates a private invite without any session; attribution falls back to System", async () => {
    const delivered: PrivateInvitationEmailData[] = [];
    const auth = await createTestAuth({
      invite: {
        sendPrivateInvitation: async (data) => {
          delivered.push(data);
        }
      }
    });
    const res = await auth.api.createSystemInvite({
      body: { type: "private", email: "invitee@test.com", name: "Invitee", role: "user" }
    });
    expect(res.inviteId).toBeTruthy();

    const row = await findInviteRow(auth, res.inviteId);
    expect(row?.createdByUserId).toBeNull();
    expect(row?.inviterName).toBe("System");
    expect(row?.inviterEmail).toBe("System");

    // Invite-only invariants still apply: the user is pre-created inert.
    const user = await findUserByEmail(auth, "invitee@test.com");
    expect(row?.preCreatedUserId).toBe(user!.id);

    expect(delivered).toHaveLength(1);
    expect(delivered[0]!.inviterName).toBe("System");
    expect(delivered[0]!.inviterEmail).toBe("System");
  });

  it("uses the configured appName as the inviter name", async () => {
    const auth = await createTestAuth({ auth: { appName: "Acme" } });
    const res = await auth.api.createSystemInvite({
      body: { type: "private", email: "invitee@test.com" }
    });
    const row = await findInviteRow(auth, res.inviteId);
    expect(row?.inviterName).toBe("Acme");
    expect(row?.inviterEmail).toBe("System");
  });

  it('treats an explicit "Better Auth" appName as absent', async () => {
    const auth = await createTestAuth({ auth: { appName: "Better Auth" } });
    const res = await auth.api.createSystemInvite({
      body: { type: "private", email: "invitee@test.com" }
    });
    const row = await findInviteRow(auth, res.inviteId);
    expect(row?.inviterName).toBe("System");
  });

  it("explicit inviter fields win over appName and System", async () => {
    const auth = await createTestAuth({ auth: { appName: "Acme" } });
    const res = await auth.api.createSystemInvite({
      body: {
        type: "private",
        email: "invitee@test.com",
        inviter: { name: "Billing", email: "billing@acme.com" }
      }
    });
    const row = await findInviteRow(auth, res.inviteId);
    expect(row?.inviterName).toBe("Billing");
    expect(row?.inviterEmail).toBe("billing@acme.com");
  });

  it("returns token and url for a public invite, like the session endpoint", async () => {
    const auth = await createTestAuth();
    const res = await auth.api.createSystemInvite({
      body: { type: "public", role: "user", maxUses: 5 }
    });
    expect(res.token).toBeTruthy();
    expect(res.url).toContain(res.token!);
  });

  it("keeps the session gate on the regular endpoint", async () => {
    const auth = await createTestAuth();
    const err = await captureError(() =>
      auth.api.createInvite({
        body: { type: "private", email: "invitee@test.com" },
        headers: new Headers()
      })
    );
    expect(err?.status).toBe("UNAUTHORIZED");
  });

  it("still enforces the email lock and existing-user conflict", async () => {
    const auth = await createTestAuth();
    await auth.api.createSystemInvite({
      body: { type: "private", email: "invitee@test.com" }
    });
    const locked = await captureError(() =>
      auth.api.createSystemInvite({
        body: { type: "private", email: "invitee@test.com" }
      })
    );
    expect(locked?.code).toBe("EMAIL_ALREADY_INVITED");

    await seedUser(auth, { email: "existing@test.com" });
    const conflict = await captureError(() =>
      auth.api.createSystemInvite({
        body: { type: "private", email: "existing@test.com" }
      })
    );
    expect(conflict?.code).toBe("USER_ALREADY_EXISTS");
  });

  it("still validates roles", async () => {
    const auth = await createTestAuth();
    const err = await captureError(() =>
      auth.api.createSystemInvite({
        body: { type: "private", email: "invitee@test.com", role: "superuser" }
      })
    );
    expect(err?.code).toBe("INVALID_ROLE");
  });

  it("is not reachable over HTTP", async () => {
    const auth = await createTestAuth();
    const res = await auth.handler(
      new Request("http://localhost:3000/api/auth/invite/create-system", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ type: "private", email: "invitee@test.com" })
      })
    );
    expect(res.status).toBe(404);
    expect(await findUserByEmail(auth, "invitee@test.com")).toBeNull();
  });

  it("fires onInviteCreated with a null admin", async () => {
    const seen: { invite: Invite; admin: User | null }[] = [];
    const auth = await createTestAuth({
      invite: {
        onInviteCreated: (data) => {
          seen.push(data);
        }
      }
    });
    await auth.api.createSystemInvite({
      body: { type: "private", email: "invitee@test.com" }
    });
    expect(seen).toHaveLength(1);
    expect(seen[0]!.admin).toBeNull();
  });
});
