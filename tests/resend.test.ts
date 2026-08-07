import { describe, expect, it, vi } from "vitest";
import {
  createInvite,
  createTestAuth,
  expireInvite,
  findUserByEmail,
  seedAdmin,
  seedUser,
  signInHeaders,
  sentInvites
} from "./helpers";

async function captureError(fn: () => Promise<unknown>) {
  try {
    await fn();
    return null;
  } catch (e) {
    const err = e as { status?: string; body?: { message?: string; code?: string } };
    return { status: err.status, message: err.body?.message, code: err.body?.code };
  }
}

describe("resending invitations", () => {
  it("private resend: old link dies, new link delivered and redeemable, hook fires", async () => {
    const onInviteResent = vi.fn();
    const auth = await createTestAuth({ invite: { onInviteResent } });
    const headers = await seedAdmin(auth);
    const first = await createInvite(auth, {
      body: { type: "private", email: "resend@test.com", name: "Ada" },
      headers
    });

    const res = await auth.api.resendInvite({
      body: { inviteId: first.inviteId },
      headers
    });
    expect(res.inviteId).toBe(first.inviteId);
    expect("token" in res).toBe(false);

    // The new link went out through the same delivery path.
    const sent = sentInvites(auth);
    expect(sent).toHaveLength(2);
    const fresh = sent[sent.length - 1]!;
    expect(fresh.email).toBe("resend@test.com");
    expect(fresh.token).not.toBe(first.token);
    expect(onInviteResent).toHaveBeenCalledOnce();

    // Old token is dead, new one redeems.
    const stale = await captureError(() =>
      auth.api.acceptInvite({ body: { token: first.token, password: "password123" } })
    );
    expect(stale?.code).toBe("INVITE_NOT_FOUND");
    await auth.api.acceptInvite({ body: { token: fresh.token, password: "password123" } });
    const user = await findUserByEmail(auth, "resend@test.com");
    expect(user?.emailVerified).toBe(true);
  });

  it("revives an expired invite with a fresh expiry", async () => {
    const auth = await createTestAuth();
    const headers = await seedAdmin(auth);
    const first = await createInvite(auth, {
      body: { type: "private", email: "late@test.com" },
      headers
    });
    await expireInvite(auth, first.inviteId);
    const expired = await captureError(() =>
      auth.api.acceptInvite({ body: { token: first.token, password: "password123" } })
    );
    expect(expired?.code).toBe("INVITE_EXPIRED");

    const res = await auth.api.resendInvite({ body: { inviteId: first.inviteId }, headers });
    expect(res.expiresAt && res.expiresAt > new Date()).toBe(true);

    const fresh = sentInvites(auth)[1]!;
    await auth.api.acceptInvite({ body: { token: fresh.token, password: "password123" } });
    const user = await findUserByEmail(auth, "late@test.com");
    expect(user?.emailVerified).toBe(true);
  });

  it("public resend: rotates the link, preserves the remaining uses, returns it once", async () => {
    const auth = await createTestAuth();
    const headers = await seedAdmin(auth);
    const first = await createInvite(auth, {
      body: { type: "public", role: "user", maxUses: 2 },
      headers
    });
    await auth.api.acceptInvite({
      body: { token: first.token, password: "password123", email: "one@test.com" }
    });

    const res = await auth.api.resendInvite({ body: { inviteId: first.inviteId }, headers });
    expect(res.token).toBeTruthy();
    expect(res.token).not.toBe(first.token);
    expect(res.url).toContain(res.token!);

    const stale = await captureError(() =>
      auth.api.acceptInvite({
        body: { token: first.token, password: "password123", email: "two@test.com" }
      })
    );
    expect(stale?.code).toBe("INVITE_NOT_FOUND");

    // One of the two uses was consumed before the rotation and stays spent.
    await auth.api.acceptInvite({
      body: { token: res.token!, password: "password123", email: "two@test.com" }
    });
    // The cap is reached, so the invite settles to accepted.
    const exhausted = await captureError(() =>
      auth.api.acceptInvite({
        body: { token: res.token!, password: "password123", email: "three@test.com" }
      })
    );
    expect(exhausted?.code).toBe("INVITE_ALREADY_USED");
  });

  it("accepted and revoked invites cannot be resent", async () => {
    const auth = await createTestAuth();
    const headers = await seedAdmin(auth);

    const used = await createInvite(auth, {
      body: { type: "private", email: "done@test.com" },
      headers
    });
    await auth.api.acceptInvite({ body: { token: used.token, password: "password123" } });
    const usedErr = await captureError(() =>
      auth.api.resendInvite({ body: { inviteId: used.inviteId }, headers })
    );
    expect(usedErr?.code).toBe("INVITE_ALREADY_USED");

    const revoked = await createInvite(auth, {
      body: { type: "private", email: "gone@test.com" },
      headers
    });
    await auth.api.revokeInvite({ body: { inviteId: revoked.inviteId }, headers });
    const revokedErr = await captureError(() =>
      auth.api.resendInvite({ body: { inviteId: revoked.inviteId }, headers })
    );
    expect(revokedErr?.code).toBe("INVITE_REVOKED");
  });

  it("requires the management gate", async () => {
    const auth = await createTestAuth();
    const headers = await seedAdmin(auth);
    const invite = await createInvite(auth, {
      body: { type: "private", email: "gated@test.com" },
      headers
    });
    await seedUser(auth, { email: "plain@test.com", password: "plain-pass-123" });
    const plainHeaders = await signInHeaders(auth, "plain@test.com", "plain-pass-123");
    const err = await captureError(() =>
      auth.api.resendInvite({ body: { inviteId: invite.inviteId }, headers: plainHeaders })
    );
    expect(err?.code).toBe("NOT_ALLOWED_TO_MANAGE_INVITES");
  });
});
