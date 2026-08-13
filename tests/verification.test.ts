import { describe, expect, it } from "vitest";
import type { User } from "better-auth";
import { createInvite, createTestAuth, findUserByEmail, seedAdmin } from "./helpers";

type Delivery = { email: string; url: string; token: string };

function captureVerification(sent: Delivery[]) {
  return {
    sendVerificationEmail: async ({
      user,
      url,
      token
    }: {
      user: User;
      url: string;
      token: string;
    }) => {
      sent.push({ email: user.email, url, token });
    }
  };
}

describe("public-invite email verification", () => {
  it("sendOnSignUp sends a verification email on public redemption, and the token verifies", async () => {
    const sent: Delivery[] = [];
    const auth = await createTestAuth({
      auth: { emailVerification: { ...captureVerification(sent), sendOnSignUp: true } }
    });
    const headers = await seedAdmin(auth);
    const invite = await createInvite(auth, {
      body: { type: "public", role: "user", maxUses: 5 },
      headers
    });
    await auth.api.acceptInvite({
      body: {
        token: invite.token,
        password: "password123",
        email: "public@test.com",
        name: "Invitee"
      }
    });

    const user = await findUserByEmail(auth, "public@test.com");
    expect(user?.emailVerified).toBe(false);
    expect(sent).toHaveLength(1);
    expect(sent[0]!.email).toBe("public@test.com");
    expect(sent[0]!.url).toContain("/verify-email?token=");

    await auth.api.verifyEmail({ query: { token: sent[0]!.token } });
    const verified = await findUserByEmail(auth, "public@test.com");
    expect(verified?.emailVerified).toBe(true);
  });

  it("requireEmailVerification alone also triggers the send, like Better Auth sign-up", async () => {
    const sent: Delivery[] = [];
    const auth = await createTestAuth({
      auth: {
        emailVerification: captureVerification(sent),
        emailAndPassword: { enabled: true, disableSignUp: true, requireEmailVerification: true }
      }
    });
    const headers = await seedAdmin(auth);
    const invite = await createInvite(auth, {
      body: { type: "public", role: "user", maxUses: 5 },
      headers
    });
    await auth.api.acceptInvite({
      body: {
        token: invite.token,
        password: "password123",
        email: "public@test.com",
        name: "Invitee"
      }
    });
    expect(sent).toHaveLength(1);
  });

  it("autoVerifyPublicInviteEmail skips the send; the user is already verified", async () => {
    const sent: Delivery[] = [];
    const auth = await createTestAuth({
      invite: { autoVerifyPublicInviteEmail: true },
      auth: { emailVerification: { ...captureVerification(sent), sendOnSignUp: true } }
    });
    const headers = await seedAdmin(auth);
    const invite = await createInvite(auth, {
      body: { type: "public", role: "user", maxUses: 5 },
      headers
    });
    await auth.api.acceptInvite({
      body: {
        token: invite.token,
        password: "password123",
        email: "public@test.com",
        name: "Invitee"
      }
    });
    const user = await findUserByEmail(auth, "public@test.com");
    expect(user?.emailVerified).toBe(true);
    expect(sent).toHaveLength(0);
  });

  it("private invites never send one; acceptance itself verifies the email", async () => {
    const sent: Delivery[] = [];
    const auth = await createTestAuth({
      auth: { emailVerification: { ...captureVerification(sent), sendOnSignUp: true } }
    });
    const headers = await seedAdmin(auth);
    const invite = await createInvite(auth, {
      body: { type: "private", email: "private@test.com" },
      headers
    });
    await auth.api.acceptInvite({
      body: { token: invite.token, password: "password123", name: "Invitee" }
    });
    const user = await findUserByEmail(auth, "private@test.com");
    expect(user?.emailVerified).toBe(true);
    expect(sent).toHaveLength(0);
  });
});
