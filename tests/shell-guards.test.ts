import { emailOTP } from "better-auth/plugins";
import { describe, expect, it } from "vitest";
import {
  cookieHeaders,
  createInvite,
  createTestAuth,
  expireInvite,
  findAccounts,
  findUserByEmail,
  seedAdmin,
  seedUser,
  type TestAuth
} from "./helpers";

const INVITEE = "invitee@corp.test";
const PASSWORD = "Chosen-Pass-9917";
const BASE = "http://localhost:3000/api/auth";

async function http(auth: TestAuth, method: "GET" | "POST", path: string, body?: unknown) {
  const headers = new Headers({ origin: "http://localhost:3000" });
  if (body !== undefined) headers.set("content-type", "application/json");
  let res: Response;
  try {
    res = await auth.handler(
      new Request(`${BASE}${path}`, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body)
      })
    );
  } catch (e) {
    // Better Auth 1.6 runs database after-hooks once the response is built,
    // so a refusal there rejects the handler; a server answers 500.
    return { status: 500, headers: new Headers(), text: String(e) };
  }
  return { status: res.status, headers: res.headers, text: await res.text() };
}

async function sessionRole(auth: TestAuth, headers: Headers) {
  const session = await auth.api.getSession({ headers: cookieHeaders(headers) });
  return session ? ((session.user as { role?: string }).role ?? null) : null;
}

function mailbox() {
  const verifications: { email: string; token: string }[] = [];
  const resets: { email: string; token: string }[] = [];
  const otps: { email: string; otp: string; type: string }[] = [];
  return {
    verifications,
    resets,
    otps,
    make: (opts?: { autoSignIn?: boolean; otp?: boolean }) =>
      createTestAuth({
        plugins: opts?.otp
          ? [
              emailOTP({
                disableSignUp: true,
                sendVerificationOTP: async ({ email, otp, type }) => {
                  otps.push({ email, otp, type });
                }
              })
            ]
          : undefined,
        auth: {
          emailAndPassword: {
            enabled: true,
            disableSignUp: true,
            sendResetPassword: async ({ user, token }) => {
              resets.push({ email: user.email, token });
            }
          },
          emailVerification: {
            sendVerificationEmail: async ({ user, token }) => {
              verifications.push({ email: user.email, token });
            },
            autoSignInAfterVerification: opts?.autoSignIn ?? false
          }
        }
      })
  };
}

async function adminInvite(auth: TestAuth) {
  const adminHeaders = await seedAdmin(auth);
  const inv = await createInvite(auth, {
    body: { type: "private", email: INVITEE, role: "admin" },
    headers: adminHeaders
  });
  return { adminHeaders, inv };
}

describe("pre-created shell guards", () => {
  it("the shell holds the default role; the invited role arrives at redemption", async () => {
    const auth = await createTestAuth();
    const { inv } = await adminInvite(auth);
    expect(((await findUserByEmail(auth, INVITEE)) as { role?: string }).role).toBe("user");
    await auth.api.redeemInvite({ body: { token: inv.token, password: PASSWORD, name: "I" } });
    expect(((await findUserByEmail(auth, INVITEE)) as { role?: string }).role).toBe("admin");
  });

  it("revoke removes the shell, so the verification mail has nothing to activate", async () => {
    const box = mailbox();
    const auth = await box.make({ autoSignIn: true });
    const { adminHeaders, inv } = await adminInvite(auth);
    await auth.api.revokeInvite({ body: { inviteId: inv.inviteId }, headers: adminHeaders });
    expect(await findUserByEmail(auth, INVITEE)).toBeFalsy();
    await http(auth, "POST", "/send-verification-email", { email: INVITEE });
    expect(box.verifications.length).toBe(0);
  });

  it("verifying a pending shell is refused and signs nobody in", async () => {
    const box = mailbox();
    const auth = await box.make({ autoSignIn: true });
    const { inv } = await adminInvite(auth);
    await http(auth, "POST", "/send-verification-email", { email: INVITEE });
    const verified = await http(
      auth,
      "GET",
      `/verify-email?token=${encodeURIComponent(box.verifications[0]!.token)}`
    );
    expect(await sessionRole(auth, verified.headers)).toBeNull();
    expect((await findUserByEmail(auth, INVITEE))?.emailVerified).toBe(false);

    // The refused attempt leaves the invite redeemable.
    const redeemed = await auth.api.redeemInvite({
      body: { token: inv.token, password: PASSWORD, name: "I" }
    });
    expect(redeemed.action).toBe("ACCEPTED");
  });

  it("delete and expiry cleanup remove the shell; a later reset finds no account", async () => {
    const box = mailbox();
    const auth = await box.make();
    const { adminHeaders, inv } = await adminInvite(auth);
    await auth.api.deleteInvite({ body: { inviteId: inv.inviteId }, headers: adminHeaders });
    expect(await findUserByEmail(auth, INVITEE)).toBeFalsy();

    const again = await createInvite(auth, {
      body: { type: "private", email: INVITEE, role: "admin" },
      headers: adminHeaders
    });
    await expireInvite(auth, again.inviteId);
    expect(await auth.api.cleanupExpiredInvites({ body: {} })).toEqual({ deleted: 1 });
    expect(await findUserByEmail(auth, INVITEE)).toBeFalsy();

    await http(auth, "POST", "/request-password-reset", {
      email: INVITEE,
      redirectTo: "http://localhost:3000/reset"
    });
    expect(box.resets.length).toBe(0);
  });

  it("email OTP cannot sign in a pending shell or write a password onto it", async () => {
    const box = mailbox();
    const auth = await box.make({ otp: true });
    await adminInvite(auth);

    await http(auth, "POST", "/email-otp/send-verification-otp", {
      email: INVITEE,
      type: "sign-in"
    });
    const signIn = await http(auth, "POST", "/sign-in/email-otp", {
      email: INVITEE,
      otp: box.otps.at(-1)?.otp
    });
    expect(await sessionRole(auth, signIn.headers)).toBeNull();

    await http(auth, "POST", "/email-otp/request-password-reset", { email: INVITEE });
    await http(auth, "POST", "/email-otp/reset-password", {
      email: INVITEE,
      otp: box.otps.at(-1)?.otp,
      password: PASSWORD
    });
    const shell = await findUserByEmail(auth, INVITEE);
    expect(shell?.emailVerified).toBe(false);
    expect(await findAccounts(auth, shell!.id)).toEqual([]);
  });

  it("a shell activated before the guards existed is refused a session and removed on revoke", async () => {
    const box = mailbox();
    const auth = await box.make({ otp: true });
    const { adminHeaders, inv } = await adminInvite(auth);
    const ctx = await auth.$context;
    const shell = await findUserByEmail(auth, INVITEE);
    await ctx.adapter.update({
      model: "user",
      where: [{ field: "id", value: shell!.id }],
      update: { emailVerified: true }
    });

    await http(auth, "POST", "/email-otp/send-verification-otp", {
      email: INVITEE,
      type: "sign-in"
    });
    const signIn = await http(auth, "POST", "/sign-in/email-otp", {
      email: INVITEE,
      otp: box.otps.at(-1)?.otp
    });
    expect(await sessionRole(auth, signIn.headers)).toBeNull();

    await auth.api.revokeInvite({ body: { inviteId: inv.inviteId }, headers: adminHeaders });
    expect(await findUserByEmail(auth, INVITEE)).toBeFalsy();
  });

  it("established users are untouched: verification, OTP sign-in and reset work", async () => {
    const box = mailbox();
    const auth = await box.make({ otp: true });
    const { adminHeaders, inv } = await adminInvite(auth);
    await auth.api.redeemInvite({ body: { token: inv.token, password: PASSWORD, name: "I" } });
    await seedUser(auth, { email: "plain@corp.test", password: PASSWORD, emailVerified: false });

    await http(auth, "POST", "/send-verification-email", { email: "plain@corp.test" });
    await http(
      auth,
      "GET",
      `/verify-email?token=${encodeURIComponent(box.verifications.at(-1)!.token)}`
    );
    expect((await findUserByEmail(auth, "plain@corp.test"))?.emailVerified).toBe(true);

    await http(auth, "POST", "/email-otp/send-verification-otp", {
      email: INVITEE,
      type: "sign-in"
    });
    const otpSignIn = await http(auth, "POST", "/sign-in/email-otp", {
      email: INVITEE,
      otp: box.otps.at(-1)?.otp
    });
    expect(await sessionRole(auth, otpSignIn.headers)).toBe("admin");

    // A revoked invite to an established address never deletes the account.
    const later = await createInvite(auth, {
      body: { type: "private", email: "plain@corp.test", role: "partner" },
      headers: adminHeaders
    }).catch(() => null);
    if (later) {
      await auth.api.revokeInvite({ body: { inviteId: later.inviteId }, headers: adminHeaders });
    }
    expect(await findUserByEmail(auth, "plain@corp.test")).toBeTruthy();

    await http(auth, "POST", "/request-password-reset", {
      email: INVITEE,
      redirectTo: "http://localhost:3000/reset"
    });
    expect(box.resets.length).toBe(1);
  });
});
