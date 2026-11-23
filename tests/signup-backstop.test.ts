import { readFileSync } from "node:fs";
import { anonymous, emailOTP } from "better-auth/plugins";
import { describe, expect, it } from "vitest";
import {
  createInvite,
  createTestAuth,
  findUserByEmail,
  seedAdmin,
  seedUser,
  type TestAuth
} from "./helpers";

const BASE = "http://localhost:3000/api/auth";
const PASSWORD = "Chosen-Pass-9917";

async function post(auth: TestAuth, path: string, body: unknown) {
  const res = await auth.handler(
    new Request(`${BASE}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: "http://localhost:3000" },
      body: JSON.stringify(body)
    })
  );
  const text = await res.text();
  const json = JSON.parse(text || "{}") as {
    code?: string;
    message?: string;
    token?: string | null;
  };
  return { status: res.status, code: json.code, message: json.message, token: json.token };
}

// Better Auth 1.7 turns a 403 from a sign-up hook into its generic duplicate answer.
const installed = JSON.parse(
  readFileSync(new URL("../node_modules/better-auth/package.json", import.meta.url), "utf8")
) as { version: string };
const [major, minor] = installed.version.split(".").map(Number);
const hidesHookRefusals = major! > 1 || (major === 1 && minor! >= 7);

/** Invite-only app whose email OTP plugin still allows sign-up (not detectable). */
async function otpApp(invite?: Parameters<typeof createTestAuth>[0]) {
  const otps: { email: string; otp: string }[] = [];
  const auth = await createTestAuth({
    ...invite,
    plugins: [
      emailOTP({
        sendVerificationOTP: async ({ email, otp }) => {
          otps.push({ email, otp });
        }
      })
    ]
  });
  const otpSignIn = async (email: string) => {
    await post(auth, "/email-otp/send-verification-otp", { email, type: "sign-in" });
    return post(auth, "/sign-in/email-otp", { email, otp: otps.at(-1)?.otp ?? "000000" });
  };
  return { auth, otpSignIn };
}

describe("sign-up backstop (invite-only)", () => {
  it("refuses accounts from sign-up paths mode detection cannot see", async () => {
    const { auth, otpSignIn } = await otpApp();
    const res = await otpSignIn("stranger@corp.test");
    expect(res.status).toBe(403);
    expect(res.code).toBe("SIGN_UP_REQUIRES_INVITATION");
    expect(await findUserByEmail(auth, "stranger@corp.test")).toBeNull();

    const anon = await createTestAuth({ plugins: [anonymous()] });
    const ctx = await anon.$context;
    const before = await ctx.adapter.count({ model: "user" });
    expect((await post(anon, "/sign-in/anonymous", {})).code).toBe("SIGN_UP_REQUIRES_INVITATION");
    expect(await ctx.adapter.count({ model: "user" })).toBe(before);
  });

  it("still lets redemption, the admin plugin and server code create accounts", async () => {
    const { auth, otpSignIn } = await otpApp();
    const headers = await seedAdmin(auth);
    const inv = await createInvite(auth, {
      body: { type: "private", email: "invitee@corp.test" },
      headers
    });
    const redeemed = await auth.api.redeemInvite({
      body: { token: inv.token, password: PASSWORD, name: "Invitee" }
    });
    expect(redeemed.action).toBe("ACCEPTED");

    const created = await auth.api.createUser({
      body: { email: "made@corp.test", password: PASSWORD, name: "Made", role: "user" },
      headers
    });
    expect(created.user.email).toBe("made@corp.test");
    expect(await seedUser(auth, { email: "seeded@corp.test" })).toBeTruthy();

    // Existing accounts keep signing in through the same plugin.
    expect((await otpSignIn("invitee@corp.test")).status).toBe(200);
  });

  it("with allowOpenSignup, holds back only invited addresses, answering as for an existing account", async () => {
    for (const hide of hidesHookRefusals ? [false, true] : [false]) {
      const auth = await createTestAuth({
        invite: { allowOpenSignup: true },
        auth: { emailAndPassword: { enabled: true, requireEmailVerification: hide } }
      });
      const headers = await seedAdmin(auth);
      const signUp = (email: string) =>
        post(auth, "/sign-up/email", { email, password: PASSWORD, name: "X" });

      expect((await signUp("stranger@corp.test")).status).toBe(200);
      const existing = await signUp("stranger@corp.test");

      const pending = await createInvite(auth, {
        body: { type: "private", email: "invited@corp.test" },
        headers
      });
      const refused = await signUp("invited@corp.test");
      expect(refused).toEqual(existing);
      expect(refused.status).toBe(hide ? 200 : 422);
      expect(await findUserByEmail(auth, "invited@corp.test")).toBeNull();

      await auth.api.revokeInvite({ body: { inviteId: pending.inviteId }, headers });
      expect((await signUp("invited@corp.test")).status).toBe(200);
    }
  });
});

describe("sign-up backstop (open mode)", () => {
  it("does nothing: invited addresses sign up through the app's own paths", async () => {
    const auth = await createTestAuth({
      invite: { mode: "open" },
      auth: { emailAndPassword: { enabled: true } }
    });
    const headers = await seedAdmin(auth);
    await createInvite(auth, { body: { type: "private", email: "invited@corp.test" }, headers });
    const res = await post(auth, "/sign-up/email", {
      email: "invited@corp.test",
      password: PASSWORD,
      name: "X"
    });
    expect(res.status).toBe(200);
  });
});
