import { describe, expect, it } from "vitest";
import * as z from "zod";
import {
  createInvite,
  createTestAuth,
  findUserByEmail,
  seedAdmin,
  seedUser,
  signInHeaders,
  type TestAuth
} from "./helpers";

const PASSWORD = "password123";

async function errCode(promise: Promise<unknown>): Promise<string | undefined> {
  try {
    await promise;
    return undefined;
  } catch (e) {
    return (e as { body?: { code?: string } }).body?.code;
  }
}

async function userRow(auth: TestAuth, email: string) {
  const ctx = await auth.$context;
  return await ctx.adapter.findOne<Record<string, unknown>>({
    model: "user",
    where: [{ field: "email", value: email }]
  });
}

describe("required name at redemption", () => {
  it("accept without a name fails with NAME_REQUIRED for private and public invites", async () => {
    const auth = await createTestAuth();
    const headers = await seedAdmin(auth);
    const priv = await createInvite(auth, {
      body: { type: "private", email: "noname@test.com", role: "user" },
      headers
    });
    expect(
      await errCode(auth.api.acceptInvite({ body: { token: priv.token, password: PASSWORD } }))
    ).toBe("NAME_REQUIRED");
    expect(
      await errCode(
        auth.api.acceptInvite({ body: { token: priv.token, password: PASSWORD, name: "  " } })
      )
    ).toBe("NAME_REQUIRED");

    const pub = await createInvite(auth, {
      body: { type: "public", role: "user" },
      headers
    });
    expect(
      await errCode(
        auth.api.redeemInvite({
          body: { token: pub.token, password: PASSWORD, email: "pub-noname@test.com" }
        })
      )
    ).toBe("NAME_REQUIRED");
    // The failed attempts consumed nothing.
    const accepted = await auth.api.acceptInvite({
      body: { token: priv.token, password: PASSWORD, name: "Named Invitee" }
    });
    expect(accepted).toMatchObject({
      action: "ACCEPTED",
      user: { name: "Named Invitee" }
    });
  });

  it("creation still does not require a name; get lists name as required for SIGN_UP", async () => {
    const auth = await createTestAuth();
    const headers = await seedAdmin(auth);
    const priv = await createInvite(auth, {
      body: { type: "private", email: "fields@test.com", role: "user" },
      headers
    });
    const info = await auth.api.getInvite({ query: { token: priv.token } });
    expect(info.requiredFields).toEqual(["password", "name"]);
    expect(info.optionalFields).toEqual([]);

    const pub = await createInvite(auth, {
      body: { type: "public", role: "user" },
      headers
    });
    const pubInfo = await auth.api.getInvite({ query: { token: pub.token } });
    expect(pubInfo.requiredFields).toEqual(["password", "name", "email"]);
  });
});

describe("additionalFields", () => {
  it("required fields are enforced, stored on the user, and listed by get", async () => {
    const auth = await createTestAuth({
      invite: {
        additionalFields: {
          department: { type: "string" },
          seniority: { type: "number", required: false }
        }
      }
    });
    const headers = await seedAdmin(auth);
    const { token } = await createInvite(auth, {
      body: { type: "private", email: "dept@test.com", role: "user" },
      headers
    });

    const info = await auth.api.getInvite({ query: { token } });
    expect(info.requiredFields).toEqual(["password", "name", "department"]);
    expect(info.optionalFields).toEqual(["seniority"]);
    expect(info.additionalFields).toEqual({
      department: { type: "string", required: true },
      seniority: { type: "number", required: false }
    });

    expect(
      await errCode(
        auth.api.acceptInvite({ body: { token, password: PASSWORD, name: "Dee Party" } })
      )
    ).toBe("ADDITIONAL_FIELD_REQUIRED");

    await auth.api.acceptInvite({
      body: {
        token,
        password: PASSWORD,
        name: "Dee Party",
        department: "engineering",
        seniority: 3
      }
    });
    const row = await userRow(auth, "dept@test.com");
    expect(row?.department).toBe("engineering");
    expect(row?.seniority).toBe(3);
    expect(row?.name).toBe("Dee Party");
  });

  it("public accepts store additional fields on the created user", async () => {
    const auth = await createTestAuth({
      invite: {
        additionalFields: { referral: { type: "string" } }
      }
    });
    const headers = await seedAdmin(auth);
    const { token } = await createInvite(auth, {
      body: { type: "public", role: "user" },
      headers
    });
    await auth.api.redeemInvite({
      body: {
        token,
        password: PASSWORD,
        name: "Ref User",
        email: "ref@test.com",
        referral: "conference"
      }
    });
    const row = await userRow(auth, "ref@test.com");
    expect(row?.referral).toBe("conference");
    expect((await findUserByEmail(auth, "ref@test.com"))?.name).toBe("Ref User");
  });

  it("defaultValue fills absent values and makes the field optional in get", async () => {
    const auth = await createTestAuth({
      invite: {
        additionalFields: {
          plan: { type: "string", defaultValue: "free" },
          joinedVia: { type: "string", defaultValue: () => "invite" }
        }
      }
    });
    const headers = await seedAdmin(auth);
    const { token } = await createInvite(auth, {
      body: { type: "private", email: "plan@test.com", role: "user" },
      headers
    });
    const info = await auth.api.getInvite({ query: { token } });
    expect(info.requiredFields).toEqual(["password", "name"]);
    expect(info.optionalFields).toEqual(["plan", "joinedVia"]);
    expect(info.additionalFields.plan).toEqual({ type: "string", required: false });

    await auth.api.acceptInvite({
      body: { token, password: PASSWORD, name: "Plan User" }
    });
    const row = await userRow(auth, "plan@test.com");
    expect(row?.plan).toBe("free");
    expect(row?.joinedVia).toBe("invite");
  });

  it("type mismatches and failing validators reject with ADDITIONAL_FIELD_INVALID", async () => {
    const auth = await createTestAuth({
      invite: {
        additionalFields: {
          age: { type: "number", validator: { input: z.number().min(18) } },
          startsOn: { type: "date", required: false }
        }
      }
    });
    const headers = await seedAdmin(auth);
    const { token } = await createInvite(auth, {
      body: { type: "private", email: "valid@test.com", role: "user" },
      headers
    });
    expect(
      await errCode(
        auth.api.acceptInvite({
          body: { token, password: PASSWORD, name: "V", age: "not-a-number" }
        })
      )
    ).toBe("ADDITIONAL_FIELD_INVALID");
    expect(
      await errCode(
        auth.api.acceptInvite({
          body: { token, password: PASSWORD, name: "V", age: 12 }
        })
      )
    ).toBe("ADDITIONAL_FIELD_INVALID");
    expect(
      await errCode(
        auth.api.acceptInvite({
          body: { token, password: PASSWORD, name: "V", age: 30, startsOn: "garbage-date" }
        })
      )
    ).toBe("ADDITIONAL_FIELD_INVALID");

    await auth.api.acceptInvite({
      body: { token, password: PASSWORD, name: "V", age: 30, startsOn: "2026-09-01T00:00:00Z" }
    });
    const row = await userRow(auth, "valid@test.com");
    expect(row?.age).toBe(30);
    expect(new Date(row?.startsOn as string).getUTCFullYear()).toBe(2026);
  });

  it("undeclared body keys are ignored, never stored", async () => {
    const auth = await createTestAuth({
      invite: { additionalFields: { team: { type: "string", required: false } } }
    });
    const headers = await seedAdmin(auth);
    const { token } = await createInvite(auth, {
      body: { type: "public", role: "user" },
      headers
    });
    await auth.api.redeemInvite({
      body: {
        token,
        password: PASSWORD,
        name: "Sneaky",
        email: "sneaky@test.com",
        emailVerifiedX: true,
        favoriteColor: "red"
      }
    });
    const row = await userRow(auth, "sneaky@test.com");
    expect(row).not.toBeNull();
    expect(row).not.toHaveProperty("favoriteColor");
  });

  it("reserved field names are rejected at plugin construction", async () => {
    await expect(
      createTestAuth({
        invite: { additionalFields: { role: { type: "string" } } }
      })
    ).rejects.toThrow(/reserved redemption field/);
    await expect(
      createTestAuth({
        invite: { additionalFields: { password: { type: "string" } } }
      })
    ).rejects.toThrow(/reserved redemption field/);
  });

  it("default fields apply to sign-up only: activation flows skip them", async () => {
    const auth = await createTestAuth({
      invite: { mode: "open", additionalFields: { badge: { type: "string" } } },
      auth: { emailAndPassword: { enabled: true, disableSignUp: false } }
    });
    // Open mode: get shows no sign-up fields and activate ignores extras.
    const headers = await seedAdmin(auth);
    const { token } = await createInvite(auth, {
      body: { type: "public", role: "partner" },
      headers
    });
    const info = await auth.api.getInvite({ query: { token } });
    expect(info.nextAction).toBe("SIGN_IN");
    expect(info.requiredFields).toEqual([]);
    expect(info.additionalFields).toEqual({});

    // Signed in, the step is CONFIRM; a SIGN_UP-only field stays absent.
    const confirmInfo = await auth.api.getInvite({ query: { token }, headers });
    expect(confirmInfo.nextAction).toBe("CONFIRM");
    expect(confirmInfo.requiredFields).toEqual([]);
    expect(confirmInfo.additionalFields).toEqual({});

    const res = await auth.api.activateInvite({ body: { token }, headers });
    expect(res.action).toBe("ACCEPTED");
  });

  it("CONFIRM-action fields are listed by get and collected at activation", async () => {
    const auth = await createTestAuth({
      invite: {
        mode: "open",
        additionalFields: {
          department: { type: "string", actions: ["SIGN_UP", "CONFIRM"] },
          nickname: { type: "string", required: false, actions: ["CONFIRM"] },
          plan: { type: "string", defaultValue: "free", actions: ["SIGN_UP", "CONFIRM"] }
        }
      },
      auth: { emailAndPassword: { enabled: true, disableSignUp: false } }
    });
    const headers = await seedAdmin(auth);
    const { token } = await createInvite(auth, {
      body: { type: "public", role: "partner" },
      headers
    });

    await seedUser(auth, { email: "member@test.com", password: PASSWORD });
    const memberHeaders = await signInHeaders(auth, "member@test.com", PASSWORD);

    const info = await auth.api.getInvite({ query: { token }, headers: memberHeaders });
    expect(info.nextAction).toBe("CONFIRM");
    expect(info.requiredFields).toEqual(["department"]);
    expect(info.optionalFields).toEqual(["nickname", "plan"]);
    expect(info.additionalFields).toEqual({
      department: { type: "string", required: true },
      nickname: { type: "string", required: false },
      plan: { type: "string", required: false }
    });

    // Required confirm field missing: rejected before the use is claimed.
    expect(
      await errCode(auth.api.activateInvite({ body: { token }, headers: memberHeaders }))
    ).toBe("ADDITIONAL_FIELD_REQUIRED");

    const res = await auth.api.redeemInvite({
      body: { token, department: "sales", nickname: "Mem" },
      headers: memberHeaders
    });
    expect(res.action).toBe("ACCEPTED");
    const row = await userRow(auth, "member@test.com");
    expect(row?.department).toBe("sales");
    expect(row?.nickname).toBe("Mem");
    // Defaults never apply on confirm: the update must not clobber
    // existing user data with "free".
    expect(row?.plan ?? null).toBeNull();
  });
});
