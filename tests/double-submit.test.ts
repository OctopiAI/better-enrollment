import { describe, expect, it } from "vitest";
import {
  createInvite,
  createTestAuth,
  findInviteRow,
  findUserByEmail,
  seedAdmin,
  type TestAuth
} from "./helpers";

const PASS = "Double-Pass-4471";
const BASE = "http://localhost:3000/api/auth";

async function post(auth: TestAuth, path: string, body: unknown) {
  const res = await auth.handler(
    new Request(`${BASE}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: "http://localhost:3000" },
      body: JSON.stringify(body)
    })
  );
  const text = await res.text();
  return {
    status: res.status,
    json: JSON.parse(text || "{}") as { code?: string; action?: string }
  };
}

describe("one private invite submitted twice", () => {
  it("the second submission never removes the account the first one creates", async () => {
    let first = true;
    let entered!: () => void;
    let release!: () => void;
    const enteredP = new Promise<void>((r) => (entered = r));
    const gate = new Promise<void>((r) => (release = r));
    const auth = await createTestAuth({
      auth: {
        databaseHooks: {
          user: {
            create: {
              // A slow app hook (welcome mail, CRM sync) holds the first request.
              after: async (user: { email: string }) => {
                if (user.email === "racer@corp.test" && first) {
                  first = false;
                  entered();
                  await gate;
                }
              }
            }
          }
        }
      } as never
    });
    const adminHeaders = await seedAdmin(auth);
    const inv = await createInvite(auth, {
      body: { email: "racer@corp.test", role: "user" },
      headers: adminHeaders
    });
    const body = { token: inv.token, password: PASS, name: "Racer" };
    const a = post(auth, "/invite/redeem", body);
    await enteredP;
    const b = await post(auth, "/invite/redeem", body);
    release();
    const ar = await a;

    expect([ar.json.action, b.json.code].sort()).toEqual(["ACCEPTED", "INVITE_ALREADY_USED"]);
    const user = await findUserByEmail(auth, "racer@corp.test");
    expect(user?.emailVerified).toBe(true);
    expect((await findInviteRow(auth, inv.inviteId))?.status).toBe("accepted");
    const signIn = await post(auth, "/sign-in/email", { email: "racer@corp.test", password: PASS });
    expect(signIn.status).toBe(200);
  });
});
