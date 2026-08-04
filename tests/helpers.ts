import { betterAuth, type BetterAuthOptions, type BetterAuthPlugin } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { admin } from "better-auth/plugins";
import Database from "better-sqlite3";
import { betterEnrollment, type BetterEnrollmentOptions } from "../src";
import { sha256Base64Url } from "../src/utils";

export const ADMIN_EMAIL = "admin@test.com";
export const ADMIN_PASSWORD = "admin-password-123";

type SentInvite = { email: string | null; url: string; token: string };

/** Every invite link the plugin handed to a send function, per auth instance. */
const sentByAuth = new WeakMap<object, SentInvite[]>();

export async function createTestAuth(config?: {
  invite?: Partial<BetterEnrollmentOptions>;
  auth?: Partial<BetterAuthOptions>;
  plugins?: BetterAuthPlugin[];
  /** Omit the admin plugin, so the user model has no role field. */
  withoutAdmin?: boolean;
}) {
  // Private links never come back from the API, so tests read them where a
  // real invitee would: out of the delivered message.
  const sent: SentInvite[] = [];
  const inviteOptions: Partial<BetterEnrollmentOptions> = { ...config?.invite };
  const callerPrivate = inviteOptions.sendPrivateInvitation;
  const callerPublic = inviteOptions.sendPublicInvitation;
  inviteOptions.sendPrivateInvitation = async (data, request) => {
    sent.push({ email: data.email, url: data.url, token: data.token });
    await callerPrivate?.(data, request);
  };
  inviteOptions.sendPublicInvitation = async (data, request) => {
    sent.push({ email: null, url: data.url, token: data.token });
    await callerPublic?.(data, request);
  };
  const auth = betterAuth({
    baseURL: "http://localhost:3000",
    secret: "test-secret-key-for-vitest-only-1234567890",
    database: new Database(":memory:"),
    emailAndPassword: { enabled: true, disableSignUp: true },
    plugins: [
      ...(config?.withoutAdmin ? [] : [admin()]),
      ...(config?.plugins ?? []),
      betterEnrollment({
        mode: "invite-only",
        validRoles: ["user", "partner", "admin"],
        ...inviteOptions
      })
    ],
    ...(config?.auth ?? {})
  });
  const { runMigrations } = await getMigrations(auth.options);
  await runMigrations();
  // Force plugin init to run now so misconfiguration throws here, not lazily.
  await auth.$context;
  sentByAuth.set(auth, sent);
  return auth;
}

export type TestAuth = Awaited<ReturnType<typeof createTestAuth>>;

export async function seedUser(
  auth: TestAuth,
  user: {
    email: string;
    password?: string;
    role?: string;
    emailVerified?: boolean;
    name?: string;
  }
) {
  const ctx = await auth.$context;
  const created = await ctx.internalAdapter.createUser({
    email: user.email,
    name: user.name ?? "Test User",
    emailVerified: user.emailVerified ?? true,
    role: user.role ?? "user"
  });
  if (user.password) {
    const hash = await ctx.password.hash(user.password);
    await ctx.internalAdapter.createAccount({
      userId: created.id,
      providerId: "credential",
      accountId: created.id,
      password: hash
    });
  }
  return created;
}

export function cookieHeaders(headers: Headers): Headers {
  const setCookie = headers.get("set-cookie") ?? "";
  const cookie = setCookie
    .split(/,(?=[^ ;]+?=)/)
    .map((c) => c.split(";")[0]?.trim())
    .filter(Boolean)
    .join("; ");
  return new Headers({ cookie });
}

export async function signInHeaders(auth: TestAuth, email: string, password: string) {
  const res = await auth.api.signInEmail({
    body: { email, password },
    returnHeaders: true
  });
  return cookieHeaders(res.headers);
}

export async function seedAdmin(auth: TestAuth) {
  await seedUser(auth, {
    email: ADMIN_EMAIL,
    password: ADMIN_PASSWORD,
    role: "admin",
    name: "Admin"
  });
  return signInHeaders(auth, ADMIN_EMAIL, ADMIN_PASSWORD);
}

/**
 * Creates an invite and returns a redeemable token. Public invites carry it in
 * the response; private ones only ever put it in the email, so it is read back
 * from the captured delivery, exactly like a real invitee would.
 */
export async function createInvite(
  auth: TestAuth,
  args: Parameters<TestAuth["api"]["createInvite"]>[0]
) {
  const sent = sentByAuth.get(auth);
  const before = sent?.length ?? 0;
  const res = await auth.api.createInvite(args);
  const delivered = sent && sent.length > before ? sent[sent.length - 1] : undefined;
  const token = res.token ?? delivered?.token;
  const url = res.url ?? delivered?.url;
  if (!token || !url) {
    throw new Error("no invite link was returned or delivered");
  }
  return { ...res, token, url };
}

export async function expireInvite(auth: TestAuth, inviteId: string) {
  const ctx = await auth.$context;
  await ctx.adapter.update({
    model: "invite",
    where: [{ field: "id", value: inviteId }],
    update: { expiresAt: new Date(Date.now() - 60_000) }
  });
}

export async function findInviteRow(auth: TestAuth, inviteId: string) {
  const ctx = await auth.$context;
  return await ctx.adapter.findOne<Record<string, unknown>>({
    model: "invite",
    where: [{ field: "id", value: inviteId }]
  });
}

export async function findUserByEmail(auth: TestAuth, email: string) {
  const ctx = await auth.$context;
  const res = await ctx.internalAdapter.findUserByEmail(email.toLowerCase());
  return res && "user" in res ? res.user : res;
}

export async function findAccounts(auth: TestAuth, userId: string) {
  const ctx = await auth.$context;
  return await ctx.internalAdapter.findAccounts(userId);
}

/** Insert an invite row directly, bypassing create-time role validation. */
export async function insertInviteRow(
  auth: TestAuth,
  fields: {
    token: string;
    type?: "private" | "public";
    kind?: "app" | "org-join" | "org-create";
    email?: string | null;
    role: string;
    mode?: "invite-only" | "open";
    maxUses?: number | null;
    expiresAt?: Date | null;
    preCreatedUserId?: string | null;
    organizationId?: string | null;
    organizationRole?: string | null;
    teamId?: string | null;
  }
) {
  const ctx = await auth.$context;
  const inviter = await ctx.internalAdapter.createUser({
    email: `seed-${fields.token}@seed.com`,
    name: "Seed",
    emailVerified: true,
    role: "admin"
  });
  let preCreatedUserId = fields.preCreatedUserId ?? null;
  if (
    !preCreatedUserId &&
    (fields.type ?? "private") === "private" &&
    fields.email &&
    (fields.mode ?? "invite-only") === "invite-only"
  ) {
    const invitee = await ctx.internalAdapter.createUser({
      email: fields.email,
      name: "",
      emailVerified: false,
      role: fields.role
    });
    preCreatedUserId = invitee.id;
  }
  const now = new Date();
  return await ctx.adapter.create<Record<string, unknown>>({
    model: "invite",
    data: {
      type: fields.type ?? "private",
      kind: fields.kind ?? "app",
      email: fields.email ?? null,
      name: null,
      role: fields.role,
      tokenHash: await sha256Base64Url(fields.token),
      status: "pending",
      mode: fields.mode ?? "invite-only",
      organizationId: fields.organizationId ?? null,
      organizationRole: fields.organizationRole ?? null,
      teamId: fields.teamId ?? null,
      presetSeatLimit: null,
      preCreatedUserId,
      createdByUserId: inviter.id,
      inviterName: "Seed",
      inviterEmail: inviter.email,
      expiresAt: fields.expiresAt ?? new Date(Date.now() + 3600_000),
      maxUses: fields.maxUses ?? (fields.type === "public" ? null : 1),
      useCount: 0,
      revokedAt: null,
      revokedByUserId: null,
      createdAt: now,
      updatedAt: now
    }
  });
}
