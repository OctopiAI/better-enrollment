import type {
  AuthContext,
  BetterAuthOptions,
  BetterAuthPlugin,
  DBTransactionAdapter,
  GenericEndpointContext,
  User
} from "better-auth";
import { getCurrentAdapter } from "better-auth";
import {
  APIError,
  createAuthEndpoint,
  createAuthMiddleware,
  createEmailVerificationToken,
  getSessionFromCtx,
  sessionMiddleware
} from "better-auth/api";
import { generateRandomString } from "better-auth/crypto";
import { defaultRoles as adminPluginDefaultRoles } from "better-auth/plugins/admin/access";
import { defaultRoles as orgPluginDefaultRoles } from "better-auth/plugins/organization/access";
import * as z from "zod";
import { defaultInviteRoles, type InviteManagementAction } from "./access";
import { buildSchema } from "./schema";
import { isValidOrgName, isValidOrgSlug, normalizeOrgSlug, ORG_SLUG_MAX_LENGTH } from "./validation";
import {
  INVITE_ERROR_CODES,
  type BetterEnrollmentOptions,
  type Invite,
  type InviteAdditionalField,
  type InviteCancelReason,
  type InvitesCancelledData,
  type InviteFieldAction,
  type InviteKind,
  type InviteMode,
  type InviteType,
  type InviteUse,
  type MemberRecord,
  type OrganizationRecord,
  type OrgRoleLike,
  type TeamRecord
} from "./types";
import { setSessionCookie } from "better-auth/cookies";
import {
  compareNewestFirst,
  decodeCursor,
  deriveStatus,
  encodeCursor,
  isExpired,
  maskEmail,
  mergeRoles,
  reservedSeats,
  sha256Base64Url,
  slugify,
  splitRoles
} from "./utils";

export * from "./access";
export * from "./types";
export { roleGate } from "./utils";
export * from "./validation";

const DEFAULT_EXPIRES_IN = 60 * 60 * 24 * 7;

type AuthCtx = AuthContext;
type Undo = () => Promise<unknown>;

/** Passed to `user.validateUserInfo` (Better Auth >= 1.7) for every user this plugin creates. */
const PROVISIONING_SOURCE = { method: "invite" } as const;

// The only paths allowed to verify, sign in, or add an account to a
// pre-created shell: redemption is the shell's single way in.
const REDEEM_PATHS = new Set(["/invite/accept", "/invite/redeem"]);
const fromRedeem = (context: { path?: string } | null | undefined): boolean =>
  !!context?.path && REDEEM_PATHS.has(context.path);

/** Better Auth's own answer to a sign-up for an email that already has an account. */
const USER_ALREADY_EXISTS = {
  code: "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL",
  message: "User already exists. Use another email."
};

// Endpoints besides redemption that may create users in invite-only mode.
const USER_CREATION_PATHS = new Set(["/admin/create-user"]);

// Sign-in paths that need a credential or linked account, which a shell
// cannot obtain (the account hook refuses it). The session hook skips its
// lookup here, so ordinary logins pay nothing; any other path is checked.
const ACCOUNT_SIGN_IN_PATHS = new Set([
  "/sign-in/email",
  "/sign-in/username",
  "/sign-in/social",
  "/sign-in/passkey",
  "/sign-up/email"
]);
const ACCOUNT_SIGN_IN_PREFIXES = ["/callback/", "/oauth2/callback/"];
const isAccountSignIn = (path: string | undefined): boolean =>
  !!path &&
  (ACCOUNT_SIGN_IN_PATHS.has(path) || ACCOUNT_SIGN_IN_PREFIXES.some((p) => path.startsWith(p)));

/** True while `userId` is the pre-created shell of a non-accepted invite. */
async function isPendingShell(adapter: DBTransactionAdapter, userId: string): Promise<boolean> {
  const owner = await adapter.findOne<{ id: string }>({
    model: "invite",
    where: [
      { field: "preCreatedUserId", value: userId },
      { field: "status", value: ["pending", "cancelled"], operator: "in" }
    ]
  });
  return !!owner;
}

type SignupPath = {
  name: string;
  open: boolean;
  conditional?: boolean;
};

type MaybeWithAccounts = User | { user: User; accounts: { providerId: string }[] };

type BannableUser = User & { role?: string | null; banned?: boolean | null };

type RedeemBody = {
  token: string;
  password?: string;
  name?: string;
  email?: string;
  organizationName?: string;
  organizationSlug?: string;
} & Record<string, unknown>;

/**
 * Body keys the redeem flow owns, plus user columns no invitee may set.
 * additionalFields may not shadow any of them.
 */
const RESERVED_FIELD_NAMES = new Set([
  "token",
  "password",
  "name",
  "email",
  "organizationName",
  "organizationSlug",
  "id",
  "emailVerified",
  "image",
  "role",
  "banned",
  "banReason",
  "banExpires",
  "createdAt",
  "updatedAt"
]);

type OrgPrecheck = {
  org?: OrganizationRecord | null;
  orgInput?: { name: string; slug: string };
  /** The org name and slug came from the invite, not the redeemer. */
  preset?: boolean;
  /** Fields returned by beforeOrgCreate, merged into the org row. */
  orgFields?: Record<string, unknown>;
};

const SLUG_SUFFIX_ATTEMPTS = 5;

type AdapterWhere = NonNullable<
  Parameters<GenericEndpointContext["context"]["adapter"]["findMany"]>[0]["where"]
>;

/** The magic-link plugin config this plugin reads off the plugin object. */
type MagicLinkLikeOptions = {
  disableSignUp?: boolean;
  storeToken?:
    "plain" | "hashed" | { type: "custom-hasher"; hash: (token: string) => Promise<string> };
};

type RoleRecord = Record<string, unknown>;

/**
 * Startup check for grantableRoles: every role a holder may grant must
 * carry no permission the holder lacks, because the holder can always
 * route a grantable role to an account it controls. Returns one problem
 * line per gap or unverifiable entry.
 */
function grantableRoleProblems(
  scope: "app" | "organization",
  grantable: Record<string, string[]> | undefined,
  record: RoleRecord | undefined
): string[] {
  if (!grantable) return [];
  const statementsOf = (name: string) =>
    (record?.[name] as { statements?: Record<string, readonly string[]> } | undefined)
      ?.statements;
  const problems: string[] = [];
  for (const [holder, roles] of Object.entries(grantable)) {
    const held = statementsOf(holder);
    for (const granted of roles) {
      const wants = statementsOf(granted);
      if (!held || !wants) {
        problems.push(
          `${scope} grantableRoles ${holder} -> ${granted}: cannot verify (role not found in the access control roles)`
        );
        continue;
      }
      const gaps = Object.entries(wants).flatMap(([resource, actions]) =>
        actions
          .filter((a) => !(held[resource] ?? []).includes(a))
          .map((a) => `${resource}:${a}`)
      );
      if (gaps.length > 0) {
        problems.push(
          `${scope} grantableRoles ${holder} -> ${granted}: ${granted} holds ${gaps.join(", ")} which ${holder} does not`
        );
      }
    }
  }
  return problems;
}

/** The organization plugin config this plugin reads (limits and hooks). */
type OrgPluginLikeOptions = {
  creatorRole?: string;
  membershipLimit?:
    | number
    | ((user: User, organization: OrganizationRecord) => Promise<number> | number);
  teams?: { maximumMembersPerTeam?: unknown };
  organizationHooks?: {
    beforeAddMember?: (data: {
      member: { userId: string; organizationId: string; role: string };
      user: User;
      organization: OrganizationRecord;
    }) => unknown;
    afterAddMember?: (data: {
      member: MemberRecord;
      user: User;
      organization: OrganizationRecord;
    }) => unknown;
  };
};

/** The admin plugin config read to decide who holds user:set-role. */
type AdminPluginLikeOptions = {
  roles?: Record<string, OrgRoleLike | undefined>;
  adminUserIds?: string[];
  defaultRole?: string;
};

function unwrapUser(result: MaybeWithAccounts | null): User | null {
  if (!result) return null;
  return "user" in result ? result.user : result;
}

function detectSignupPaths(options: BetterAuthOptions): SignupPath[] {
  const paths: SignupPath[] = [];
  if (options.emailAndPassword?.enabled) {
    paths.push({
      name: "email-password",
      open: !options.emailAndPassword.disableSignUp
    });
  }
  for (const [name, provider] of Object.entries(options.socialProviders ?? {})) {
    if (!provider || (provider as { enabled?: boolean }).enabled === false) continue;
    const p = provider as {
      disableSignUp?: boolean;
      disableImplicitSignUp?: boolean;
    };
    if (p.disableSignUp) {
      paths.push({ name, open: false });
    } else if (p.disableImplicitSignUp) {
      paths.push({ name, open: true, conditional: true });
    } else {
      paths.push({ name, open: true });
    }
  }
  // The magic-link plugin exposes its options on the plugin object, so
  // this sign-up path is detectable, unlike most third-party plugins.
  const magicLink = options.plugins?.find((p) => p.id === "magic-link") as
    { options?: MagicLinkLikeOptions } | undefined;
  if (magicLink) {
    paths.push({ name: "magic-link", open: !magicLink.options?.disableSignUp });
  }
  return paths;
}

function describePaths(paths: SignupPath[]): string {
  return paths
    .map(
      (p) =>
        `${p.name}: ${p.open ? (p.conditional ? "conditionally open (disableImplicitSignUp)" : "open") : "closed"}`
    )
    .join(", ");
}

export const betterEnrollment = (options: BetterEnrollmentOptions) => {
  const opts = {
    mode: "auto" as const,
    allowOpenSignup: false,
    defaultRole: "user",
    expiresIn: DEFAULT_EXPIRES_IN,
    publicExpiresIn: DEFAULT_EXPIRES_IN as number | null,
    maxExpiresIn: (365 * 24 * 60 * 60) as number | null,
    maxPublicUses: 10_000 as number | null,
    resendCooldown: 60,
    passwordless: "auto" as const,
    autoVerifyPublicInviteEmail: false,
    exposeEmailOnGet: false,
    adminRoles: ["admin"],
    adminUserIds: [] as string[],
    ...options
  };
  const orgOpts = opts.organization;

  const additionalFieldDefs: Record<string, InviteAdditionalField> = opts.additionalFields ?? {};
  for (const key of Object.keys(additionalFieldDefs)) {
    if (RESERVED_FIELD_NAMES.has(key)) {
      throw new Error(
        `better-enrollment: additional field "${key}" collides with a reserved redemption field`
      );
    }
  }

  // A required field with a defaultValue can never fail the required
  // check, so the invite page should render it as optional.
  const isEffectivelyRequired = (field: InviteAdditionalField): boolean =>
    field.required !== false && field.defaultValue === undefined;

  const fieldAppliesTo = (field: InviteAdditionalField, action: InviteFieldAction): boolean =>
    (field.actions ?? ["SIGN_UP"]).includes(action);

  /**
   * Validates the redeem body against the additional fields configured
   * for the given step, mirroring Better Auth's parseInputData semantics:
   * defaults applied when absent, required enforced, type checked (dates
   * accept ISO strings), then the standard-schema validator. Returns only
   * declared keys; everything else in the body is ignored.
   */
  function parseAdditionalFields(
    body: Record<string, unknown>,
    action: InviteFieldAction
  ): Record<string, unknown> {
    const invalid = (key: string, detail: string) =>
      APIError.from("BAD_REQUEST", {
        ...INVITE_ERROR_CODES.ADDITIONAL_FIELD_INVALID,
        message: `${key} ${detail}`
      });
    const out: Record<string, unknown> = {};
    for (const [key, field] of Object.entries(additionalFieldDefs)) {
      if (!fieldAppliesTo(field, action)) continue;
      let value = body[key];
      if (value === undefined || value === null) {
        if (field.defaultValue !== undefined) {
          // Only sign-up creates the row; a confirm updates an existing
          // user, where writing the default would clobber their data.
          if (action === "SIGN_UP") {
            out[key] =
              typeof field.defaultValue === "function" ? field.defaultValue() : field.defaultValue;
          }
        } else if (field.required !== false) {
          throw APIError.from("BAD_REQUEST", {
            ...INVITE_ERROR_CODES.ADDITIONAL_FIELD_REQUIRED,
            message: `${key} is required`
          });
        }
        continue;
      }
      if (field.type === "date" && (typeof value === "string" || typeof value === "number")) {
        const parsed = new Date(value);
        if (Number.isNaN(parsed.getTime())) throw invalid(key, "must be a valid date");
        value = parsed;
      }
      const typeOk =
        field.type === "string"
          ? typeof value === "string"
          : field.type === "number"
            ? typeof value === "number" && Number.isFinite(value)
            : field.type === "boolean"
              ? typeof value === "boolean"
              : value instanceof Date;
      if (!typeOk) throw invalid(key, `must be a ${field.type}`);
      if (field.validator?.input) {
        const result = field.validator.input["~standard"].validate(value);
        if (result instanceof Promise) {
          throw new APIError("INTERNAL_SERVER_ERROR", {
            message: "better-enrollment: async field validators are not supported"
          });
        }
        if ("issues" in result && result.issues) {
          throw invalid(key, result.issues[0]?.message ?? "failed validation");
        }
        value = (result as { value: unknown }).value;
      }
      out[key] = value;
    }
    return out;
  }

  const state = {
    mode: (opts.mode === "auto" ? null : opts.mode) as InviteMode | null,
    orgPluginPresent: false,
    // Resolved at init from the magic-link plugin and emailAndPassword.
    passwordless: false,
    credentialEnabled: false,
    magicLinkOptions: null as MagicLinkLikeOptions | null,
    // The admin plugin's own config: who may user:set-role is read from it.
    adminPluginOptions: null as AdminPluginLikeOptions | null,
    // The org plugin's creatorRole, which holds every org permission.
    orgCreatorRole: "owner",
    orgPluginOptions: null as OrgPluginLikeOptions | null
  };
  const getMode = (): InviteMode => {
    if (!state.mode) {
      throw new APIError("INTERNAL_SERVER_ERROR", {
        message: "better-enrollment: mode not resolved; plugin init did not run"
      });
    }
    return state.mode;
  };
  const orgEnabled = () => !!orgOpts && state.orgPluginPresent;

  // Bulk operations read and delete in pages of this size, so neither
  // memory nor IN-clause length grows with table size (drivers cap bind
  // parameters, e.g. 65535 on Postgres).
  const DB_PAGE = 1000;
  // Per-user secondary-storage calls in flight at once (bans, org delete).
  const SESSION_STORAGE_CONCURRENCY = 20;

  async function findInviteByToken(
    ctx: GenericEndpointContext,
    token: string
  ): Promise<Invite | null> {
    const tokenHash = await sha256Base64Url(token);
    return await ctx.context.adapter.findOne<Invite>({
      model: "invite",
      where: [{ field: "tokenHash", value: tokenHash }]
    });
  }

  /** expiresAt for a create or resend; a caller-sent lifetime is capped. */
  function inviteExpiresAt(requested: number | undefined, type: InviteType): Date | null {
    if (requested != null && opts.maxExpiresIn != null && requested > opts.maxExpiresIn) {
      throw APIError.from("UNPROCESSABLE_ENTITY", INVITE_ERROR_CODES.EXPIRES_IN_TOO_LONG);
    }
    const expiresIn = requested ?? (type === "public" ? opts.publicExpiresIn : opts.expiresIn);
    if (expiresIn == null) return null;
    const at = new Date(Date.now() + expiresIn * 1000);
    if (Number.isNaN(at.getTime())) {
      throw APIError.from("UNPROCESSABLE_ENTITY", INVITE_ERROR_CODES.EXPIRES_IN_TOO_LONG);
    }
    return at;
  }

  // Before-hooks run ahead of body validation: anything but a string is left
  // for the endpoint to reject with its own 400.
  function bodyEmail(ctx: GenericEndpointContext): string | undefined {
    const raw = (ctx.body as Record<string, unknown> | undefined)?.email;
    return typeof raw === "string" ? raw.toLowerCase().trim() || undefined : undefined;
  }

  /**
   * True when a non-accepted invite-only invite still owns a pre-created
   * shell for this email. Shells enter only through their invite; both
   * magic-link guards key on this.
   */
  async function hasPendingShellInvite(
    ctx: GenericEndpointContext,
    email: string
  ): Promise<boolean> {
    return (await inviteOnlyState(ctx, email)).shell;
  }

  /**
   * One read of the address's open invite-only invites: whether one still
   * owns a user pre-created by 0.x, whether a private one is pending (past
   * expiry included, like the email lock), and whether one is still live.
   */
  async function inviteOnlyState(
    ctx: GenericEndpointContext,
    email: string
  ): Promise<{ shell: boolean; pendingPrivate: boolean; livePrivate: boolean }> {
    let pendingPrivate = false;
    let livePrivate = false;
    // Usually one page: an address holds one invite per scope.
    for (let offset = 0; ; offset += DB_PAGE) {
      const invites = await ctx.context.adapter.findMany<Invite>({
        model: "invite",
        where: [
          { field: "email", value: email.toLowerCase() },
          { field: "mode", value: "invite-only" },
          { field: "status", value: ["pending", "cancelled"], operator: "in" }
        ],
        limit: DB_PAGE,
        offset,
        sortBy: { field: "id", direction: "asc" }
      });
      const privates = invites.filter((i) => i.status === "pending" && i.type === "private");
      pendingPrivate ||= privates.length > 0;
      livePrivate ||= privates.some((i) => !isExpired(i));
      if (invites.some((i) => i.preCreatedUserId)) {
        return { shell: true, pendingPrivate: true, livePrivate };
      }
      if (invites.length < DB_PAGE) return { shell: false, pendingPrivate, livePrivate };
    }
  }

  // An account is established once somebody can sign into it: verified, or
  // holding any account row (magic-link users are verified with zero rows).
  // Anything else is an inert pre-created shell.
  async function isEstablished(
    ctx: GenericEndpointContext,
    user: { id: string; emailVerified: boolean }
  ): Promise<boolean> {
    if (user.emailVerified) return true;
    const accounts = await ctx.context.internalAdapter.findAccounts(user.id);
    return accounts.length > 0;
  }

  // A private invite-only invite redeems as an activation (sign in, then
  // confirm) only against an established account. Its own shell, another
  // invite's inert shell, or no user at all are all sign-up: whichever live
  // token for the email is redeemed first claims the shell, so redemption
  // order across coexisting invites never matters. The one exception is an
  // own shell that already holds a login (left by a failed attempt before
  // redemptions were undone): its owner signs in with it instead.
  async function privateInviteActivates(
    ctx: GenericEndpointContext,
    invite: Invite
  ): Promise<boolean> {
    if (!invite.email) return false;
    if (invite.preCreatedUserId) {
      const own = await ctx.context.internalAdapter.findUserById(invite.preCreatedUserId);
      if (own) {
        const accounts = await ctx.context.internalAdapter.findAccounts(own.id);
        return accounts.length > 0;
      }
    }
    const user = unwrapUser(
      (await ctx.context.internalAdapter.findUserByEmail(invite.email)) as MaybeWithAccounts | null
    );
    return !!user && (await isEstablished(ctx, user));
  }

  function buildInviteUrl(ctx: GenericEndpointContext, token: string, type: InviteType): string {
    if (opts.buildInviteUrl) {
      return opts.buildInviteUrl({ token, type, mode: getMode() });
    }
    const origin = new URL(ctx.context.baseURL).origin;
    const sep = opts.linkStyle === "query" ? "?" : "#";
    return `${origin}/invite${sep}token=${encodeURIComponent(token)}`;
  }

  async function getAuthUser(ctx: GenericEndpointContext): Promise<BannableUser> {
    const session = ctx.context.session;
    if (!session) {
      throw new APIError("UNAUTHORIZED");
    }
    // Re-read from DB: never trust the cookie cache for a privilege gate.
    const user = (await ctx.context.internalAdapter.findUserById(
      session.user.id
    )) as BannableUser | null;
    if (!user) {
      throw new APIError("UNAUTHORIZED");
    }
    return user;
  }

  // AC mode engages when the app hands over its admin-plugin permission
  // file. `roles` alone works; `ac` alone falls back to defaultInviteRoles.
  const acMode = !!(opts.roles || opts.ac);
  const inviteAcRoles: Record<string, OrgRoleLike | undefined> = opts.roles ?? defaultInviteRoles;
  const acResource = opts.permissionResource ?? "invite";

  async function isInviteAdmin(
    user: BannableUser,
    action: InviteManagementAction
  ): Promise<boolean> {
    if (acMode) {
      // Mirrors the admin plugin's hasPermission: adminUserIds bypass,
      // then each held role is asked for <resource>:<action>.
      if (opts.adminUserIds.includes(user.id)) return true;
      const roles = splitRoles(user.role);
      if (roles.length === 0) roles.push(opts.defaultRole);
      return roles.some((r) => !!inviteAcRoles[r]?.authorize({ [acResource]: [action] }).success);
    }
    if (opts.canManageInvites) {
      return await opts.canManageInvites(user);
    }
    return (
      opts.adminUserIds.includes(user.id) ||
      splitRoles(user.role).some((r) => opts.adminRoles.includes(r))
    );
  }

  async function requireInviteAdmin(
    ctx: GenericEndpointContext,
    action: InviteManagementAction
  ): Promise<BannableUser> {
    const user = await getAuthUser(ctx);
    if (!(await isInviteAdmin(user, action))) {
      throw APIError.from("FORBIDDEN", INVITE_ERROR_CODES.NOT_ALLOWED_TO_MANAGE_INVITES);
    }
    return user;
  }

  /** org-create invites found organizations: `manage-orgs`, like the org controls. */
  async function assertMayFoundOrgs(user: BannableUser): Promise<void> {
    if (!(await isInviteAdmin(user, "manage-orgs"))) {
      throw APIError.from("FORBIDDEN", INVITE_ERROR_CODES.NOT_ALLOWED_TO_MANAGE_INVITES);
    }
  }

  // ------------------------------------------------------- role ceiling
  // An invite that grants a role is a role assignment. Whoever chooses or
  // receives the link must hold the right to assign it, so invite rights
  // never widen into role rights. All checks are in memory except the org
  // dynamic-role read, and run only on create, public resend and redeem.

  /** Full app role authority: what the admin plugin requires for set-role. */
  function holdsSetRole(user: BannableUser): boolean {
    if (opts.adminUserIds.includes(user.id)) return true;
    const admin = state.adminPluginOptions;
    if (admin) {
      // Mirrors the admin plugin's hasPermission exactly (no trimming).
      if (admin.adminUserIds?.includes(user.id)) return true;
      const held = (user.role || admin.defaultRole || "user").split(",");
      const acRoles = (admin.roles ?? adminPluginDefaultRoles) as Record<
        string,
        OrgRoleLike | undefined
      >;
      return held.some((r) => {
        try {
          return !!acRoles[r]?.authorize({ user: ["set-role"] }).success;
        } catch {
          return false;
        }
      });
    }
    // No admin plugin: no set-role to read. adminRoles are full admins;
    // a canManageInvites-only setup keeps its old behavior (warned at init).
    if (!acMode && opts.canManageInvites && !opts.canGrantRole && !opts.grantableRoles) {
      return true;
    }
    const held = splitRoles(user.role);
    if (acMode) {
      const grants = held.some((r) => {
        try {
          return !!inviteAcRoles[r]?.authorize({ user: ["set-role"] }).success;
        } catch {
          return false;
        }
      });
      if (grants) return true;
    }
    return held.some((r) => opts.adminRoles.includes(r));
  }

  async function canGrantAppRole(user: BannableUser, role: string): Promise<boolean> {
    const wanted = splitRoles(role);
    if (wanted.every((r) => r === opts.defaultRole)) return true;
    if (opts.canGrantRole) return !!(await opts.canGrantRole(user, role));
    const grantable = new Set(
      splitRoles(user.role).flatMap((r) => opts.grantableRoles?.[r] ?? [])
    );
    if (wanted.every((r) => r === opts.defaultRole || grantable.has(r))) return true;
    return holdsSetRole(user);
  }

  /** publicInviteRoles and organization.publicInviteRoles; null allows any role. */
  function assertPublicRolesAllowed(
    invite: Pick<Invite, "type" | "kind" | "role" | "organizationRole">,
    status: "UNPROCESSABLE_ENTITY" | "FORBIDDEN"
  ): void {
    if (invite.type !== "public") return;
    const appList =
      opts.publicInviteRoles === undefined ? [opts.defaultRole] : opts.publicInviteRoles;
    const orgList =
      orgOpts?.publicInviteRoles === undefined ? [defaultOrgRole()] : orgOpts.publicInviteRoles;
    const appOk = !appList || splitRoles(invite.role).every((r) => appList.includes(r));
    const orgOk =
      !orgList ||
      invite.kind !== "org-join" ||
      splitRoles(invite.organizationRole ?? defaultOrgRole()).every((r) => orgList.includes(r));
    if (!appOk || !orgOk) {
      throw APIError.from(status, INVITE_ERROR_CODES.ROLE_NOT_ALLOWED_FOR_PUBLIC_INVITE);
    }
  }

  async function assertCanGrantAppRole(user: BannableUser, role: string): Promise<void> {
    if (!(await canGrantAppRole(user, role))) {
      throw APIError.from("FORBIDDEN", INVITE_ERROR_CODES.ROLE_NOT_GRANTABLE);
    }
  }

  const defaultOrgRole = () => orgOpts?.defaultOrganizationRole ?? "member";

  /**
   * The org plugin's creatorRole ("owner" by default) controls the org. A
   * role merely named "owner" under another creatorRole is ordinary.
   */
  const isTopOrgRole = (role: string) => role === state.orgCreatorRole;

  /**
   * The owner rule: the creatorRole is granted only with allowOwnerInvites,
   * and only by a member who holds it, as the org plugin requires.
   */
  function mayGrantTopOrgRole(member: MemberRecord | null, role: string): boolean {
    if (!splitRoles(role).some(isTopOrgRole)) return true;
    return !!orgOpts?.allowOwnerInvites && !!member && splitRoles(member.role).some(isTopOrgRole);
  }

  /**
   * Whether a member may grant an org role through an invite. Used at
   * create, public resend, the role-change hook and the redemption re-check.
   */
  async function canGrantOrgRole(
    ctx: GenericEndpointContext,
    member: MemberRecord,
    org: OrganizationRecord,
    role: string
  ): Promise<boolean> {
    if (!mayGrantTopOrgRole(member, role)) return false;
    const wanted = splitRoles(role);
    const def = defaultOrgRole();
    if (wanted.every((r) => r === def)) return true;
    if (orgOpts?.canGrantOrgRole) return !!(await orgOpts.canGrantOrgRole(member, org, role));
    const grantable = new Set(
      splitRoles(member.role).flatMap((r) => orgOpts?.grantableRoles?.[r] ?? [])
    );
    if (wanted.every((r) => r === def || grantable.has(r))) return true;
    return await memberHasOrgPermission(ctx, member, "member", "update");
  }

  async function assertCanGrantOrgRole(
    ctx: GenericEndpointContext,
    member: MemberRecord,
    org: OrganizationRecord,
    role: string
  ): Promise<void> {
    if (!(await canGrantOrgRole(ctx, member, org, role))) {
      throw APIError.from("FORBIDDEN", INVITE_ERROR_CODES.ORG_ROLE_NOT_GRANTABLE);
    }
  }

  /**
   * Redeeming your own invite assigns its roles to yourself. Allowed only
   * with full authority for each: user:set-role for the app role,
   * member:update in the org for the org role, manage-orgs for founding an
   * org through org-create. grantableRoles and the
   * canGrant callbacks delegate granting to others, never to oneself.
   */
  async function assertNotSelfGrant(
    ctx: GenericEndpointContext,
    invite: Invite,
    userId: string
  ): Promise<void> {
    if (!invite.createdByUserId || invite.createdByUserId !== userId) return;
    const fresh = (await ctx.context.internalAdapter.findUserById(userId)) as BannableUser | null;
    let allowed = !!fresh;
    if (allowed && !splitRoles(invite.role).every((r) => r === opts.defaultRole)) {
      allowed = holdsSetRole(fresh!);
    }
    if (allowed && invite.kind === "org-create") {
      allowed = await isInviteAdmin(fresh!, "manage-orgs");
    }
    if (allowed && invite.kind === "org-join" && invite.organizationId) {
      const orgRole = invite.organizationRole ?? defaultOrgRole();
      if (!splitRoles(orgRole).every((r) => r === defaultOrgRole())) {
        const member = await findMember(ctx, userId, invite.organizationId);
        allowed =
          !!member &&
          mayGrantTopOrgRole(member, orgRole) &&
          (await memberHasOrgPermission(ctx, member, "member", "update"));
      }
    }
    if (!allowed) {
      throw APIError.from("FORBIDDEN", INVITE_ERROR_CODES.CANNOT_REDEEM_OWN_INVITE);
    }
  }

  /**
   * onInviteExpired at most once per invite: the reader that stamps
   * expiryNotifiedAt fires it. Not updatedAt, which the resend cooldown reads.
   */
  async function notifyExpired(ctx: GenericEndpointContext, invite: Invite): Promise<void> {
    if (!opts.onInviteExpired || invite.expiryNotifiedAt) return;
    const stamped = await ctx.context.adapter.updateMany({
      model: "invite",
      where: [
        { field: "id", value: invite.id },
        { field: "expiryNotifiedAt", value: null }
      ],
      update: { expiryNotifiedAt: new Date() }
    });
    if (stamped > 0) await opts.onInviteExpired({ invite });
  }

  /**
   * One existing-account notice per public invite and address per
   * cooldown. First writer wins through Better Auth's verification store;
   * an expired marker is replaced. Fails closed: no store, no mail.
   */
  async function noticeDue(
    ctx: GenericEndpointContext,
    invite: Invite,
    email: string
  ): Promise<boolean> {
    const cooldown = opts.existingAccountNoticeCooldown ?? 24 * 60 * 60;
    if (cooldown <= 0) return true;
    const ia = ctx.context.internalAdapter;
    const identifier = `better-enrollment-notice:${invite.id}:${email.toLowerCase()}`;
    const marker = () => ({
      identifier,
      value: "1",
      expiresAt: new Date(Date.now() + cooldown * 1000)
    });
    if (await ia.reserveVerificationValue(marker())) return true;
    const prior = await ia.findVerificationValue(identifier);
    if (prior && new Date(prior.expiresAt) > new Date()) return false;
    await ia.deleteVerificationByIdentifier(identifier);
    return await ia.reserveVerificationValue(marker());
  }

  async function assertUsable(
    ctx: GenericEndpointContext,
    invite: Invite | null
  ): Promise<Invite> {
    if (!invite) {
      throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.INVITE_NOT_FOUND);
    }
    if (invite.status === "cancelled") {
      throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.INVITE_REVOKED);
    }
    if (invite.status === "accepted") {
      throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.INVITE_ALREADY_USED);
    }
    if (isExpired(invite)) {
      await notifyExpired(ctx, invite);
      throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.INVITE_EXPIRED);
    }
    return invite;
  }

  async function resolveRole(invite: Invite): Promise<string> {
    if (!opts.validRoles || opts.validRoles.includes(invite.role)) {
      return invite.role;
    }
    if (opts.fallbackRole) return opts.fallbackRole;
    await opts.onInvalidRole?.({ invite, role: invite.role });
    throw APIError.from("UNPROCESSABLE_ENTITY", INVITE_ERROR_CODES.ROLE_NO_LONGER_VALID);
  }

  // Atomic claim: the where clause doubles as guard, losers get null.
  async function claimUse(ctx: GenericEndpointContext, invite: Invite): Promise<Invite | null> {
    const singleUse = invite.type === "private" || invite.maxUses === 1;
    return await ctx.context.adapter.incrementOne<Invite>({
      model: "invite",
      where: [
        { field: "id", value: invite.id },
        { field: "status", value: "pending" },
        ...(invite.maxUses != null
          ? [
              {
                field: "useCount",
                value: invite.maxUses,
                operator: "lt" as const
              }
            ]
          : [])
      ],
      increment: { useCount: 1 },
      set: {
        updatedAt: new Date(),
        ...(singleUse ? { status: "accepted" } : {})
      }
    });
  }

  async function rollbackClaim(ctx: GenericEndpointContext, invite: Invite): Promise<void> {
    try {
      // Return exactly this claim's +1. No snapshot CAS: under parallel
      // claims the live count differs from this claimer's snapshot, and a
      // rollback that silently matches nothing strands the invite.
      await ctx.context.adapter.incrementOne({
        model: "invite",
        where: [
          { field: "id", value: invite.id },
          { field: "useCount", value: 0, operator: "gt" as const }
        ],
        increment: { useCount: -1 },
        set: { updatedAt: new Date() }
      });
      // Reopen a settle or single-use flip, never a revocation, and only
      // while the freed seat actually exists.
      await ctx.context.adapter.update({
        model: "invite",
        where: [
          { field: "id", value: invite.id },
          { field: "status", value: "accepted" },
          ...(invite.maxUses != null
            ? [{ field: "useCount", value: invite.maxUses, operator: "lt" as const }]
            : [])
        ],
        update: { status: "pending", updatedAt: new Date() }
      });
    } catch (e) {
      ctx.context.logger.error(`better-enrollment: claim rollback failed: ${String(e)}`);
    }
  }

  /**
   * Records a redemption; the undo log gets its removal. Every write after
   * the claim registers an undo the same way, so a redemption that fails at
   * any step leaves nothing behind (no adapter-agnostic transaction exists).
   */
  async function recordUse(
    ctx: GenericEndpointContext,
    invite: Invite,
    userId: string,
    email: string,
    undo: Undo[]
  ): Promise<void> {
    const use = await ctx.context.adapter.create<Omit<InviteUse, "id">, InviteUse>({
      model: "inviteUse",
      data: {
        inviteId: invite.id,
        usedByUserId: userId,
        inviteeEmail: email.toLowerCase(),
        usedAt: new Date()
      }
    });
    undo.push(() =>
      ctx.context.adapter.delete({ model: "inviteUse", where: [{ field: "id", value: use.id }] })
    );
  }

  /** Runs a failed redemption's undo steps newest first; each is best effort. */
  async function runUndo(ctx: GenericEndpointContext, undo: Undo[]): Promise<void> {
    for (const step of [...undo].reverse()) {
      try {
        await step();
      } catch (e) {
        ctx.context.logger.error(
          `better-enrollment: undo after failed redemption failed: ${String(e)}`
        );
      }
    }
  }

  /** The user columns a redemption overwrites, as they were before it. */
  function userSnapshot(user: User, keys: string[]): Record<string, unknown> {
    const row = user as unknown as Record<string, unknown>;
    return Object.fromEntries(keys.map((k) => [k, row[k] ?? null]));
  }

  // Public invites flip to accepted only once the cap is reached.
  async function settlePublicStatus(ctx: GenericEndpointContext, claimed: Invite): Promise<void> {
    if (claimed.maxUses != null && claimed.useCount >= claimed.maxUses) {
      await ctx.context.adapter.update({
        model: "invite",
        where: [
          { field: "id", value: claimed.id },
          { field: "status", value: "pending" },
          // Guard on the live count, not this claimer's snapshot: a
          // parallel loser may have rolled its use back since.
          { field: "useCount", value: claimed.maxUses, operator: "gte" as const }
        ],
        update: { status: "accepted", updatedAt: new Date() }
      });
    }
  }

  // Deletes a non-accepted invite plus its never-redeemed shell.
  async function deleteInviteAndInertUser(
    ctx: GenericEndpointContext,
    invite: Invite
  ): Promise<void> {
    if (invite.preCreatedUserId) {
      await deleteInertShells(ctx.context, [invite.preCreatedUserId]);
    }
    await ctx.context.adapter.deleteMany({
      model: "inviteUse",
      where: [{ field: "inviteId", value: invite.id }]
    });
    await ctx.context.adapter.delete({
      model: "invite",
      where: [{ field: "id", value: invite.id }]
    });
  }

  // Removes the pre-created shells of invites being withdrawn (revoke,
  // delete, cleanup, org deletion; callers pass only non-accepted invites).
  // A shell with no recorded redemption goes whatever state it reached, so
  // a withdrawn invite never leaves a claimable account behind. Users with
  // an inviteUse row redeemed something and stay.
  async function deleteInertShells(c: AuthCtx, userIds: string[]): Promise<void> {
    if (userIds.length === 0) return;
    const users = await c.adapter.findMany<{ id: string; emailVerified: boolean }>({
      model: "user",
      where: [{ field: "id", value: userIds, operator: "in" }],
      limit: userIds.length
    });
    if (users.length === 0) return;
    const ids = users.map((u) => u.id);
    const uses = await c.adapter.findMany<{ usedByUserId: string }>({
      model: "inviteUse",
      where: [{ field: "usedByUserId", value: ids, operator: "in" }],
      limit: 100000
    });
    const redeemed = new Set(uses.map((u) => u.usedByUserId));
    const shells = users.filter((u) => !redeemed.has(u.id));
    if (shells.length === 0) return;
    const accounts = await c.adapter.findMany<{ userId: string }>({
      model: "account",
      where: [{ field: "userId", value: shells.map((u) => u.id), operator: "in" }],
      limit: 100000
    });
    const linked = new Set(accounts.map((a) => a.userId));
    // Shells activated outside redemption (before the shell guards existed)
    // may hold accounts and sessions; end those in whatever storage first.
    const touched = shells.filter((u) => u.emailVerified || linked.has(u.id)).map((u) => u.id);
    if (touched.length > 0) {
      for (const id of touched) await c.internalAdapter.deleteUserSessions(id);
      await c.adapter.deleteMany({
        model: "account",
        where: [{ field: "userId", value: touched, operator: "in" }]
      });
    }
    // Raw delete, so the user.delete hook (invitee cleanup) never runs for
    // a shell: removing one invite's shell must not cancel the same
    // address's invites in other scopes.
    await c.adapter.deleteMany({
      model: "user",
      where: [{ field: "id", value: shells.map((u) => u.id), operator: "in" }]
    });
  }

  async function notifyCancelled(c: AuthCtx, data: InvitesCancelledData): Promise<void> {
    if (!opts.onInvitesCancelled || data.inviteIds.length === 0) return;
    try {
      await opts.onInvitesCancelled(data);
    } catch (e) {
      c.logger.error(`better-enrollment: onInvitesCancelled failed: ${String(e)}`);
    }
  }

  /**
   * Cancels pending invites matching `where`, a page at a time, and removes
   * their never-redeemed shells like revoke does. `keep` leaves an invite
   * pending. Sorted by id so offset paging over kept rows stays exact.
   */
  async function cancelPendingInvites(
    c: AuthCtx,
    where: { field: string; value: string | string[]; operator?: "in" }[],
    reason: InviteCancelReason,
    scope: { userId?: string | null; organizationId?: string | null },
    keep?: (invite: Invite) => Promise<boolean> | boolean
  ): Promise<number> {
    let offset = 0;
    let total = 0;
    for (;;) {
      const page = await c.adapter.findMany<Invite>({
        model: "invite",
        where: [...where, { field: "status", value: "pending" }],
        limit: DB_PAGE,
        offset,
        sortBy: { field: "id", direction: "asc" }
      });
      if (page.length === 0) break;
      const cancel: Invite[] = [];
      for (const invite of page) {
        if (!(keep && (await keep(invite)))) cancel.push(invite);
      }
      if (cancel.length > 0) {
        const now = new Date();
        const ids = cancel.map((i) => i.id);
        await c.adapter.updateMany({
          model: "invite",
          where: [
            { field: "id", value: ids, operator: "in" },
            { field: "status", value: "pending" }
          ],
          update: { status: "cancelled", revokedAt: now, updatedAt: now }
        });
        // Only rows this call cancelled: a parallel redemption may have
        // claimed one in between, and its shell is now a real account.
        const done = await c.adapter.findMany<Invite>({
          model: "invite",
          where: [
            { field: "id", value: ids, operator: "in" },
            { field: "status", value: "cancelled" }
          ],
          limit: ids.length
        });
        await deleteInertShells(
          c,
          done.map((i) => i.preCreatedUserId).filter((v): v is string => !!v)
        );
        await notifyCancelled(c, {
          reason,
          inviteIds: done.map((i) => i.id),
          deleted: false,
          userId: scope.userId ?? null,
          organizationId: scope.organizationId ?? null
        });
        total += done.length;
      }
      offset += page.length - cancel.length;
      if (page.length < DB_PAGE) break;
    }
    return total;
  }

  /** Deletes a removed user's pending invites, a page at a time. */
  async function deleteCreatorInvites(c: AuthCtx, userId: string): Promise<void> {
    for (;;) {
      const page = await c.adapter.findMany<Invite>({
        model: "invite",
        where: [
          { field: "createdByUserId", value: userId },
          { field: "status", value: "pending" }
        ],
        limit: DB_PAGE
      });
      if (page.length === 0) break;
      const ids = page.map((i) => i.id);
      await deleteInertShells(
        c,
        page.map((i) => i.preCreatedUserId).filter((v): v is string => !!v)
      );
      await c.adapter.deleteMany({
        model: "inviteUse",
        where: [{ field: "inviteId", value: ids, operator: "in" }]
      });
      await c.adapter.deleteMany({
        model: "invite",
        where: [{ field: "id", value: ids, operator: "in" }]
      });
      await notifyCancelled(c, {
        reason: "inviter-deleted",
        inviteIds: ids,
        deleted: true,
        userId,
        organizationId: null
      });
      if (page.length < DB_PAGE) break;
    }
  }

  /**
   * The creator of an invite must still exist and not be banned when it is
   * read or redeemed; with revalidateInviterOnRedeem, also still hold the
   * rights it used. Otherwise the invite is cancelled on the spot. Returns
   * the invite as it now stands. One primary-key read; none for system
   * invites without an attributed user.
   */
  async function settleInviter(ctx: GenericEndpointContext, invite: Invite): Promise<Invite> {
    if (!invite.createdByUserId || deriveStatus(invite) !== "pending") return invite;
    const creator = (await ctx.context.internalAdapter.findUserById(
      invite.createdByUserId
    )) as BannableUser | null;
    let active = !!creator && !isBanned(creator);
    if (active && opts.revalidateInviterOnRedeem !== false && !invite.createdBySystem) {
      active = await inviterStillAuthorized(ctx, invite, creator!);
    }
    if (active) return invite;
    const cancelled = await ctx.context.adapter.update<Invite>({
      model: "invite",
      where: [
        { field: "id", value: invite.id },
        { field: "status", value: "pending" }
      ],
      update: { status: "cancelled", revokedAt: new Date(), updatedAt: new Date() }
    });
    if (!cancelled) return invite;
    if (cancelled.preCreatedUserId) {
      await deleteInertShells(ctx.context, [cancelled.preCreatedUserId]);
    }
    await notifyCancelled(ctx.context, {
      reason: "inviter-inactive",
      inviteIds: [cancelled.id],
      deleted: false,
      userId: invite.createdByUserId,
      organizationId: invite.organizationId ?? null
    });
    return cancelled;
  }

  async function inviterStillAuthorized(
    ctx: GenericEndpointContext,
    invite: Invite,
    creator: BannableUser
  ): Promise<boolean> {
    if (invite.kind === "org-join" && invite.organizationId) {
      const org = await findOrg(ctx, invite.organizationId);
      const member = org ? await findMember(ctx, creator.id, org.id) : null;
      if (!org || !member) return false;
      const mayCreate = orgOpts?.canCreateOrgInvites
        ? await orgOpts.canCreateOrgInvites(member, org)
        : await memberHasInvitePermission(ctx, member, "create");
      return (
        mayCreate &&
        (await canGrantOrgRole(ctx, member, org, invite.organizationRole ?? defaultOrgRole()))
      );
    }
    return (
      (await isInviteAdmin(creator, "create")) &&
      (invite.kind !== "org-create" || (await isInviteAdmin(creator, "manage-orgs"))) &&
      (await canGrantAppRole(creator, invite.role))
    );
  }

  // ---------------------------------------------------------------- org

  async function findOrg(
    ctx: GenericEndpointContext,
    organizationId: string
  ): Promise<OrganizationRecord | null> {
    return await ctx.context.adapter.findOne<OrganizationRecord>({
      model: "organization",
      where: [{ field: "id", value: organizationId }]
    });
  }

  async function findMember(
    ctx: GenericEndpointContext,
    userId: string,
    organizationId: string
  ): Promise<MemberRecord | null> {
    return await ctx.context.adapter.findOne<MemberRecord>({
      model: "member",
      where: [
        { field: "userId", value: userId },
        { field: "organizationId", value: organizationId }
      ]
    });
  }

  async function dynamicOrgRoles(
    ctx: GenericEndpointContext,
    organizationId: string
  ): Promise<{ role: string; permission: unknown }[]> {
    // The organizationRole table only exists with dynamic access control.
    const all: { role: string; permission: unknown }[] = [];
    try {
      for (let offset = 0; ; offset += DB_PAGE) {
        const page = await ctx.context.adapter.findMany<{ role: string; permission: unknown }>({
          model: "organizationRole",
          where: [{ field: "organizationId", value: organizationId }],
          limit: DB_PAGE,
          offset,
          sortBy: { field: "id", direction: "asc" }
        });
        all.push(...page);
        if (page.length < DB_PAGE) return all;
      }
    } catch {
      return [];
    }
  }

  async function memberHasInvitePermission(
    ctx: GenericEndpointContext,
    member: MemberRecord,
    action: "create" | "cancel"
  ): Promise<boolean> {
    return await memberHasOrgPermission(ctx, member, "invitation", action);
  }

  async function memberHasOrgPermission(
    ctx: GenericEndpointContext,
    member: MemberRecord,
    resource: "invitation" | "member",
    action: string
  ): Promise<boolean> {
    const roles = splitRoles(member.role);
    // The org plugin's update-member-role passes the creator role
    // regardless of the roles record (allowCreatorAllPermissions).
    if (resource === "member" && roles.includes(state.orgCreatorRole)) return true;
    for (const name of roles) {
      const configured = orgOpts?.roles?.[name];
      if (configured?.authorize) {
        try {
          if (configured.authorize({ [resource]: [action] }).success) {
            return true;
          }
          continue;
        } catch {
          continue;
        }
      }
      // Org plugin defaults apply only when no roles record was given,
      // mirroring its hasPermission (options.roles || defaultRoles):
      // owner and admin hold invitation create/cancel and member update.
      if (!orgOpts?.roles && (name === "owner" || name === "admin")) return true;
    }
    const dynamic = await dynamicOrgRoles(ctx, member.organizationId);
    for (const row of dynamic) {
      if (!roles.includes(row.role)) continue;
      try {
        const permission =
          typeof row.permission === "string"
            ? (JSON.parse(row.permission) as Record<string, string[]>)
            : (row.permission as Record<string, string[]> | null);
        if (permission?.[resource]?.includes(action)) return true;
      } catch {
        // unreadable permission blob: treat as no grant
      }
    }
    return false;
  }

  /**
   * Gate for org-join management. Unknown org and non-membership throw the
   * identical FORBIDDEN so organization ids cannot be enumerated.
   */
  /**
   * Loads an invite addressed by id once the caller may manage it. Callers
   * without rights get the same error whether the invite is missing, an
   * app invite, or another org's, so ids and states reveal nothing; app
   * admins get the precise INVITE_NOT_FOUND.
   */
  async function inviteForManagement(
    ctx: GenericEndpointContext,
    user: BannableUser,
    inviteId: string,
    adminAction: InviteManagementAction,
    orgAction: "create" | "cancel"
  ): Promise<{ invite: Invite; org: OrganizationRecord | null; member: MemberRecord | null }> {
    const invite = await ctx.context.adapter.findOne<Invite>({
      model: "invite",
      where: [{ field: "id", value: inviteId }]
    });
    if (await isInviteAdmin(user, adminAction)) {
      if (!invite) throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.INVITE_NOT_FOUND);
      const org = invite.organizationId ? await findOrg(ctx, invite.organizationId) : null;
      return { invite, org, member: null };
    }
    // One code per app setup, never per invite: without orgs a non-admin
    // can manage nothing; with orgs every refusal is the org gate's error.
    if (!orgEnabled()) {
      throw APIError.from("FORBIDDEN", INVITE_ERROR_CODES.NOT_ALLOWED_TO_MANAGE_INVITES);
    }
    if (!invite?.organizationId) {
      throw APIError.from("FORBIDDEN", INVITE_ERROR_CODES.ORG_INVITE_NOT_ALLOWED);
    }
    const { org, member } = await requireOrgInviteAccess(ctx, user, invite.organizationId, orgAction);
    return { invite, org, member };
  }

  async function requireOrgInviteAccess(
    ctx: GenericEndpointContext,
    user: BannableUser,
    organizationId: string,
    action: "create" | "cancel"
  ): Promise<{ org: OrganizationRecord; member: MemberRecord }> {
    const org = await findOrg(ctx, organizationId);
    const member = org ? await findMember(ctx, user.id, org.id) : null;
    let allowed = false;
    if (org && member) {
      if (action === "create" && orgOpts?.canCreateOrgInvites) {
        allowed = await orgOpts.canCreateOrgInvites(member, org);
      } else {
        allowed = await memberHasInvitePermission(ctx, member, action);
      }
    }
    if (!org || !member || !allowed) {
      throw APIError.from("FORBIDDEN", INVITE_ERROR_CODES.ORG_INVITE_NOT_ALLOWED);
    }
    // After the membership check, so disabled state never leaks to outsiders. App admins
    // never reach this gate and keep moderating a disabled org's invites.
    if (org.disabledAt) {
      throw APIError.from("FORBIDDEN", INVITE_ERROR_CODES.ORG_DISABLED);
    }
    return { org, member };
  }

  async function knownOrgRoles(
    ctx: GenericEndpointContext,
    organizationId: string
  ): Promise<string[]> {
    const base = orgOpts?.roles ? Object.keys(orgOpts.roles) : ["owner", "admin", "member"];
    const dynamic = await dynamicOrgRoles(ctx, organizationId);
    return [...new Set([...base, ...dynamic.map((r) => r.role)])];
  }

  async function seatLimitFor(
    ctx: GenericEndpointContext,
    org: OrganizationRecord
  ): Promise<number | null> {
    if (orgOpts?.resolveSeatLimit) {
      const resolved = await orgOpts.resolveSeatLimit(org);
      if (resolved !== undefined) return resolved;
    }
    if (org.seatLimit != null) return org.seatLimit;
    return orgOpts?.defaultSeatLimit ?? null;
  }

  /**
   * Members plus seats held by pending invites. Seat races are closed by
   * write, then verify: a writer that sees the total over the limit after
   * its own write backs out. Whoever checks last sees every earlier write,
   * so the limit is never exceeded; two writers racing for the last seat
   * may both back out. Adapters give no insertion order to rank by.
   */
  async function seatUsage(
    ctx: GenericEndpointContext,
    organizationId: string
  ): Promise<{ members: number; reserved: number }> {
    const members = await ctx.context.adapter.count({
      model: "member",
      where: [{ field: "organizationId", value: organizationId }]
    });
    // Reservation math needs each row's maxUses/useCount, so this cannot
    // be a count; paging keeps memory flat for invite-heavy orgs.
    const now = new Date();
    let reserved = 0;
    let offset = 0;
    for (;;) {
      const pending = await ctx.context.adapter.findMany<Invite>({
        model: "invite",
        where: [
          { field: "organizationId", value: organizationId },
          { field: "status", value: "pending" }
        ],
        limit: DB_PAGE,
        offset
      });
      reserved += pending.reduce((sum, i) => sum + reservedSeats(i, now), 0);
      if (pending.length < DB_PAGE) break;
      offset += DB_PAGE;
    }
    return { members, reserved };
  }

  function isBanned(user: unknown): boolean {
    return (user as { banned?: boolean | null } | null)?.banned === true;
  }

  /**
   * Redemption-time org preconditions, checked BEFORE the invite claim so
   * failures are clean. State can change between create and accept.
   */
  async function assertOrgRedeemable(
    ctx: GenericEndpointContext,
    invite: Invite,
    body: RedeemBody
  ): Promise<OrgPrecheck> {
    if (invite.kind === "org-join") {
      if (!orgEnabled() || !invite.organizationId) {
        throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.INVITE_NOT_FOUND);
      }
      const org = await findOrg(ctx, invite.organizationId);
      if (!org) {
        // Org gone: the invite died with it.
        throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.INVITE_NOT_FOUND);
      }
      if (org.disabledAt) {
        throw APIError.from("FORBIDDEN", INVITE_ERROR_CODES.ORG_DISABLED);
      }
      return { org };
    }
    if (invite.kind === "org-create") {
      if (!orgEnabled()) {
        throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.INVITE_NOT_FOUND);
      }
      if (invite.presetOrganizationName) {
        // The inviter fixed the org; redeem body org fields are ignored.
        const name = invite.presetOrganizationName;
        const slug = await availableSlug(ctx, invite.presetOrganizationSlug ?? slugify(name));
        return { orgInput: { name, slug }, preset: true };
      }
      const name = body.organizationName?.trim();
      const slug = body.organizationSlug ? normalizeOrgSlug(body.organizationSlug) : "";
      if (!name || !slug) {
        throw APIError.from("UNPROCESSABLE_ENTITY", INVITE_ERROR_CODES.ORG_INFO_REQUIRED);
      }
      assertValidOrgFields(name, slug);
      const existing = await ctx.context.adapter.findOne<OrganizationRecord>({
        model: "organization",
        where: [{ field: "slug", value: slug }]
      });
      if (existing) {
        throw APIError.from("CONFLICT", INVITE_ERROR_CODES.ORG_SLUG_TAKEN);
      }
      return { orgInput: { name, slug } };
    }
    return {};
  }

  /** Same rules the client checks before sending (src/validation.ts). */
  function assertValidOrgFields(name: string | undefined, slug: string | undefined): void {
    if (name !== undefined && !isValidOrgName(name)) {
      throw APIError.from("UNPROCESSABLE_ENTITY", INVITE_ERROR_CODES.INVALID_ORG_NAME);
    }
    if (slug !== undefined && !isValidOrgSlug(slug)) {
      throw APIError.from("UNPROCESSABLE_ENTITY", INVITE_ERROR_CODES.INVALID_ORG_SLUG);
    }
  }

  async function slugTaken(ctx: GenericEndpointContext, slug: string): Promise<boolean> {
    const existing = await ctx.context.adapter.findOne<OrganizationRecord>({
      model: "organization",
      where: [{ field: "slug", value: slug }]
    });
    return !!existing;
  }

  // The base gives up room so suffixed slugs stay within the slug rule.
  const suffixed = (base: string) =>
    `${base.slice(0, ORG_SLUG_MAX_LENGTH - 7).replace(/-+$/, "")}-${generateRandomString(6, "a-z", "0-9")}`;

  // A preset invite cannot ask the redeemer for another slug, so a taken
  // one gets a random suffix instead of failing the redemption.
  async function availableSlug(ctx: GenericEndpointContext, base: string): Promise<string> {
    if (!(await slugTaken(ctx, base))) return base;
    for (let i = 0; i < SLUG_SUFFIX_ATTEMPTS; i++) {
      const candidate = suffixed(base);
      if (!(await slugTaken(ctx, candidate))) return candidate;
    }
    throw APIError.from("CONFLICT", INVITE_ERROR_CODES.ORG_SLUG_TAKEN);
  }

  async function runBeforeOrgCreate(
    invite: Invite,
    user: User,
    pre: OrgPrecheck
  ): Promise<OrgPrecheck> {
    if (invite.kind !== "org-create" || !pre.orgInput || !orgOpts?.beforeOrgCreate) return pre;
    const fields = await orgOpts.beforeOrgCreate({
      invite,
      user,
      organization: { ...pre.orgInput }
    });
    return fields ? { ...pre, orgFields: fields } : pre;
  }

  async function createFoundedOrg(
    ctx: GenericEndpointContext,
    invite: Invite,
    input: { name: string; slug: string },
    pre: OrgPrecheck,
    now: Date
  ): Promise<OrganizationRecord> {
    const { id: _id, ...orgFields } = pre.orgFields ?? {};
    let slug = input.slug;
    for (let attempt = 0; ; attempt++) {
      try {
        return await ctx.context.adapter.create<Omit<OrganizationRecord, "id">, OrganizationRecord>(
          {
            model: "organization",
            data: {
              ...orgFields,
              name: input.name,
              slug,
              createdAt: now,
              seatLimit: invite.presetSeatLimit ?? null,
              disabledAt: null
            }
          }
        );
      } catch (e) {
        // Unique slug race between precheck and create.
        if (!pre.preset) throw APIError.from("CONFLICT", INVITE_ERROR_CODES.ORG_SLUG_TAKEN);
        if (attempt >= SLUG_SUFFIX_ATTEMPTS || !(await slugTaken(ctx, slug))) throw e;
        slug = suffixed(invite.presetOrganizationSlug ?? slugify(input.name));
      }
    }
  }

  async function resolveOrgRoleForRedeem(
    ctx: GenericEndpointContext,
    invite: Invite,
    organizationId: string
  ): Promise<string> {
    const fallback = orgOpts?.defaultOrganizationRole ?? "member";
    const requested = invite.organizationRole ?? fallback;
    const known = await knownOrgRoles(ctx, organizationId);
    // A role deleted between create and accept degrades to the default.
    return known.includes(requested) ? requested : fallback;
  }

  /**
   * Runs after the claim inside the redemption flow. Creates the member
   * (and team membership) for org-join, or founds the org for org-create.
   */
  async function applyOrgEffects(
    ctx: GenericEndpointContext,
    invite: Invite,
    user: User,
    pre: OrgPrecheck,
    undo: Undo[]
  ): Promise<OrganizationRecord | null> {
    if (invite.kind === "app") return null;
    const now = new Date();
    const adapter = ctx.context.adapter;
    const removeMember = (id: string) => () =>
      adapter.delete({ model: "member", where: [{ field: "id", value: id }] });

    if (invite.kind === "org-create") {
      if (!pre.orgInput) return null;
      const org = await createFoundedOrg(ctx, invite, pre.orgInput, pre, now);
      undo.push(() =>
        adapter.delete({ model: "organization", where: [{ field: "id", value: org.id }] })
      );
      const member = await adapter.create<Record<string, unknown>, MemberRecord>({
        model: "member",
        data: await memberDataFor(org, user, orgOpts?.orgCreateRole ?? state.orgCreatorRole, now)
      });
      undo.push(removeMember(member.id));
      await orgPluginHooks()?.afterAddMember?.({ member, user, organization: org });
      await orgOpts?.onOrgMemberAdded?.({
        organization: org,
        member,
        user,
        invite,
        teamAdded: false
      });
      return org;
    }

    // org-join
    const org = pre.org ?? (await findOrg(ctx, invite.organizationId!));
    if (!org) {
      throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.INVITE_NOT_FOUND);
    }
    const existing = await findMember(ctx, user.id, org.id);
    const orgRole = await resolveOrgRoleForRedeem(ctx, invite, org.id);
    if (existing) {
      // Already a member: merge org roles, consume no seat.
      await adapter.update({
        model: "member",
        where: [{ field: "id", value: existing.id }],
        update: { role: mergeRoles(existing.role, orgRole) }
      });
      undo.push(() =>
        adapter.update({
          model: "member",
          where: [{ field: "id", value: existing.id }],
          update: { role: existing.role }
        })
      );
      return org;
    }
    const limit = await seatLimitFor(ctx, org);
    const membershipLimit = await orgPluginMembershipLimit(user, org);
    if (limit != null || membershipLimit != null) {
      // Fast refusal before writing anything.
      const members = await ctx.context.adapter.count({
        model: "member",
        where: [{ field: "organizationId", value: org.id }]
      });
      await assertWithinMemberLimits(org, invite, members, limit, membershipLimit);
    }
    const member = await ctx.context.adapter.create<Record<string, unknown>, MemberRecord>({
      model: "member",
      data: await memberDataFor(org, user, orgRole, now)
    });
    if (limit != null || membershipLimit != null) {
      // Write, then verify (see seatUsage): parallel redemptions can all
      // pass the count above; over the limit, this member row backs out.
      const total = await ctx.context.adapter.count({
        model: "member",
        where: [{ field: "organizationId", value: org.id }]
      });
      try {
        await assertWithinMemberLimits(org, invite, total - 1, limit, membershipLimit);
      } catch (e) {
        await removeMember(member.id)();
        throw e;
      }
    }
    undo.push(removeMember(member.id));
    let teamAdded = false;
    if (invite.teamId && (await teamHasRoom(ctx.context, invite.teamId))) {
      // Team deleted since creation: join the org, skip the team.
      const team = await ctx.context.adapter
        .findOne<TeamRecord>({
          model: "team",
          where: [{ field: "id", value: invite.teamId }]
        })
        .catch(() => null);
      if (team && team.organizationId === org.id) {
        const teamMember = await adapter.create<Record<string, unknown>, { id: string }>({
          model: "teamMember",
          data: {
            teamId: invite.teamId,
            userId: user.id,
            createdAt: now
          }
        });
        undo.push(() =>
          adapter.delete({ model: "teamMember", where: [{ field: "id", value: teamMember.id }] })
        );
        teamAdded = true;
      }
    }
    await orgPluginHooks()?.afterAddMember?.({ member, user, organization: org });
    await orgOpts?.onOrgMemberAdded?.({
      organization: org,
      member,
      user,
      invite,
      teamAdded
    });
    return org;
  }

  /** The org plugin's organizationHooks, unless runOrgPluginHooks is false. */
  function orgPluginHooks(): OrgPluginLikeOptions["organizationHooks"] {
    return orgOpts?.runOrgPluginHooks !== false
      ? state.orgPluginOptions?.organizationHooks
      : undefined;
  }

  /** Member row data, passed through the org plugin's beforeAddMember when enabled. */
  async function memberDataFor(
    org: OrganizationRecord,
    user: User,
    role: string,
    now: Date
  ): Promise<Record<string, unknown>> {
    const data = { organizationId: org.id, userId: user.id, role, createdAt: now };
    const res = await orgPluginHooks()?.beforeAddMember?.({
      member: { userId: user.id, organizationId: org.id, role },
      user,
      organization: org
    });
    return res && typeof res === "object" && "data" in res
      ? { ...data, ...(res as { data: Record<string, unknown> }).data }
      : data;
  }

  /** `members` counts the org's other members (this one excluded). */
  async function assertWithinMemberLimits(
    org: OrganizationRecord,
    invite: Invite,
    members: number,
    seatLimit: number | null,
    membershipLimit: number | null
  ): Promise<void> {
    if (seatLimit != null && members >= seatLimit) {
      await orgOpts?.onSeatLimitReached?.({ organization: org, invite });
      throw APIError.from("UNPROCESSABLE_ENTITY", INVITE_ERROR_CODES.SEAT_LIMIT_REACHED);
    }
    if (membershipLimit != null && members >= membershipLimit) {
      throw APIError.from("FORBIDDEN", INVITE_ERROR_CODES.MEMBERSHIP_LIMIT_REACHED);
    }
  }

  /**
   * Public sign-up only: refuses a full org before the new/existing address
   * split, so both get the same answer. A membershipLimit function needs a
   * user and is left to the per-user check.
   */
  async function assertOrgHasRoom(
    ctx: GenericEndpointContext,
    invite: Invite,
    org: OrganizationRecord
  ): Promise<void> {
    const seatLimit = await seatLimitFor(ctx, org);
    const configured =
      orgOpts?.respectMembershipLimit === false
        ? null
        : (state.orgPluginOptions?.membershipLimit || 100);
    const membershipLimit = typeof configured === "number" ? configured : null;
    if (seatLimit == null && membershipLimit == null) return;
    const members = await ctx.context.adapter.count({
      model: "member",
      where: [{ field: "organizationId", value: org.id }]
    });
    await assertWithinMemberLimits(org, invite, members, seatLimit, membershipLimit);
  }

  /**
   * The org plugin's membershipLimit, applied exactly as the org plugin
   * does (default 100), unless respectMembershipLimit is false.
   */
  async function orgPluginMembershipLimit(
    user: User,
    org: OrganizationRecord
  ): Promise<number | null> {
    if (orgOpts?.respectMembershipLimit === false) return null;
    const configured = state.orgPluginOptions?.membershipLimit || 100;
    return typeof configured === "number" ? configured : await configured(user, org);
  }

  /**
   * Unless runOrgPluginHooks is false, a numeric teams.maximumMembersPerTeam is
   * honored: a full team is skipped like a deleted one (the member still
   * joins the org, teamAdded reports false).
   */
  async function teamHasRoom(c: AuthCtx, teamId: string): Promise<boolean> {
    const max =
      orgOpts?.runOrgPluginHooks !== false
        ? state.orgPluginOptions?.teams?.maximumMembersPerTeam
        : undefined;
    if (typeof max !== "number") return true;
    const count = await c.adapter
      .count({ model: "teamMember", where: [{ field: "teamId", value: teamId }] })
      .catch(() => 0);
    return count < max;
  }

  // Sessions live in the database, in secondary storage (Redis), or both.
  // Database only: one set-based delete per page. With secondary storage
  // there is no query by user, so Better Auth's per-user helper runs (it
  // also clears the database copy when storeSessionInDatabase is on).
  async function endUserSessions(ctx: GenericEndpointContext, userIds: string[]): Promise<void> {
    if (userIds.length === 0) return;
    if (!ctx.context.options.secondaryStorage) {
      await ctx.context.adapter.deleteMany({
        model: "session",
        where: [{ field: "userId", value: userIds, operator: "in" }]
      });
      return;
    }
    for (let i = 0; i < userIds.length; i += SESSION_STORAGE_CONCURRENCY) {
      await Promise.all(
        userIds
          .slice(i, i + SESSION_STORAGE_CONCURRENCY)
          .map((id) => ctx.context.internalAdapter.deleteUserSessions(id))
      );
    }
  }

  // Clears activeOrganizationId on sessions pointing at a deleted org.
  // Only members can hold it active, so with secondary storage each
  // member's own session list is read instead of scanning every session.
  async function clearActiveOrg(
    ctx: GenericEndpointContext,
    organizationId: string,
    memberUserIds: string[]
  ): Promise<void> {
    if (!ctx.context.options.secondaryStorage) {
      await ctx.context.adapter
        .updateMany({
          model: "session",
          where: [{ field: "activeOrganizationId", value: organizationId }],
          update: { activeOrganizationId: null }
        })
        .catch(() => {});
      return;
    }
    const clearFor = async (userId: string) => {
      const sessions = (await ctx.context.internalAdapter.listSessions(userId)) as {
        token: string;
        activeOrganizationId?: string | null;
      }[];
      for (const s of sessions) {
        if (s.activeOrganizationId !== organizationId) continue;
        await ctx.context.internalAdapter.updateSession(s.token, { activeOrganizationId: null });
      }
    };
    for (let i = 0; i < memberUserIds.length; i += SESSION_STORAGE_CONCURRENCY) {
      await Promise.all(
        memberUserIds.slice(i, i + SESSION_STORAGE_CONCURRENCY).map((id) =>
          clearFor(id).catch((e) => {
            ctx.context.logger.error(
              `better-enrollment: failed to clear the deleted organization from a session: ${String(e)}`
            );
          })
        )
      );
    }
  }

  /** Ban reason stamped by banMembers; enableOrg's unbanMembers lifts exactly these. */
  const orgBanReason = (organizationId: string) =>
    `Organization suspended by administrator (org:${organizationId})`;

  /**
   * Bans an org's members for a takedown. Platform staff are skipped: the
   * caller and anyone who may run platform controls themselves, so one call
   * can never lock the administrators out.
   */
  async function banOrgMembers(
    ctx: GenericEndpointContext,
    organizationId: string,
    actorId: string
  ): Promise<{ banned: number; skipped: number }> {
    // Member rows are not deleted here, so offset paging is stable.
    let offset = 0;
    let banned = 0;
    let skipped = 0;
    for (;;) {
      const members = await ctx.context.adapter.findMany<MemberRecord>({
        model: "member",
        where: [{ field: "organizationId", value: organizationId }],
        limit: DB_PAGE,
        offset
      });
      if (members.length === 0) break;
      const memberIds = [...new Set(members.map((m) => m.userId))];
      const users = await ctx.context.adapter.findMany<BannableUser>({
        model: "user",
        where: [{ field: "id", value: memberIds, operator: "in" }],
        limit: memberIds.length
      });
      const ids: string[] = [];
      for (const u of users) {
        if (u.id === actorId || (await isInviteAdmin(u, "manage-orgs"))) skipped++;
        else ids.push(u.id);
      }
      if (ids.length === 0) {
        if (members.length < DB_PAGE) break;
        offset += DB_PAGE;
        continue;
      }
      await ctx.context.adapter.updateMany({
        model: "user",
        where: [{ field: "id", value: ids, operator: "in" }],
        update: {
          banned: true,
          banReason: orgBanReason(organizationId)
        }
      });
      // The admin plugin checks bans only at sign-in: live sessions must end.
      await endUserSessions(ctx, ids);
      // A raw write, so the user.update ban hook does not see it.
      if (orgOpts?.revokeInvitesOnInviterBan !== false) {
        await cancelPendingInvites(
          ctx.context,
          [{ field: "createdByUserId", value: ids, operator: "in" }],
          "inviter-banned",
          { organizationId }
        );
      }
      banned += ids.length;
      if (members.length < DB_PAGE) break;
      offset += DB_PAGE;
    }
    return { banned, skipped };
  }

  /** Lifts the bans banOrgMembers stamped for this org, on its members only. */
  async function unbanOrgMembers(ctx: GenericEndpointContext, organizationId: string) {
    let offset = 0;
    let unbanned = 0;
    for (;;) {
      const members = await ctx.context.adapter.findMany<MemberRecord>({
        model: "member",
        where: [{ field: "organizationId", value: organizationId }],
        limit: DB_PAGE,
        offset
      });
      if (members.length === 0) break;
      unbanned += await ctx.context.adapter.updateMany({
        model: "user",
        where: [
          { field: "id", value: [...new Set(members.map((m) => m.userId))], operator: "in" },
          { field: "banned", value: true },
          { field: "banReason", value: orgBanReason(organizationId) }
        ],
        update: { banned: false, banReason: null, banExpires: null }
      });
      if (members.length < DB_PAGE) break;
      offset += DB_PAGE;
    }
    return unbanned;
  }

  /**
   * One page newest first by (date field, id). Adapters sort by a single
   * field and do not nest AND/OR, so ties on the date are read with their
   * own id-sorted query. Equality is gte+lte: some adapters compare dates
   * by reference.
   */
  async function keysetPage<T extends { id: string }>(
    ctx: GenericEndpointContext,
    model: string,
    dateField: keyof T & string,
    where: AdapterWhere,
    limit: number,
    cursor: { createdAt: Date; id: string } | null
  ): Promise<{ rows: T[]; hasMore: boolean }> {
    const at = (r: T) => new Date(r[dateField] as Date | string);
    const newestFirst = (a: T, b: T) =>
      compareNewestFirst({ createdAt: at(a), id: a.id }, { createdAt: at(b), id: b.id });
    const sameInstant = (instant: Date): AdapterWhere => [
      { field: dateField, value: instant, operator: "gte" },
      { field: dateField, value: instant, operator: "lte" }
    ];
    const page: T[] = [];
    if (cursor) {
      const ties = await ctx.context.adapter.findMany<T>({
        model,
        where: [
          ...where,
          ...sameInstant(cursor.createdAt),
          { field: "id", value: cursor.id, operator: "lt" }
        ],
        limit: limit + 1,
        sortBy: { field: "id", direction: "desc" }
      });
      if (ties.length > limit) return { rows: ties.slice(0, limit), hasMore: true };
      page.push(...ties);
    }
    const remaining = limit - page.length;
    const older = await ctx.context.adapter.findMany<T>({
      model,
      where: cursor
        ? [...where, { field: dateField, value: cursor.createdAt, operator: "lt" }]
        : where,
      limit: remaining + 1,
      sortBy: { field: dateField, direction: "desc" }
    });
    if (older.length <= remaining) {
      return { rows: [...page, ...older.sort(newestFirst)], hasMore: false };
    }
    if (remaining === 0) return { rows: page, hasMore: true };
    // Rows newer than the boundary instant all fit; the boundary's ties
    // are refetched in id order so the cursor resumes exactly after them.
    const boundary = at(older[remaining - 1]!);
    const head = older
      .filter((r) => at(r).getTime() > boundary.getTime())
      .sort(newestFirst);
    const tail = await ctx.context.adapter.findMany<T>({
      model,
      where: [...where, ...sameInstant(boundary)],
      limit: remaining - head.length,
      sortBy: { field: "id", direction: "desc" }
    });
    return { rows: [...page, ...head, ...tail], hasMore: true };
  }

  async function requireOrgFeatures(): Promise<void> {
    if (!orgEnabled()) {
      throw APIError.from("UNPROCESSABLE_ENTITY", INVITE_ERROR_CODES.ORG_FEATURES_DISABLED);
    }
  }

  // ---------------------------------------------------------- redemption

  async function acceptCore(ctx: GenericEndpointContext, body: RedeemBody) {
    const found = await findInviteByToken(ctx, body.token);
    const invite = await assertUsable(ctx, found && (await settleInviter(ctx, found)));
    assertPublicRolesAllowed(invite, "FORBIDDEN");
    const role = await resolveRole(invite);

    if (body.password) {
      // A password field on a passwordless app misleads the accepter into
      // thinking they set one; reject instead of silently dropping it.
      if (!state.credentialEnabled) {
        throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.PASSWORD_NOT_AVAILABLE);
      }
      const { minPasswordLength, maxPasswordLength } = ctx.context.password.config;
      if (body.password.length < minPasswordLength || body.password.length > maxPasswordLength) {
        throw new APIError("BAD_REQUEST", {
          message: `Password must be between ${minPasswordLength} and ${maxPasswordLength} characters`
        });
      }
    } else if (!state.passwordless) {
      throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.PASSWORD_REQUIRED);
    }
    // The accept flow exists to populate the profile; a nameless profile
    // defeats it. Activation flows never reach this path.
    const name = body.name?.trim();
    if (!name) {
      throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.NAME_REQUIRED);
    }
    const extraFields = parseAdditionalFields(body, "SIGN_UP");

    let pre = await assertOrgRedeemable(ctx, invite, body);

    if (invite.type === "private") {
      let target =
        (invite.preCreatedUserId
          ? await ctx.context.internalAdapter.findUserById(invite.preCreatedUserId)
          : null) ??
        unwrapUser(
          (await ctx.context.internalAdapter.findUserByEmail(
            invite.email!
          )) as MaybeWithAccounts | null
        );
      if (target) {
        if (isBanned(target)) {
          throw APIError.from("FORBIDDEN", INVITE_ERROR_CODES.USER_BANNED);
        }
        // An account someone can already sign into is never taken over by
        // the token: merging into it requires the owner's session. That is
        // any account holding a login, including this invite's own 0.x
        // shell when an earlier failed attempt left a password on it; its
        // owner signs in with that password. Another invite's verified
        // shell counts as established too.
        const ownShell = invite.preCreatedUserId === target.id;
        const accounts = await ctx.context.internalAdapter.findAccounts(target.id);
        if (accounts.length > 0 || (!ownShell && target.emailVerified)) {
          return ctx.json({
            action: "SIGN_IN_REQUIRED" as const,
            callbackURL: buildInviteUrl(ctx, body.token, invite.type)
          });
        }
        await assertNotSelfGrant(ctx, invite, target.id);
        pre = await runBeforeOrgCreate(invite, target, pre);
      }
      // Claim before creating a user: a submission that loses the claim has
      // written nothing, so it can never remove the winner's account.
      const claimed = await claimUse(ctx, invite);
      if (!claimed) {
        throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.INVITE_ALREADY_USED);
      }
      const undo: Undo[] = [() => rollbackClaim(ctx, invite)];
      try {
        if (!target) {
          // No account yet: the usual case, since invites no longer
          // pre-create one. Created unverified with the default role, and
          // completed below.
          try {
            target = await ctx.context.internalAdapter.createUser(
              {
                email: invite.email!,
                name: "",
                emailVerified: false,
                role: opts.defaultRole
              },
              PROVISIONING_SOURCE
            );
          } catch (e) {
            // validateUserInfo and database hook rejections keep their own error.
            if (e instanceof APIError) throw e;
            // Unique email: another invite for this address is being redeemed.
            throw APIError.from("CONFLICT", INVITE_ERROR_CODES.REDEMPTION_IN_PROGRESS);
          }
          const createdId = target.id;
          undo.push(() =>
            ctx.context.adapter.delete({ model: "user", where: [{ field: "id", value: createdId }] })
          );
          pre = await runBeforeOrgCreate(invite, target, pre);
        }
        const targetId = target.id;
        // Everything that can refuse (seats, org plugin hooks, slug race)
        // runs before the user is touched. Hooks see the user as it is
        // about to be written.
        const intended = { ...target, emailVerified: true, role, name, ...extraFields } as User;
        const org = await applyOrgEffects(ctx, claimed, intended, pre, undo);
        if (body.password) {
          const credential = await ctx.context.internalAdapter.createAccount({
            userId: target.id,
            providerId: "credential",
            accountId: target.id,
            password: await ctx.context.password.hash(body.password)
          });
          undo.push(() =>
            ctx.context.adapter.delete({
              model: "account",
              where: [{ field: "id", value: credential.id }]
            })
          );
        }
        const written = { emailVerified: true, role, name, ...extraFields };
        const before = userSnapshot(target, Object.keys(written));
        const updated = (await ctx.context.internalAdapter.updateUser(target.id, written)) ?? intended;
        undo.push(() =>
          ctx.context.adapter.update({
            model: "user",
            where: [{ field: "id", value: targetId }],
            update: before
          })
        );
        // Handover: the account is real now. Other invites that pre-created
        // this shell stop owning it, so they redeem as activations (roles
        // merge, never overwrite) and the shell guards (magic link, cleanup)
        // no longer read an established account as inert.
        if (invite.preCreatedUserId !== target.id) {
          // Each page is released before the next read, so this drains.
          for (;;) {
            const siblings = await ctx.context.adapter.findMany<Invite>({
              model: "invite",
              where: [{ field: "preCreatedUserId", value: target.id }],
              limit: DB_PAGE
            });
            if (siblings.length === 0) break;
            const ids = siblings.map((i) => i.id);
            await ctx.context.adapter.updateMany({
              model: "invite",
              where: [{ field: "id", value: ids, operator: "in" }],
              update: { preCreatedUserId: null, updatedAt: new Date() }
            });
            undo.push(() =>
              ctx.context.adapter.updateMany({
                model: "invite",
                where: [{ field: "id", value: ids, operator: "in" }],
                update: { preCreatedUserId: targetId }
              })
            );
            if (siblings.length < DB_PAGE) break;
          }
        }
        await recordUse(ctx, invite, target.id, target.email, undo);
        // With a password, no session is created or mutated: the accepter
        // signs in through the app's own flow with the credentials they
        // just set. Passwordless has no credential to sign in with, and
        // the emailed token already proved the mailbox, so the accepter
        // is signed in directly instead of a second email round trip.
        let signedIn = false;
        if (!body.password) {
          const session = await ctx.context.internalAdapter.createSession(updated.id);
          undo.push(() => ctx.context.internalAdapter.deleteSession(session.token));
          await setSessionCookie(ctx, { session, user: updated });
          signedIn = true;
        }
        await opts.onInviteAccepted?.({ invite: claimed, user: updated });
        return ctx.json({
          action: "ACCEPTED" as const,
          signedIn,
          user: {
            id: updated.id,
            email: updated.email,
            name: updated.name,
            emailVerified: updated.emailVerified
          },
          organization: org ? { id: org.id, name: org.name, slug: org.slug } : null
        });
      } catch (e) {
        await runUndo(ctx, undo);
        throw e;
      }
    }

    const email = body.email?.toLowerCase().trim();
    if (!email) {
      throw APIError.from(
        "UNPROCESSABLE_ENTITY",
        INVITE_ERROR_CODES.EMAIL_REQUIRED_FOR_PUBLIC_ACCEPT
      );
    }
    // A full org refuses every address alike, before the split below.
    if (invite.kind === "org-join" && pre.org) await assertOrgHasRoom(ctx, invite, pre.org);
    const existingUser = unwrapUser(
      (await ctx.context.internalAdapter.findUserByEmail(email)) as MaybeWithAccounts | null
    );
    // New and existing addresses get the same answer, so the endpoint never
    // confirms an account to an unauthenticated caller. The owner of an
    // existing account is mailed the link instead; a signed-in redeem
    // activates it.
    const checkEmail = () => ctx.json({ action: "CHECK_EMAIL" as const });
    if (existingUser) {
      // Same hashing cost as a sign-up, so timing does not tell them apart.
      if (body.password) await ctx.context.password.hash(body.password);
      try {
        if (
          !opts.sendExistingAccountNotice ||
          !(await noticeDue(ctx, invite, existingUser.email))
        ) {
          return checkEmail();
        }
        await opts.sendExistingAccountNotice(
          {
            email: existingUser.email,
            name: existingUser.name,
            role: invite.role,
            kind: invite.kind,
            mode: invite.mode,
            url: buildInviteUrl(ctx, body.token, invite.type),
            inviterName: invite.inviterName,
            inviterEmail: invite.inviterEmail,
            organizationName: pre.org?.name ?? invite.presetOrganizationName ?? null,
            inviteId: invite.id,
            organizationId: invite.organizationId,
            organizationRole: invite.organizationRole,
            teamId: invite.teamId,
            expiresAt: invite.expiresAt
          },
          ctx.request
        );
      } catch (e) {
        // A mail failure must not answer differently from the sign-up path.
        ctx.context.logger.error("better-enrollment: sendExistingAccountNotice failed", e);
      }
      return checkEmail();
    }
    // An address with a live private invite enters only through that
    // invite; a public link must not register it first. Same answer, nothing
    // written, no use taken. An expired one no longer holds it here.
    if ((await inviteOnlyState(ctx, email)).livePrivate) {
      if (body.password) await ctx.context.password.hash(body.password);
      return checkEmail();
    }
    const claimed = await claimUse(ctx, invite);
    if (!claimed) {
      throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.INVITE_USES_EXHAUSTED);
    }
    const undo: Undo[] = [() => rollbackClaim(ctx, invite)];
    try {
      let user: User;
      try {
        user = await ctx.context.internalAdapter.createUser(
          {
            email,
            name,
            emailVerified: opts.autoVerifyPublicInviteEmail,
            role,
            ...extraFields
          },
          PROVISIONING_SOURCE
        );
      } catch (e) {
        if (e instanceof APIError) throw e;
        // Unique email: a parallel redemption registered the address first,
        // which answers like an existing account.
        await runUndo(ctx, undo);
        return checkEmail();
      }
      // The user created in THIS attempt must not outlive a failed
      // redemption, or the email would be locked while the invite stays
      // pending.
      undo.push(async () => {
        await ctx.context.adapter.deleteMany({
          model: "account",
          where: [{ field: "userId", value: user.id }]
        });
        await ctx.context.adapter.delete({
          model: "user",
          where: [{ field: "id", value: user.id }]
        });
      });
      // The public sign-up has no user before its claim, so the hook runs
      // here; a refusal deletes the user and returns the use.
      pre = await runBeforeOrgCreate(invite, user, pre);
      // Refusals (seats, org plugin hooks, slug race) come before the
      // credential and the verification email.
      await applyOrgEffects(ctx, claimed, user, pre, undo);
      if (body.password) {
        const hash = await ctx.context.password.hash(body.password);
        await ctx.context.internalAdapter.createAccount({
          userId: user.id,
          providerId: "credential",
          accountId: user.id,
          password: hash
        });
      }
      // Redemption bypasses the sign-up route, so its sendOnSignUp logic
      // never runs; mirror its trigger here or the unverified accepter
      // would never receive a verification email.
      const verification = ctx.context.options.emailVerification;
      if (
        !user.emailVerified &&
        verification?.sendVerificationEmail &&
        (verification.sendOnSignUp ??
          ctx.context.options.emailAndPassword?.requireEmailVerification)
      ) {
        const verifyToken = await createEmailVerificationToken(
          ctx.context.secret,
          user.email,
          undefined,
          verification.expiresIn
        );
        const verifyUrl = `${ctx.context.baseURL}/verify-email?token=${verifyToken}&callbackURL=${encodeURIComponent("/")}`;
        await verification.sendVerificationEmail(
          { user, url: verifyUrl, token: verifyToken },
          ctx.request
        );
      }
      await recordUse(ctx, invite, user.id, email, undo);
      await settlePublicStatus(ctx, claimed);
      await opts.onInviteAccepted?.({ invite: claimed, user });
      // No session is created or mutated, even passwordless: a public link
      // proves nothing about the mailbox, so the accepter verifies it and
      // signs in through the app's own flow.
      return checkEmail();
    } catch (e) {
      await runUndo(ctx, undo);
      throw e;
    }
  }

  async function activateCore(ctx: GenericEndpointContext, body: RedeemBody) {
    const found = await findInviteByToken(ctx, body.token);
    const invite = await assertUsable(ctx, found && (await settleInviter(ctx, found)));
    assertPublicRolesAllowed(invite, "FORBIDDEN");

    const session = await getSessionFromCtx(ctx);
    if (!session) {
      // Stateless round-trip: the token in the URL is the only state.
      return ctx.json({
        action: "SIGN_IN_REQUIRED" as const,
        callbackURL: buildInviteUrl(ctx, body.token, invite.type)
      });
    }
    // Ban, email and verification are read from the database: a cookie
    // cache can be up to its max age out of date.
    const current = (await ctx.context.internalAdapter.findUserById(
      session.user.id
    )) as BannableUser | null;
    if (!current) {
      return ctx.json({
        action: "SIGN_IN_REQUIRED" as const,
        callbackURL: buildInviteUrl(ctx, body.token, invite.type)
      });
    }
    if (isBanned(current)) {
      throw APIError.from("FORBIDDEN", INVITE_ERROR_CODES.USER_BANNED);
    }

    if (invite.type === "private") {
      if (current.email.toLowerCase() !== invite.email?.toLowerCase()) {
        throw APIError.from("FORBIDDEN", INVITE_ERROR_CODES.EMAIL_MISMATCH);
      }
      if (!current.emailVerified) {
        throw APIError.from("FORBIDDEN", INVITE_ERROR_CODES.EMAIL_NOT_VERIFIED);
      }
    }
    await assertNotSelfGrant(ctx, invite, current.id);

    // Re-activation by the same user is idempotent.
    const priorUse = await ctx.context.adapter.findOne<InviteUse>({
      model: "inviteUse",
      where: [
        { field: "inviteId", value: invite.id },
        { field: "usedByUserId", value: session.user.id }
      ]
    });
    if (priorUse) {
      return ctx.json({
        action: "ACCEPTED" as const,
        role: current.role ?? null,
        organization: null
      });
    }

    const role = await resolveRole(invite);
    // Confirm-step fields validate before the claim, so bad input never
    // consumes a use.
    const extraFields = parseAdditionalFields(body, "CONFIRM");
    const pre = await runBeforeOrgCreate(
      invite,
      current as User,
      await assertOrgRedeemable(ctx, invite, body)
    );
    const claimed = await claimUse(ctx, invite);
    if (!claimed) {
      throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.INVITE_USES_EXHAUSTED);
    }
    const undo: Undo[] = [() => rollbackClaim(ctx, invite)];
    try {
      const merged = mergeRoles(current.role, role);
      const written = { role: merged, ...extraFields };
      // Refusals (seats, org plugin hooks) come before the role merge.
      const intended = { ...current, ...written } as User;
      const org = await applyOrgEffects(ctx, claimed, intended, pre, undo);
      const before = userSnapshot(current as User, Object.keys(written));
      const updated = await ctx.context.internalAdapter.updateUser(session.user.id, written);
      undo.push(() =>
        ctx.context.adapter.update({
          model: "user",
          where: [{ field: "id", value: session.user.id }],
          update: before
        })
      );
      await recordUse(ctx, invite, session.user.id, session.user.email, undo);
      await settlePublicStatus(ctx, claimed);
      await opts.onInviteAccepted?.({
        invite: claimed,
        user: updated ?? session.user
      });
      return ctx.json({
        action: "ACCEPTED" as const,
        role: merged,
        organization: org ? { id: org.id, name: org.name, slug: org.slug } : null
      });
    } catch (e) {
      await runUndo(ctx, undo);
      throw e;
    }
  }

  /** invite.checkSlug and invite.verifySlug. */
  async function checkSlugCore(ctx: GenericEndpointContext, token: string, slug: string) {
    const invite = await findInviteByToken(ctx, token);
    if (!invite || invite.kind !== "org-create" || deriveStatus(invite) !== "pending") {
      throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.INVITE_NOT_FOUND);
    }
    assertValidOrgFields(undefined, slug);
    const existing = await ctx.context.adapter.findOne<OrganizationRecord>({
      model: "organization",
      where: [{ field: "slug", value: normalizeOrgSlug(slug) }]
    });
    if (existing) {
      throw APIError.from("CONFLICT", INVITE_ERROR_CODES.ORG_SLUG_TAKEN);
    }
    return ctx.json({ status: true });
  }

  /** invite.get and invite.lookup: the invite page's single read. */
  async function getInviteCore(ctx: GenericEndpointContext, token: string) {
    const found = await findInviteByToken(ctx, token);
    if (!found) {
      throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.INVITE_NOT_FOUND);
    }
    // An inactive inviter shows as revoked here, not only at redeem.
    const invite = await settleInviter(ctx, found);
    const status = deriveStatus(invite);
    if (status === "expired") await notifyExpired(ctx, invite);

    let organizationName: string | null = null;
    if (invite.kind === "org-join" && invite.organizationId && orgEnabled()) {
      const org = await findOrg(ctx, invite.organizationId);
      organizationName = org?.name ?? null;
    } else if (invite.kind === "org-create") {
      organizationName = invite.presetOrganizationName ?? null;
    }

    // nextAction drives a single invite page for every kind.
    const session = await getSessionFromCtx(ctx).catch(() => null);
    let nextAction: "SIGN_UP" | "SIGN_IN" | "CONFIRM" | null = null;
    if (status === "pending") {
      if (getMode() === "invite-only") {
        // Activation invites (established accounts) sign in, not up.
        const activation =
          (invite.type === "private" && (await privateInviteActivates(ctx, invite))) ||
          (invite.type === "public" && !!session);
        nextAction = activation ? (session ? "CONFIRM" : "SIGN_IN") : "SIGN_UP";
      } else {
        nextAction = session ? "CONFIRM" : "SIGN_IN";
      }
    }
    // Of the four next actions, only SIGN_UP and CONFIRM render a
    // form; SIGN_IN and the terminal state collect nothing.
    const formAction =
      nextAction === "SIGN_UP" || nextAction === "CONFIRM" ? nextAction : null;
    const requiredFields: string[] = [];
    const optionalFields: string[] = [];
    if (nextAction === "SIGN_UP") {
      if (!state.passwordless) requiredFields.push("password");
      requiredFields.push("name");
      if (invite.type === "public") requiredFields.push("email");
    }
    if (formAction) {
      for (const [key, field] of Object.entries(additionalFieldDefs)) {
        if (!fieldAppliesTo(field, formAction)) continue;
        (isEffectivelyRequired(field) ? requiredFields : optionalFields).push(key);
      }
    }
    if (invite.kind === "org-create" && nextAction && !invite.presetOrganizationName) {
      requiredFields.push("organizationName", "organizationSlug");
    }
    // Types let the page render the right input for each extra field.
    const additionalFields = formAction
      ? Object.fromEntries(
          Object.entries(additionalFieldDefs)
            .filter(([, field]) => fieldAppliesTo(field, formAction))
            .map(([key, field]) => [
              key,
              { type: field.type, required: isEffectivelyRequired(field) }
            ])
        )
      : {};

    return ctx.json({
      type: invite.type,
      kind: invite.kind,
      email: invite.email
        ? opts.exposeEmailOnGet
          ? invite.email
          : maskEmail(invite.email)
        : null,
      role: invite.role,
      status,
      organizationName,
      nextAction,
      passwordless: state.passwordless,
      requiredFields,
      optionalFields,
      additionalFields,
      // No use counts: only a new address consumes a use, so they would
      // tell a link holder which emails have accounts. invite.list has them.
      expiresAt: invite.expiresAt,
      maxUses: invite.maxUses
    });
  }

  const createInviteBody = z.object({
    type: z.enum(["private", "public"]).default("private"),
    kind: z.enum(["app", "org-join", "org-create"]).default("app"),
    email: z.email().optional(),
    name: z.string().max(200).optional(),
    role: z.string().max(100).optional(),
    expiresIn: z.number().int().positive().optional(),
    maxUses: z.number().int().positive().nullable().optional(),
    organizationId: z.string().max(200).optional(),
    organizationRole: z.string().max(100).optional(),
    teamId: z.string().max(200).optional(),
    presetSeatLimit: z.number().int().positive().optional(),
    organization: z
      .object({
        name: z.string().trim().min(1).max(200),
        slug: z.string().trim().toLowerCase().min(1).max(200).optional()
      })
      .optional()
  });

  type CreateInviteBody = z.infer<typeof createInviteBody>;

  // A system actor is a trusted server-only caller with no session. It
  // carries its own attribution and skips the permission gates only; every
  // state invariant (seat limits, email locks, org checks) still runs.
  type InviteCreateActor =
    | { type: "user" }
    | {
        type: "system";
        inviterName: string;
        inviterEmail: string;
        createdByUserId: string | null;
      };

  async function createInviteCore(
    ctx: GenericEndpointContext,
    body: CreateInviteBody,
    actor: InviteCreateActor
  ) {
    const mode = getMode();
    const kind: InviteKind = body.kind;
    const type = body.type;
    // The app-level role is an admin-only field. org-join creators
    // are gated by org permission, not app adminship, so honoring
    // their role would let any org inviter mint app admins.
    if (kind === "org-join" && body.role != null) {
      throw APIError.from("UNPROCESSABLE_ENTITY", INVITE_ERROR_CODES.ROLE_NOT_ALLOWED_FOR_ORG_JOIN);
    }
    const role = body.role ?? opts.defaultRole;
    if (opts.validRoles && !opts.validRoles.includes(role)) {
      throw APIError.from("UNPROCESSABLE_ENTITY", INVITE_ERROR_CODES.INVALID_ROLE);
    }

    let email: string | null = null;
    let maxUses: number | null;
    if (type === "private") {
      if (!body.email) {
        throw APIError.from(
          "UNPROCESSABLE_ENTITY",
          INVITE_ERROR_CODES.EMAIL_REQUIRED_FOR_PRIVATE_INVITE
        );
      }
      if (body.maxUses != null && body.maxUses !== 1) {
        throw APIError.from(
          "UNPROCESSABLE_ENTITY",
          INVITE_ERROR_CODES.MAX_USES_INVALID_FOR_PRIVATE
        );
      }
      email = body.email.toLowerCase().trim();
      maxUses = 1;
    } else {
      maxUses = body.maxUses === undefined ? null : body.maxUses;
      if (maxUses != null && opts.maxPublicUses != null && maxUses > opts.maxPublicUses) {
        throw APIError.from("UNPROCESSABLE_ENTITY", INVITE_ERROR_CODES.MAX_USES_TOO_HIGH);
      }
    }

    // Gate by kind. Org sovereignty: only the org invites into
    // itself; only app admins mint app and org-create invites.
    let creator: BannableUser | null = null;
    let org: OrganizationRecord | null = null;
    let organizationRole: string | null = null;
    if (kind === "org-join") {
      await requireOrgFeatures();
      if (!body.organizationId) {
        throw APIError.from("UNPROCESSABLE_ENTITY", INVITE_ERROR_CODES.ORGANIZATION_ID_REQUIRED);
      }
      if (body.presetSeatLimit != null || body.organization) {
        throw APIError.from("UNPROCESSABLE_ENTITY", INVITE_ERROR_CODES.ORG_FIELDS_NOT_ALLOWED);
      }
      let creatorMember: MemberRecord | null = null;
      if (actor.type === "user") {
        creator = await getAuthUser(ctx);
        const access = await requireOrgInviteAccess(ctx, creator, body.organizationId, "create");
        org = access.org;
        creatorMember = access.member;
      } else {
        org = await findOrg(ctx, body.organizationId);
        if (!org) {
          throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.ORG_NOT_FOUND);
        }
      }
      if (org.disabledAt) {
        throw APIError.from("FORBIDDEN", INVITE_ERROR_CODES.ORG_DISABLED);
      }
      organizationRole = body.organizationRole ?? orgOpts?.defaultOrganizationRole ?? "member";
      const known = await knownOrgRoles(ctx, org.id);
      if (!known.includes(organizationRole)) {
        throw APIError.from("UNPROCESSABLE_ENTITY", INVITE_ERROR_CODES.INVALID_ORG_ROLE);
      }
      if (splitRoles(organizationRole).some(isTopOrgRole)) {
        // A system actor has no membership; the option is its only gate.
        const mayInviteOwner =
          actor.type === "system"
            ? !!orgOpts?.allowOwnerInvites
            : mayGrantTopOrgRole(creatorMember, organizationRole);
        if (!mayInviteOwner) {
          throw APIError.from("FORBIDDEN", INVITE_ERROR_CODES.OWNER_INVITES_NOT_ALLOWED);
        }
      }
      if (creatorMember) {
        await assertCanGrantOrgRole(ctx, creatorMember, org, organizationRole);
      }
      if (body.teamId) {
        const team = await ctx.context.adapter
          .findOne<TeamRecord>({
            model: "team",
            where: [{ field: "id", value: body.teamId }]
          })
          .catch(() => null);
        if (!team || team.organizationId !== org.id) {
          throw APIError.from("UNPROCESSABLE_ENTITY", INVITE_ERROR_CODES.TEAM_NOT_FOUND);
        }
      }
      const limit = await seatLimitFor(ctx, org);
      if (limit != null) {
        if (type === "public" && maxUses == null) {
          throw APIError.from(
            "UNPROCESSABLE_ENTITY",
            INVITE_ERROR_CODES.PUBLIC_ORG_INVITE_REQUIRES_MAX_USES
          );
        }
        const needed = type === "private" ? 1 : (maxUses as number);
        const { members, reserved } = await seatUsage(ctx, org.id);
        if (members + reserved + needed > limit) {
          await orgOpts?.onSeatLimitReached?.({ organization: org });
          throw APIError.from("UNPROCESSABLE_ENTITY", INVITE_ERROR_CODES.SEAT_LIMIT_REACHED);
        }
      }
    } else {
      if (actor.type === "user") {
        creator = await requireInviteAdmin(ctx, "create");
        // Founding an org (and fixing its seat limit) is a platform action.
        if (kind === "org-create") await assertMayFoundOrgs(creator);
        await assertCanGrantAppRole(creator, role);
      }
      if (body.organizationId || body.organizationRole || body.teamId) {
        throw APIError.from("UNPROCESSABLE_ENTITY", INVITE_ERROR_CODES.ORG_FIELDS_NOT_ALLOWED);
      }
      if (kind === "org-create") {
        await requireOrgFeatures();
        if (body.organization) assertValidOrgFields(body.organization.name, body.organization.slug);
      } else if (body.presetSeatLimit != null || body.organization) {
        throw APIError.from("UNPROCESSABLE_ENTITY", INVITE_ERROR_CODES.ORG_FIELDS_NOT_ALLOWED);
      }
    }
    assertPublicRolesAllowed({ type, kind, role, organizationRole }, "UNPROCESSABLE_ENTITY");

    // For a user actor, creator is always resolved by the gating above.
    const createdByUserId = actor.type === "system" ? actor.createdByUserId : (creator?.id ?? null);
    const inviterName = actor.type === "system" ? actor.inviterName : (creator?.name ?? "");
    const inviterEmail = actor.type === "system" ? actor.inviterEmail : (creator?.email ?? "");

    if (email) {
      // The email lock is per scope: one pending row per (kind, org), held
      // even past expiresAt, where resend is the release valve. Invites in
      // other scopes always coexist (one email invited to several orgs, or
      // to the app and an org): redemption is state-driven, so whichever
      // live token is redeemed first creates the account and the rest
      // become activations. Scoping also keeps an org inviter from probing
      // for pending invites elsewhere in the app.
      const existing = await ctx.context.adapter.findOne<Invite>({
        model: "invite",
        where: [
          { field: "email", value: email },
          { field: "status", value: "pending" },
          { field: "kind", value: kind },
          ...(kind === "org-join" ? [{ field: "organizationId", value: org!.id }] : [])
        ]
      });
      if (existing) {
        throw APIError.from("CONFLICT", INVITE_ERROR_CODES.EMAIL_ALREADY_INVITED);
      }
      const existingUser = unwrapUser(
        (await ctx.context.internalAdapter.findUserByEmail(email)) as MaybeWithAccounts | null
      );
      // An org-bound invite to an established account is an activation
      // invite: redeem merges the membership onto the signed-in user.
      // App-kind invites grant nothing an established user lacks. A user
      // pre-created by an invite from before 1.0 is neither; its token
      // claims it at redemption like any other sign-up.
      if (
        existingUser &&
        mode === "invite-only" &&
        kind === "app" &&
        (await isEstablished(ctx, existingUser))
      ) {
        throw APIError.from("CONFLICT", INVITE_ERROR_CODES.USER_ALREADY_EXISTS);
      }
    }

    const expiresAt = inviteExpiresAt(body.expiresIn, type);

    const token = generateRandomString(32);
    const tokenHash = await sha256Base64Url(token);
    const now = new Date();

    try {
      const invite = await ctx.context.adapter.create<Omit<Invite, "id">, Invite>({
        model: "invite",
        data: {
          type,
          kind,
          email,
          name: body.name ?? null,
          role,
          tokenHash,
          status: "pending",
          mode,
          organizationId: org?.id ?? null,
          organizationRole,
          teamId: kind === "org-join" ? (body.teamId ?? null) : null,
          presetSeatLimit: kind === "org-create" ? (body.presetSeatLimit ?? null) : null,
          presetOrganizationName: body.organization?.name ?? null,
          presetOrganizationSlug: body.organization?.slug ?? null,
          preCreatedUserId: null,
          createdByUserId,
          createdBySystem: actor.type === "system",
          inviterName,
          inviterEmail,
          expiresAt,
          maxUses,
          useCount: 0,
          revokedAt: null,
          revokedByUserId: null,
          expiryNotifiedAt: null,
          createdAt: now,
          updatedAt: now
        }
      });

      // The email lock is a read then a write: count the scope after
      // writing and back out when another create got in (both may, which
      // leaves none rather than two; the creator retries).
      if (email) {
        const pending = await ctx.context.adapter.count({
          model: "invite",
          where: [
            { field: "email", value: email },
            { field: "status", value: "pending" },
            { field: "kind", value: kind },
            ...(kind === "org-join" ? [{ field: "organizationId", value: org!.id }] : [])
          ]
        });
        if (pending > 1) {
          throw APIError.from("CONFLICT", INVITE_ERROR_CODES.EMAIL_ALREADY_INVITED);
        }
      }

      // Write, then verify (see seatUsage): parallel creates can all pass
      // the check above. Over the limit, the catch below removes this
      // invite. Seat-limited orgs only.
      if (org && kind === "org-join") {
        const limit = await seatLimitFor(ctx, org);
        if (limit != null) {
          const { members, reserved } = await seatUsage(ctx, org.id);
          if (members + reserved > limit) {
            await orgOpts?.onSeatLimitReached?.({ organization: org });
            throw APIError.from("UNPROCESSABLE_ENTITY", INVITE_ERROR_CODES.SEAT_LIMIT_REACHED);
          }
        }
      }

      const url = buildInviteUrl(ctx, token, type);
      if (type === "private" && email) {
        await opts.sendPrivateInvitation?.(
          {
            email,
            name: body.name ?? null,
            role,
            kind,
            mode,
            url,
            token,
            inviterName,
            inviterEmail,
            organizationName: org?.name ?? invite.presetOrganizationName ?? null,
            inviteId: invite.id,
            organizationId: invite.organizationId,
            organizationRole: invite.organizationRole,
            teamId: invite.teamId,
            expiresAt
          },
          ctx.request
        );
      } else {
        await opts.sendPublicInvitation?.(
          {
            role,
            kind,
            mode,
            url,
            token,
            inviterName,
            inviterEmail,
            organizationName: org?.name ?? invite.presetOrganizationName ?? null,
            inviteId: invite.id,
            organizationId: invite.organizationId,
            organizationRole: invite.organizationRole,
            teamId: invite.teamId,
            maxUses,
            expiresAt
          },
          ctx.request
        );
      }
      await opts.onInviteCreated?.({ invite, admin: creator });
      // A private invite is a one-mailbox credential: only the
      // emailed recipient may hold the link, never the creator. A
      // public invite is meant to be shared, so it returns its link.
      // Hand delivery without email = public invite with maxUses 1.
      return ctx.json({
        inviteId: invite.id,
        expiresAt,
        ...(type === "public" ? { token, url } : {})
      });
    } catch (e) {
      // Leave nothing behind so the creator can retry cleanly.
      await ctx.context.adapter
        .deleteMany({
          model: "invite",
          where: [{ field: "tokenHash", value: tokenHash }]
        })
        .catch(() => {});
      throw e;
    }
  }

  // -------------------------------------------------------------- plugin

  return {
    id: "better-enrollment",
    schema: buildSchema(!!orgOpts, additionalFieldDefs),
    $ERROR_CODES: INVITE_ERROR_CODES,

    init(ctx: AuthContext) {
      const paths = detectSignupPaths(ctx.options);
      const openPaths = paths.filter((p) => p.open);
      const closedPaths = paths.filter((p) => !p.open);

      if (opts.mode === "auto") {
        if (paths.length === 0) {
          throw new Error(
            'better-enrollment: no sign-up paths detected. Set mode: "invite-only" or "open" explicitly.'
          );
        }
        if (openPaths.length === 0) {
          state.mode = "invite-only";
        } else if (closedPaths.length === 0) {
          state.mode = "open";
        } else {
          throw new Error(
            `better-enrollment: mixed sign-up configuration (${describePaths(paths)}). Set mode explicitly: "invite-only" (with allowOpenSignup: true if intentional) or "open".`
          );
        }
        ctx.logger.info(
          `better-enrollment: mode "${state.mode}" auto-detected (${describePaths(paths)}). Sign-up paths from other plugins are not detected${state.mode === "invite-only" ? " and cannot create accounts in invite-only mode" : ""}; set mode explicitly if you use any.`
        );
      } else {
        state.mode = opts.mode;
        if (opts.mode === "invite-only" && openPaths.length > 0) {
          const msg = `better-enrollment: mode is "invite-only" but sign-up is open on: ${describePaths(openPaths)}. The invite guarantee is per-email only; anyone else can sign up through the open paths.`;
          if (opts.allowOpenSignup) {
            ctx.logger.warn(msg);
          } else {
            throw new Error(
              `${msg} Close those paths, or set allowOpenSignup: true if intentional.`
            );
          }
        }
      }

      const magicLinkPlugin = ctx.options.plugins?.find((p) => p.id === "magic-link") as
        { options?: MagicLinkLikeOptions } | undefined;
      state.magicLinkOptions = magicLinkPlugin ? (magicLinkPlugin.options ?? {}) : null;
      state.credentialEnabled = !!ctx.options.emailAndPassword?.enabled;
      state.passwordless =
        opts.passwordless === "auto"
          ? !!magicLinkPlugin && !state.credentialEnabled
          : opts.passwordless;
      if (state.passwordless) {
        ctx.logger.info(
          "better-enrollment: passwordless redemption active. Accept works without a password; private accepters are signed in directly."
        );
      }
      if (!opts.buildInviteUrl && !ctx.baseURL) {
        throw new Error(
          "better-enrollment: set baseURL (or BETTER_AUTH_URL) or buildInviteUrl, so invite links point at your app and not at the host a request names."
        );
      }
      if (
        state.mode === "invite-only" &&
        state.credentialEnabled &&
        !ctx.options.emailAndPassword?.requireEmailVerification
      ) {
        ctx.logger.warn(
          "better-enrollment: emailAndPassword.requireEmailVerification is off, so accounts created through public invite links are usable before their email is verified. Set requireEmailVerification: true, or issue only private invites."
        );
      }

      const adminPlugin = ctx.options.plugins?.find((p) => p.id === "admin") as
        { options?: AdminPluginLikeOptions } | undefined;
      state.adminPluginOptions = adminPlugin ? (adminPlugin.options ?? {}) : null;
      if (
        !adminPlugin &&
        !acMode &&
        opts.canManageInvites &&
        !opts.canGrantRole &&
        !opts.grantableRoles
      ) {
        ctx.logger.warn(
          "better-enrollment: canManageInvites is set without the admin plugin, canGrantRole or grantableRoles, so anyone it admits may grant any role through an invite. Set canGrantRole to limit which roles each inviter may grant."
        );
      }

      const orgPlugin = ctx.options.plugins?.find((p) => p.id === "organization") as
        { options?: OrgPluginLikeOptions } | undefined;
      state.orgPluginPresent = !!orgPlugin;
      state.orgPluginOptions = orgPlugin?.options ?? null;
      state.orgCreatorRole = orgPlugin?.options?.creatorRole ?? "owner";

      if (opts.grantableRolesCheck !== "off") {
        const appRecord = (state.adminPluginOptions?.roles ??
          opts.roles ??
          (adminPlugin ? adminPluginDefaultRoles : undefined)) as RoleRecord | undefined;
        const orgRecord = (orgOpts?.roles ?? orgPluginDefaultRoles) as RoleRecord;
        const problems = [
          ...grantableRoleProblems("app", opts.grantableRoles, appRecord),
          ...grantableRoleProblems("organization", orgOpts?.grantableRoles, orgRecord)
        ];
        if (problems.length > 0) {
          const msg = `better-enrollment: a grantable role must not exceed its holder's permissions, since the holder can redeem it through a second account.\n  ${problems.join("\n  ")}`;
          if ((opts.grantableRolesCheck ?? "error") === "error") throw new Error(msg);
          ctx.logger.warn(msg);
        }
      }
      if (orgOpts && !orgPlugin) {
        throw new Error(
          "better-enrollment: organization options are set but the organization plugin is not registered. Add organization() to your plugins or remove the organization block."
        );
      }
      if (!orgOpts && orgPlugin) {
        ctx.logger.info(
          "better-enrollment: organization plugin detected but org invite features are off. Pass organization: {} to enable them."
        );
      }

      // Roles are stored on user.role. Without that field the invited role
      // has nowhere to land and the default admin gate matches nobody.
      const userFields = (
        ctx.tables as Record<string, { fields?: Record<string, unknown> }> | undefined
      )?.user?.fields;
      const hasRoleField = !!userFields?.role || !!ctx.options.user?.additionalFields?.role;
      if (!hasRoleField) {
        ctx.logger.warn(
          "better-enrollment: the user model has no `role` field. Invited roles cannot be stored, and the default adminRoles gate will match nobody. Register the admin plugin, or add a string `role` field via user.additionalFields, or gate invite management with adminUserIds / canManageInvites instead."
        );
      }

      if (!opts.validRoles) {
        ctx.logger.warn(
          "better-enrollment: no validRoles configured; invite roles are not validated."
        );
      }

      // A pre-created shell enters only through redemption. These hooks key
      // on the row (isPendingShell), not on the request path, so every
      // verification, sign-in, and account write is covered, including
      // plugins this plugin does not know about.
      // Hooks run inside the caller's transaction when there is one (Better
      // Auth 1.7.2x wraps several flows). Reading through the outer adapter
      // there waits on that transaction; single-connection databases such
      // as SQLite never return.
      const adapterOf = (context: GenericEndpointContext | null | undefined) =>
        getCurrentAdapter(context?.context.adapter ?? ctx.adapter);
      // update.before sees only the changed fields, not the row; it marks
      // the request so update.after (which sees the row) checks just the
      // writes that verify an email.
      const verifying = new WeakSet<object>();
      // Same marker technique for writes that ban a user, from any endpoint.
      const banning = new WeakSet<object>();
      // The auth context with its adapter swapped for the transaction's.
      const authOf = async (context: GenericEndpointContext | null | undefined): Promise<AuthCtx> => {
        const base = (context?.context ?? ctx) as AuthCtx;
        const adapter = await getCurrentAdapter(base.adapter);
        return adapter === base.adapter ? base : Object.assign(Object.create(base), { adapter });
      };
      const revokeOnBan = orgOpts?.revokeInvitesOnInviterBan !== false;

      return {
        options: {
          databaseHooks: {
            user: {
              create: {
                // Backstop for sign-up paths mode detection cannot see (other
                // plugins). Invite-only: accounts come from redemption, the
                // admin plugin, or server code outside a request. With
                // allowOpenSignup only invited addresses are held back.
                before: async (user, context) => {
                  if (state.mode !== "invite-only" || !context) return;
                  if (fromRedeem(context) || USER_CREATION_PATHS.has(context.path)) return;
                  if (opts.allowOpenSignup) {
                    const email = (user as { email?: unknown }).email;
                    if (typeof email !== "string" || !email) return;
                    const invited = await (await adapterOf(context)).findOne<Invite>({
                      model: "invite",
                      where: [
                        { field: "email", value: email.toLowerCase() },
                        { field: "mode", value: "invite-only" },
                        { field: "type", value: "private" },
                        { field: "status", value: "pending" }
                      ]
                    });
                    if (!invited) return;
                    // Answer as for an address that already has an account,
                    // so open paths never single out invited addresses. With
                    // duplicate hiding on, /sign-up/email turns a 403 here
                    // into its generic duplicate response (Better Auth 1.7).
                    const ep = ctx.options.emailAndPassword;
                    const hidesDuplicates =
                      !!ep?.requireEmailVerification || ep?.autoSignIn === false;
                    throw APIError.from(
                      hidesDuplicates ? "FORBIDDEN" : "UNPROCESSABLE_ENTITY",
                      USER_ALREADY_EXISTS
                    );
                  }
                  throw APIError.from("FORBIDDEN", INVITE_ERROR_CODES.SIGN_UP_REQUIRES_INVITATION);
                }
              },
              update: {
                before: async (data, context) => {
                  if (!context) return;
                  const changed = data as { emailVerified?: boolean; banned?: boolean };
                  if (changed.banned === true && revokeOnBan) banning.add(context);
                  if (state.mode !== "invite-only" || fromRedeem(context)) return;
                  if (changed.emailVerified === true) verifying.add(context);
                },
                after: async (user, context) => {
                  const banned = user as { id?: string; banned?: boolean | null } | null;
                  // Without a request context nothing was marked; a direct
                  // server-side write that leaves the user banned still counts.
                  const banWrite = context ? banning.has(context) : revokeOnBan;
                  if (context) banning.delete(context);
                  if (banWrite && banned?.id && banned.banned === true) {
                    await cancelPendingInvites(
                      await authOf(context),
                      [{ field: "createdByUserId", value: banned.id }],
                      "inviter-banned",
                      { userId: banned.id }
                    );
                  }
                  if (!context || !verifying.has(context)) return;
                  verifying.delete(context);
                  const row = user as { id?: string; emailVerified?: boolean } | null;
                  if (!row?.id || !row.emailVerified) return;
                  const adapter = await adapterOf(context);
                  if (!(await isPendingShell(adapter, row.id))) return;
                  await adapter.update({
                    model: "user",
                    where: [{ field: "id", value: row.id }],
                    update: { emailVerified: false }
                  });
                  throw APIError.from("FORBIDDEN", INVITE_ERROR_CODES.INVITATION_REQUIRED);
                }
              },
              delete: {
                // Any account deletion (admin remove-user, self-delete,
                // deleteUser). Shell cleanup deletes raw and never lands here.
                after: async (user, context) => {
                  const row = user as { id?: string; email?: string } | null;
                  if (!row?.id) return;
                  const c = await authOf(context);
                  await deleteCreatorInvites(c, row.id);
                  // A pending private invite to the removed address would
                  // recreate the account and undo the removal.
                  if (row.email) {
                    await cancelPendingInvites(
                      c,
                      [{ field: "email", value: row.email.toLowerCase() }],
                      "invitee-deleted",
                      { userId: row.id }
                    );
                  }
                }
              }
            },
            account: {
              create: {
                before: async (account, context) => {
                  if (state.mode !== "invite-only") return;
                  // Any provider, credential included: a password reset
                  // writes a credential onto a shell just like OAuth links.
                  if (
                    !fromRedeem(context) &&
                    (await isPendingShell(await adapterOf(context), account.userId))
                  ) {
                    throw APIError.from("FORBIDDEN", INVITE_ERROR_CODES.INVITATION_REQUIRED);
                  }
                  if (account.providerId === "credential") return;
                  if (!context) return;
                  const user = await context.context.internalAdapter.findUserById(account.userId);
                  if (!user || user.emailVerified) return;
                  // Any non-accepted invite: a cancelled one leaves an inert
                  // pre-created user behind; linking stays blocked for it too.
                  const open = await (await adapterOf(context)).findMany<Invite>({
                    model: "invite",
                    where: [
                      { field: "email", value: user.email.toLowerCase() },
                      { field: "mode", value: "invite-only" },
                      { field: "status", value: ["pending", "cancelled"], operator: "in" }
                    ],
                    limit: 1
                  });
                  if (open.length > 0) {
                    throw APIError.from("FORBIDDEN", INVITE_ERROR_CODES.INVITATION_REQUIRED);
                  }
                }
              }
            },
            session: {
              create: {
                // Paths that can sign in a user without an account row
                // (verification auto sign-in, email OTP, magic link, unknown
                // plugins): one indexed lookup. Account-based logins skip it.
                before: async (session, context) => {
                  if (state.mode !== "invite-only" || fromRedeem(context)) return;
                  if (isAccountSignIn(context?.path)) return;
                  const userId = (session as { userId: string }).userId;
                  const adapter = await adapterOf(context);
                  if (await isPendingShell(adapter, userId)) {
                    // A verify step may have flipped emailVerified through
                    // a write this plugin's hooks never saw; undo it so the
                    // shell stays inert, then refuse the session.
                    await adapter.update({
                      model: "user",
                      where: [{ field: "id", value: userId }],
                      update: { emailVerified: false }
                    });
                    throw APIError.from("FORBIDDEN", INVITE_ERROR_CODES.INVITATION_REQUIRED);
                  }
                }
              }
            }
          }
        } satisfies Partial<BetterAuthOptions>
      };
    },

    hooks: {
      before: [
        {
          matcher: (ctx) =>
            ctx.path === "/request-password-reset" || ctx.path === "/forget-password",
          handler: createAuthMiddleware(async (ctx) => {
            if (state.mode !== "invite-only") return;
            const email = bodyEmail(ctx);
            if (!email) return;
            // Only an invite's own pre-created user is locked; established
            // accounts reset normally whatever invites their address had.
            if (!(await hasPendingShellInvite(ctx, email))) return;
            const found = (await ctx.context.internalAdapter.findUserByEmail(email, {
              includeAccounts: true
            })) as MaybeWithAccounts | null;
            const hasCredential =
              found && "accounts" in found
                ? found.accounts.some((a) => a.providerId === "credential")
                : false;
            if (unwrapUser(found) && !hasCredential) {
              // Core resetPassword CREATES a credential account when none
              // exists (invite bypass). Reply with core's exact
              // silent-success body: no reset, no oracle.
              return new Response(
                JSON.stringify({
                  status: true,
                  message: "If this email exists in our system, check your email for the reset link"
                }),
                {
                  status: 200,
                  headers: { "content-type": "application/json" }
                }
              );
            }
          })
        },
        {
          // Magic-link verify signs in EXISTING users regardless of its
          // disableSignUp, and an invite from 0.x may still own a
          // pre-created user. Without this guard its invitee could skip
          // the invite flow entirely.
          // The token is resolved to its email without consuming it, using
          // the same storeToken transform the magic-link plugin configured.
          matcher: (ctx) => ctx.path === "/magic-link/verify",
          handler: createAuthMiddleware(async (ctx) => {
            if (state.mode !== "invite-only" || !state.magicLinkOptions) return;
            const token = (ctx.query as Record<string, unknown> | undefined)?.token;
            if (typeof token !== "string" || !token) return;
            const st = state.magicLinkOptions.storeToken ?? "plain";
            let identifier = token;
            if (st === "hashed") {
              identifier = await sha256Base64Url(token);
            } else if (typeof st === "object" && st.type === "custom-hasher") {
              identifier = await st.hash(token);
            }
            const verification = await ctx.context.adapter.findOne<{ value: string }>({
              model: "verification",
              where: [{ field: "identifier", value: identifier }]
            });
            if (!verification) return;
            let email: unknown;
            try {
              email = (JSON.parse(verification.value) as { email?: unknown }).email;
            } catch {
              return;
            }
            if (typeof email !== "string" || !email) return;
            // Only pre-created shells are locked; activation invites
            // (existing accounts) must not break their owner's sign-in.
            if (await hasPendingShellInvite(ctx, email)) {
              throw APIError.from("FORBIDDEN", INVITE_ERROR_CODES.INVITATION_REQUIRED);
            }
          })
        },
        {
          // An invited address without an account (or with a 0.x shell)
          // enters only through its invite, so a magic link would be
          // refused on verify. Reply with the endpoint's exact success body
          // without sending, mirroring the password-reset guard: no dead
          // link in the inbox, no invite oracle.
          matcher: (ctx) => ctx.path === "/sign-in/magic-link",
          handler: createAuthMiddleware(async (ctx) => {
            if (state.mode !== "invite-only" || !state.magicLinkOptions) return;
            const email = bodyEmail(ctx);
            if (!email) return;
            const invited = await inviteOnlyState(ctx, email);
            if (
              invited.shell ||
              (invited.pendingPrivate &&
                !(await ctx.context.internalAdapter.findUserByEmail(email)))
            ) {
              return new Response(JSON.stringify({ status: true }), {
                status: 200,
                headers: { "content-type": "application/json" }
              });
            }
          })
        },
        {
          // The org plugin's own invitations would add members past the
          // seat limit. Checked only on these two endpoints and only for
          // orgs with a limit; not atomic, since the org plugin writes.
          matcher: (ctx) =>
            ctx.path === "/organization/invite-member" ||
            ctx.path === "/organization/accept-invitation",
          handler: createAuthMiddleware(async (ctx) => {
            if (!orgEnabled() || orgOpts?.enforceSeatLimitOnOrgPlugin === false) return;
            const body = ctx.body as Record<string, unknown> | undefined;
            let organizationId: string | undefined;
            if (ctx.path === "/organization/accept-invitation") {
              if (typeof body?.invitationId !== "string") return;
              const invitation = await ctx.context.adapter
                .findOne<{ organizationId: string }>({
                  model: "invitation",
                  where: [{ field: "id", value: body.invitationId }]
                })
                .catch(() => null);
              organizationId = invitation?.organizationId;
            } else if (typeof body?.organizationId === "string") {
              organizationId = body.organizationId;
            } else {
              const session = await getSessionFromCtx(ctx).catch(() => null);
              organizationId =
                (session?.session as { activeOrganizationId?: string | null } | undefined)
                  ?.activeOrganizationId ?? undefined;
            }
            if (!organizationId) return;
            const org = await findOrg(ctx, organizationId);
            if (!org) return;
            const limit = await seatLimitFor(ctx, org);
            if (limit == null) return;
            const { members, reserved } = await seatUsage(ctx, org.id);
            if (members + reserved >= limit) {
              await orgOpts?.onSeatLimitReached?.({ organization: org });
              throw APIError.from("UNPROCESSABLE_ENTITY", INVITE_ERROR_CODES.SEAT_LIMIT_REACHED);
            }
          })
        },
        {
          // A disabled org rejects org plugin traffic targeting it,
          // whether addressed by id, slug, invitation, team, or implicitly
          // through the session's active organization. Every target the
          // request names is checked, in body and query alike: endpoints
          // differ in which one they prefer (reads take the slug over the
          // id), so a decoy id must not hide a disabled slug.
          matcher: (ctx) => !!ctx.path?.startsWith("/organization"),
          handler: createAuthMiddleware(async (ctx) => {
            if (!orgEnabled()) return;
            const str = (v: unknown) => (typeof v === "string" && v ? v : undefined);
            const body = ctx.body as Record<string, unknown> | undefined;
            const query = ctx.query as Record<string, unknown> | undefined;
            const named = (key: string) =>
              [...new Set([str(body?.[key]), str(query?.[key])])].filter(
                (v): v is string => !!v
              );

            const orgIds = new Set(named("organizationId"));
            for (const slug of named("organizationSlug")) {
              const bySlug = await ctx.context.adapter
                .findOne<OrganizationRecord>({
                  model: "organization",
                  where: [{ field: "slug", value: slug }]
                })
                .catch(() => null);
              if (bySlug?.disabledAt) {
                throw APIError.from("FORBIDDEN", INVITE_ERROR_CODES.ORG_DISABLED);
              }
              if (bySlug) orgIds.add(bySlug.id);
            }
            // get-invitation names its invitation as `id`.
            const invitationIds = [
              ...named("invitationId"),
              ...(ctx.path === "/organization/get-invitation" ? named("id") : [])
            ];
            for (const invitationId of invitationIds) {
              const invitation = await ctx.context.adapter
                .findOne<{ organizationId?: string }>({
                  model: "invitation",
                  where: [{ field: "id", value: invitationId }]
                })
                .catch(() => null);
              if (invitation?.organizationId) orgIds.add(invitation.organizationId);
            }
            for (const teamId of named("teamId")) {
              const team = await ctx.context.adapter
                .findOne<{ organizationId?: string }>({
                  model: "team",
                  where: [{ field: "id", value: teamId }]
                })
                .catch(() => null);
              if (team?.organizationId) orgIds.add(team.organizationId);
            }
            if (orgIds.size > 0) {
              for (const id of orgIds) {
                const org = await findOrg(ctx, id);
                if (org?.disabledAt) {
                  throw APIError.from("FORBIDDEN", INVITE_ERROR_CODES.ORG_DISABLED);
                }
              }
              return;
            }
            // No explicit target: most org endpoints then act on the
            // active organization. Endpoints that never do are exempt, or a
            // disabled active org would lock users out of listing,
            // creating, and switching orgs.
            const implicit = ![
              "/organization/list",
              "/organization/create",
              "/organization/set-active"
            ].includes(ctx.path ?? "");
            if (!implicit) return;
            const session = await getSessionFromCtx(ctx).catch(() => null);
            const orgId = str(
              (session?.session as { activeOrganizationId?: unknown } | undefined)
                ?.activeOrganizationId
            );
            if (!orgId) return;
            const org = await findOrg(ctx, orgId);
            if (org?.disabledAt) {
              throw APIError.from("FORBIDDEN", INVITE_ERROR_CODES.ORG_DISABLED);
            }
          })
        }
      ],
      after: [
        {
          // The caller's own invitation list names no org, so the
          // disabled-org before-hook cannot refuse it; drop invitations to
          // disabled orgs from the answer instead. One read, this path only.
          matcher: (ctx) => ctx.path === "/organization/list-user-invitations",
          handler: createAuthMiddleware(async (ctx) => {
            if (!orgEnabled()) return;
            const returned = ctx.context.returned;
            if (!Array.isArray(returned) || returned.length === 0) return;
            const rows = returned as { organizationId?: unknown }[];
            const ids = [
              ...new Set(
                rows
                  .map((i) => i?.organizationId)
                  .filter((v): v is string => typeof v === "string")
              )
            ];
            if (ids.length === 0) return;
            const orgs = await ctx.context.adapter.findMany<OrganizationRecord>({
              model: "organization",
              where: [{ field: "id", value: ids, operator: "in" }],
              limit: ids.length
            });
            const disabled = new Set(orgs.filter((o) => o.disabledAt).map((o) => o.id));
            if (disabled.size === 0) return;
            return ctx.json(
              rows.filter((i) => !disabled.has(i?.organizationId as string))
            );
          })
        },
        {
          // Bans and account deletion are handled by the user database
          // hooks (any path). The org plugin writes member rows directly, so
          // losing org standing is caught on its endpoints: a former member's
          // org-join invites, or those its new role may no longer create or
          // grant, are cancelled. One query unless the role changed.
          matcher: (ctx) =>
            ctx.path === "/organization/remove-member" ||
            ctx.path === "/organization/leave" ||
            ctx.path === "/organization/update-member-role",
          handler: createAuthMiddleware(async (ctx) => {
            if (!orgEnabled()) return;
            const returned = ctx.context.returned;
            if (!returned || returned instanceof APIError || returned instanceof Response) return;
            const raw = returned as { member?: MemberRecord } & Partial<MemberRecord>;
            const member = (raw.member ?? raw) as MemberRecord;
            if (!member?.userId || !member.organizationId) return;
            const where = [
              { field: "createdByUserId", value: member.userId },
              { field: "organizationId", value: member.organizationId },
              { field: "kind", value: "org-join" }
            ];
            const scope = { userId: member.userId, organizationId: member.organizationId };
            // System invites attributed to the member never relied on its org rights.
            const system = (invite: Invite) => !!invite.createdBySystem;
            if (ctx.path !== "/organization/update-member-role") {
              await cancelPendingInvites(
                ctx.context,
                where,
                ctx.path === "/organization/leave" ? "inviter-left-org" : "inviter-removed-from-org",
                scope,
                system
              );
              return;
            }
            const org = await findOrg(ctx, member.organizationId);
            if (!org) return;
            const mayCreate = orgOpts?.canCreateOrgInvites
              ? await orgOpts.canCreateOrgInvites(member, org)
              : await memberHasInvitePermission(ctx, member, "create");
            await cancelPendingInvites(
              ctx.context,
              where,
              "inviter-role-changed",
              scope,
              async (invite) =>
                system(invite) ||
                (mayCreate &&
                  (await canGrantOrgRole(
                    ctx,
                    member,
                    org,
                    invite.organizationRole ?? defaultOrgRole()
                  )))
            );
          })
        }
      ]
    },

    rateLimit: [
      {
        pathMatcher: (path) =>
          path === "/invite/accept" || path === "/invite/activate" || path === "/invite/redeem",
        window: 60,
        max: 5
      },
      {
        pathMatcher: (path) =>
          path === "/invite/get" ||
          path === "/invite/lookup" ||
          path === "/invite/check-slug" ||
          path === "/invite/verify-slug",
        window: 60,
        max: 10
      },
      // Both send mail. Server-side auth.api calls are never rate limited.
      { pathMatcher: (path) => path === "/invite/create", window: 60, max: 20 },
      { pathMatcher: (path) => path === "/invite/resend", window: 60, max: 10 }
    ],

    endpoints: {
      createInvite: createAuthEndpoint(
        "/invite/create",
        {
          method: "POST",
          use: [sessionMiddleware],
          body: createInviteBody
        },
        async (ctx) => {
          return await createInviteCore(ctx, ctx.body, { type: "user" });
        }
      ),

      createSystemInvite: createAuthEndpoint(
        "/invite/create-system",
        {
          method: "POST",
          metadata: { SERVER_ONLY: true },
          body: createInviteBody.extend({
            inviter: z
              .object({
                name: z.string().max(200).optional(),
                email: z.string().max(200).optional(),
                userId: z.string().min(1).max(200).optional()
              })
              .optional()
          })
        },
        async (ctx) => {
          // Headless creation for crons and system integrations. Attribution
          // falls back to the app name, then "System"; Better Auth resolves
          // an unset appName to "Better Auth", which counts as absent here.
          const appName = ctx.context.appName;
          const inviterName =
            ctx.body.inviter?.name || (!appName || appName === "Better Auth" ? "System" : appName);
          const inviterEmail = ctx.body.inviter?.email || "System";
          // An attributed system invite behaves like that user's own for
          // the ban and remove-user cleanup hooks.
          return await createInviteCore(ctx, ctx.body, {
            type: "system",
            inviterName,
            inviterEmail,
            createdByUserId: ctx.body.inviter?.userId ?? null
          });
        }
      ),

      resendInvite: createAuthEndpoint(
        "/invite/resend",
        {
          method: "POST",
          use: [sessionMiddleware],
          body: z.object({
            inviteId: z.string().min(1),
            expiresIn: z.number().int().positive().optional()
          })
        },
        async (ctx) => {
          const user = await getAuthUser(ctx);
          // App admin is a moderation backstop; org members need
          // invitation:create in the invite's org, mirroring creation.
          // Permission first: state is reported only to those who pass.
          const {
            invite,
            org,
            member: resenderMember
          } = await inviteForManagement(ctx, user, ctx.body.inviteId, "resend", "create");
          if (invite.status === "cancelled") {
            throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.INVITE_REVOKED);
          }
          if (invite.status === "accepted") {
            throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.INVITE_ALREADY_USED);
          }
          if (org?.disabledAt) {
            throw APIError.from("FORBIDDEN", INVITE_ERROR_CODES.ORG_DISABLED);
          }
          // Resending a public invite hands its new link to the resender,
          // which is as good as creating it: the resender must be allowed
          // to grant its roles. Private links go only to the mailbox.
          if (invite.type === "public") {
            assertPublicRolesAllowed(invite, "UNPROCESSABLE_ENTITY");
            if (invite.kind === "org-create") await assertMayFoundOrgs(user);
            await assertCanGrantAppRole(user, invite.role);
            if (invite.kind === "org-join" && org) {
              const orgRole = invite.organizationRole ?? defaultOrgRole();
              if (!splitRoles(orgRole).every((r) => r === defaultOrgRole())) {
                const member = resenderMember ?? (await findMember(ctx, user.id, org.id));
                if (!member) {
                  throw APIError.from("FORBIDDEN", INVITE_ERROR_CODES.ORG_ROLE_NOT_GRANTABLE);
                }
                await assertCanGrantOrgRole(ctx, member, org, orgRole);
              }
            }
          }
          // An expired invite released its seat reservation lazily;
          // resending re-arms it, so the limit must hold again.
          if (org && isExpired(invite)) {
            const limit = await seatLimitFor(ctx, org);
            if (limit != null) {
              const needed = reservedSeats({ ...invite, expiresAt: null });
              const { members, reserved } = await seatUsage(ctx, org.id);
              if (members + reserved + needed > limit) {
                await orgOpts?.onSeatLimitReached?.({ organization: org });
                throw APIError.from("UNPROCESSABLE_ENTITY", INVITE_ERROR_CODES.SEAT_LIMIT_REACHED);
              }
            }
          }

          const token = generateRandomString(32);
          const tokenHash = await sha256Base64Url(token);
          const expiresAt = inviteExpiresAt(ctx.body.expiresIn, invite.type);
          // Private resends mail a third party: one per cooldown, enforced
          // in the CAS so parallel resends send once. Public invites change
          // updatedAt on every use, so the rate limit covers them instead.
          const cooldownSince =
            invite.type === "private" && opts.resendCooldown > 0
              ? new Date(Date.now() - opts.resendCooldown * 1000)
              : null;
          if (cooldownSince && new Date(invite.updatedAt) > cooldownSince) {
            throw APIError.from("TOO_MANY_REQUESTS", INVITE_ERROR_CODES.RESEND_TOO_SOON);
          }
          // CAS on pending: swapping the token hash kills the old link,
          // and a parallel accept that already consumed the invite wins.
          const updated = await ctx.context.adapter.update<Invite>({
            model: "invite",
            where: [
              { field: "id", value: invite.id },
              { field: "status", value: "pending" },
              ...(cooldownSince
                ? [{ field: "updatedAt", value: cooldownSince, operator: "lte" as const }]
                : [])
            ],
            update: { tokenHash, expiresAt, expiryNotifiedAt: null, updatedAt: new Date() }
          });
          if (!updated) {
            const now = cooldownSince
              ? await ctx.context.adapter.findOne<Invite>({
                  model: "invite",
                  where: [{ field: "id", value: invite.id }]
                })
              : null;
            if (now?.status === "pending") {
              throw APIError.from("TOO_MANY_REQUESTS", INVITE_ERROR_CODES.RESEND_TOO_SOON);
            }
            throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.INVITE_ALREADY_USED);
          }
          // Write, then verify: parallel revivals can all pass the check
          // above. A revived invite keeps its old createdAt, so ranking does
          // not apply; on overflow it reverts (parallel revivals may both).
          if (org && isExpired(invite)) {
            const limit = await seatLimitFor(ctx, org);
            if (limit != null) {
              const { members, reserved } = await seatUsage(ctx, org.id);
              if (members + reserved > limit) {
                await ctx.context.adapter.update({
                  model: "invite",
                  where: [
                    { field: "id", value: invite.id },
                    { field: "tokenHash", value: tokenHash }
                  ],
                  update: {
                    tokenHash: invite.tokenHash,
                    expiresAt: invite.expiresAt,
                    expiryNotifiedAt: invite.expiryNotifiedAt ?? null
                  }
                });
                await orgOpts?.onSeatLimitReached?.({ organization: org });
                throw APIError.from("UNPROCESSABLE_ENTITY", INVITE_ERROR_CODES.SEAT_LIMIT_REACHED);
              }
            }
          }

          const url = buildInviteUrl(ctx, token, invite.type);
          if (invite.type === "private" && invite.email) {
            await opts.sendPrivateInvitation?.(
              {
                email: invite.email,
                name: invite.name ?? null,
                role: invite.role,
                kind: invite.kind,
                mode: invite.mode,
                url,
                token,
                inviterName: invite.inviterName,
                inviterEmail: invite.inviterEmail,
                organizationName: org?.name ?? invite.presetOrganizationName ?? null,
                inviteId: invite.id,
                organizationId: invite.organizationId,
                organizationRole: invite.organizationRole,
                teamId: invite.teamId,
                expiresAt
              },
              ctx.request
            );
          } else {
            await opts.sendPublicInvitation?.(
              {
                role: invite.role,
                kind: invite.kind,
                mode: invite.mode,
                url,
                token,
                inviterName: invite.inviterName,
                inviterEmail: invite.inviterEmail,
                organizationName: org?.name ?? invite.presetOrganizationName ?? null,
                inviteId: invite.id,
                organizationId: invite.organizationId,
                organizationRole: invite.organizationRole,
                teamId: invite.teamId,
                maxUses: invite.maxUses,
                expiresAt
              },
              ctx.request
            );
          }
          await opts.onInviteResent?.({ invite: updated, admin: user });
          // Same visibility rules as creation: a private link only ever
          // reaches the invitee's mailbox; a public link is returned.
          return ctx.json({
            inviteId: invite.id,
            expiresAt,
            ...(invite.type === "public" ? { token, url } : {})
          });
        }
      ),

      acceptInvite: createAuthEndpoint(
        "/invite/accept",
        {
          method: "POST",
          // Loose: configured additional fields ride alongside the fixed
          // keys and are validated by parseAdditionalFields.
          body: z.looseObject({
            token: z.string().min(1),
            // Optional at the schema level; acceptCore requires it unless
            // passwordless redemption is active.
            password: z.string().min(1).optional(),
            name: z.string().max(200).optional(),
            email: z.email().optional(),
            organizationName: z.string().max(200).optional(),
            organizationSlug: z.string().max(200).optional()
          })
        },
        async (ctx) => {
          if (getMode() !== "invite-only") {
            throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.ACCEPT_ONLY_IN_INVITE_ONLY_MODE);
          }
          return await acceptCore(ctx, ctx.body);
        }
      ),

      activateInvite: createAuthEndpoint(
        "/invite/activate",
        {
          method: "POST",
          // Loose: CONFIRM-step additional fields ride alongside the fixed
          // keys and are validated by parseAdditionalFields.
          body: z.looseObject({
            token: z.string().min(1),
            organizationName: z.string().max(200).optional(),
            organizationSlug: z.string().max(200).optional()
          })
        },
        async (ctx) => {
          if (getMode() !== "open") {
            throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.ACTIVATE_ONLY_IN_OPEN_MODE);
          }
          return await activateCore(ctx, ctx.body);
        }
      ),

      redeemInvite: createAuthEndpoint(
        "/invite/redeem",
        {
          method: "POST",
          // Loose: configured additional fields ride alongside the fixed
          // keys and are validated by parseAdditionalFields.
          body: z.looseObject({
            token: z.string().min(1),
            password: z.string().min(1).optional(),
            name: z.string().max(200).optional(),
            email: z.email().optional(),
            organizationName: z.string().max(200).optional(),
            organizationSlug: z.string().max(200).optional()
          })
        },
        async (ctx) => {
          // One door for every kind and both modes; the invite row and
          // the resolved mode decide what happens under the hood.
          if (getMode() !== "invite-only") {
            return await activateCore(ctx, ctx.body);
          }
          // Invites held by established accounts redeem as activations: a
          // private invite whose email already belongs to an account that
          // can be signed into, or a signed-in user redeeming a public
          // invite. Everything else, including another invite's inert
          // shell, is a sign-up.
          const invite = await findInviteByToken(ctx, ctx.body.token);
          if (invite?.type === "private" && (await privateInviteActivates(ctx, invite))) {
            return await activateCore(ctx, ctx.body);
          }
          if (invite?.type === "public") {
            const session = await getSessionFromCtx(ctx).catch(() => null);
            if (session) return await activateCore(ctx, ctx.body);
          }
          return await acceptCore(ctx, ctx.body);
        }
      ),

      getInvite: createAuthEndpoint(
        "/invite/get",
        {
          method: "GET",
          query: z.object({
            token: z.string().min(1)
          })
        },
        async (ctx) => getInviteCore(ctx, ctx.query.token)
      ),

      // invite.get with the token in the body: fragment links read the
      // token in the page and keep it out of URLs and access logs.
      lookupInvite: createAuthEndpoint(
        "/invite/lookup",
        {
          method: "POST",
          body: z.object({
            token: z.string().min(1)
          })
        },
        async (ctx) => getInviteCore(ctx, ctx.body.token)
      ),

      // Same single indexed lookup the org plugin's /organization/check-slug
      // runs, but gated by a pending org-create invite token instead of a
      // session, so the anonymous sign-up form can check without opening a
      // slug enumeration oracle.
      checkInviteSlug: createAuthEndpoint(
        "/invite/check-slug",
        {
          method: "GET",
          query: z.object({
            token: z.string().min(1),
            slug: z.string().min(1).max(100)
          })
        },
        async (ctx) => checkSlugCore(ctx, ctx.query.token, ctx.query.slug)
      ),

      // check-slug with the token in the body, out of URLs and access logs.
      verifyInviteSlug: createAuthEndpoint(
        "/invite/verify-slug",
        {
          method: "POST",
          body: z.object({
            token: z.string().min(1),
            slug: z.string().min(1).max(100)
          })
        },
        async (ctx) => checkSlugCore(ctx, ctx.body.token, ctx.body.slug)
      ),

      listInvites: createAuthEndpoint(
        "/invite/list",
        {
          method: "GET",
          use: [sessionMiddleware],
          query: z.object({
            status: z.enum(["pending", "accepted", "cancelled", "expired"]).optional(),
            type: z.enum(["private", "public"]).optional(),
            kind: z.enum(["app", "org-join", "org-create"]).optional(),
            email: z.string().max(200).optional(),
            organizationId: z.string().optional(),
            cursor: z.string().min(1).max(500).optional(),
            page: z.coerce.number().int().positive().default(1),
            limit: z.coerce.number().int().positive().max(100).default(20)
          })
        },
        async (ctx) => {
          const user = await getAuthUser(ctx);
          const admin = await isInviteAdmin(user, "list");
          const now = new Date();
          // email + kind let a UI resolve EMAIL_ALREADY_INVITED to the exact
          // row to resend. Same visibility rules as every other filter.
          const where = [
            ...(ctx.query.type ? [{ field: "type", value: ctx.query.type }] : []),
            ...(ctx.query.kind ? [{ field: "kind", value: ctx.query.kind }] : []),
            ...(ctx.query.email
              ? [{ field: "email", value: ctx.query.email.toLowerCase().trim() }]
              : []),
            ...(ctx.query.status === "expired"
              ? [
                  { field: "status", value: "pending" },
                  { field: "expiresAt", value: now, operator: "lt" as const }
                ]
              : ctx.query.status
                ? [{ field: "status", value: ctx.query.status }]
                : [])
          ];
          if (admin) {
            if (ctx.query.organizationId) {
              where.push({
                field: "organizationId",
                value: ctx.query.organizationId
              });
            }
          } else {
            // Org members with invitation:create see their org only.
            if (!orgEnabled() || !ctx.query.organizationId) {
              throw APIError.from("FORBIDDEN", INVITE_ERROR_CODES.NOT_ALLOWED_TO_MANAGE_INVITES);
            }
            const access = await requireOrgInviteAccess(
              ctx,
              user,
              ctx.query.organizationId,
              "create"
            );
            where.push({ field: "organizationId", value: access.org.id });
          }
          const cursor = ctx.query.cursor ? decodeCursor(ctx.query.cursor) : null;
          if (ctx.query.cursor && !cursor) {
            throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.INVALID_CURSOR);
          }
          const { limit, page } = ctx.query;
          const [{ invites, hasMore }, total] = await Promise.all([
            // Offset only for an explicit later page without a cursor; the
            // first page is keyset so its nextCursor continues exactly.
            !cursor && page > 1
              ? ctx.context.adapter
                  .findMany<Invite>({
                    model: "invite",
                    where,
                    limit: limit + 1,
                    offset: (page - 1) * limit,
                    sortBy: { field: "createdAt", direction: "desc" }
                  })
                  .then((rows) => ({ invites: rows.slice(0, limit), hasMore: rows.length > limit }))
              : keysetPage<Invite>(ctx, "invite", "createdAt", where, limit, cursor).then(
                  ({ rows, hasMore }) => ({ invites: rows, hasMore })
                ),
            ctx.context.adapter.count({ model: "invite", where })
          ]);
          const last = invites[invites.length - 1];
          // The most recent uses, one bounded query. A full page means some
          // invite may be cut short; usesTruncated says which, and
          // /invite/uses pages one invite's complete trail.
          const uses = invites.length
            ? await ctx.context.adapter.findMany<InviteUse>({
                model: "inviteUse",
                where: [
                  {
                    field: "inviteId",
                    value: invites.map((i) => i.id),
                    operator: "in"
                  }
                ],
                limit: DB_PAGE,
                sortBy: { field: "usedAt", direction: "desc" }
              })
            : [];
          const usesFull = uses.length >= DB_PAGE;
          const byInvite = new Map<string, InviteUse[]>();
          for (const u of uses) {
            const list = byInvite.get(u.inviteId) ?? [];
            list.push(u);
            byInvite.set(u.inviteId, list);
          }
          return ctx.json({
            invites: invites.map((i) => {
              const {
                tokenHash: _tokenHash,
                preCreatedUserId,
                createdByUserId,
                revokedByUserId,
                ...rest
              } = i;
              const own = byInvite.get(i.id) ?? [];
              return {
                ...rest,
                // Internal user ids are for app admins only: a null
                // preCreatedUserId would tell an org inviter that the
                // address already had an account.
                ...(admin ? { preCreatedUserId, createdByUserId, revokedByUserId } : {}),
                status: deriveStatus(i, now),
                uses: own,
                usesTruncated: usesFull && own.length < i.useCount
              };
            }),
            total,
            page,
            limit,
            nextCursor: hasMore && last ? encodeCursor(last) : null
          });
        }
      ),

      listInviteUses: createAuthEndpoint(
        "/invite/uses",
        {
          method: "GET",
          use: [sessionMiddleware],
          query: z.object({
            inviteId: z.string().min(1),
            cursor: z.string().min(1).max(500).optional(),
            limit: z.coerce.number().int().positive().max(100).default(50)
          })
        },
        async (ctx) => {
          const user = await getAuthUser(ctx);
          // Same visibility as the list.
          const { invite } = await inviteForManagement(
            ctx,
            user,
            ctx.query.inviteId,
            "list",
            "create"
          );
          const cursor = ctx.query.cursor ? decodeCursor(ctx.query.cursor) : null;
          if (ctx.query.cursor && !cursor) {
            throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.INVALID_CURSOR);
          }
          const { rows, hasMore } = await keysetPage<InviteUse>(
            ctx,
            "inviteUse",
            "usedAt",
            [{ field: "inviteId", value: invite.id }],
            ctx.query.limit,
            cursor
          );
          const last = rows[rows.length - 1];
          return ctx.json({
            uses: rows,
            nextCursor:
              hasMore && last ? encodeCursor({ createdAt: last.usedAt, id: last.id }) : null
          });
        }
      ),

      revokeInvite: createAuthEndpoint(
        "/invite/revoke",
        {
          method: "POST",
          use: [sessionMiddleware],
          body: z.object({
            inviteId: z.string().min(1)
          })
        },
        async (ctx) => {
          const user = await getAuthUser(ctx);
          // App admin is a moderation backstop; org members need
          // invitation:cancel in the invite's org.
          await inviteForManagement(ctx, user, ctx.body.inviteId, "cancel", "cancel");
          // CAS: only pending invites can be revoked; racers lose cleanly.
          const revoked = await ctx.context.adapter.update<Invite>({
            model: "invite",
            where: [
              { field: "id", value: ctx.body.inviteId },
              { field: "status", value: "pending" }
            ],
            update: {
              status: "cancelled",
              revokedAt: new Date(),
              revokedByUserId: user.id,
              updatedAt: new Date()
            }
          });
          if (!revoked) {
            throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.INVITE_NOT_FOUND);
          }
          // A withdrawn invite keeps no account behind it.
          if (revoked.preCreatedUserId) {
            await deleteInertShells(ctx.context, [revoked.preCreatedUserId]);
          }
          await opts.onInviteRevoked?.({ invite: revoked, admin: user });
          return ctx.json({ revoked: true });
        }
      ),

      deleteInvite: createAuthEndpoint(
        "/invite/delete",
        {
          method: "POST",
          use: [sessionMiddleware],
          body: z.object({
            inviteId: z.string().min(1)
          })
        },
        async (ctx) => {
          const user = await getAuthUser(ctx);
          const { invite } = await inviteForManagement(
            ctx,
            user,
            ctx.body.inviteId,
            "delete",
            "cancel"
          );
          if (invite.status === "accepted") {
            throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.ACCEPTED_INVITES_ARE_PERMANENT);
          }
          if (invite.useCount > 0) {
            throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.USED_INVITES_CANNOT_BE_DELETED);
          }
          await deleteInviteAndInertUser(ctx, invite);
          await opts.onInviteDeleted?.({ invite, admin: user });
          return ctx.json({ deleted: true });
        }
      ),

      setOrgSeatLimit: createAuthEndpoint(
        "/invite/org/set-seat-limit",
        {
          method: "POST",
          use: [sessionMiddleware],
          body: z.object({
            organizationId: z.string().min(1),
            seatLimit: z.number().int().positive().nullable()
          })
        },
        async (ctx) => {
          await requireInviteAdmin(ctx, "manage-orgs");
          await requireOrgFeatures();
          const org = await findOrg(ctx, ctx.body.organizationId);
          if (!org) {
            throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.ORG_NOT_FOUND);
          }
          await ctx.context.adapter.update({
            model: "organization",
            where: [{ field: "id", value: org.id }],
            update: { seatLimit: ctx.body.seatLimit }
          });
          return ctx.json({ seatLimit: ctx.body.seatLimit });
        }
      ),

      orgInviteUsage: createAuthEndpoint(
        "/invite/org/usage",
        {
          method: "GET",
          use: [sessionMiddleware],
          query: z.object({
            organizationId: z.string().min(1)
          })
        },
        async (ctx) => {
          await requireOrgFeatures();
          const user = await getAuthUser(ctx);
          let org: OrganizationRecord | null;
          if (await isInviteAdmin(user, "list")) {
            org = await findOrg(ctx, ctx.query.organizationId);
            if (!org) {
              throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.ORG_NOT_FOUND);
            }
          } else {
            const access = await requireOrgInviteAccess(
              ctx,
              user,
              ctx.query.organizationId,
              "create"
            );
            org = access.org;
          }
          const limit = await seatLimitFor(ctx, org);
          const { members, reserved } = await seatUsage(ctx, org.id);
          return ctx.json({
            seatLimit: limit,
            members,
            pendingReserved: reserved,
            remaining: limit == null ? null : Math.max(0, limit - members - reserved)
          });
        }
      ),

      disableOrg: createAuthEndpoint(
        "/invite/org/disable",
        {
          method: "POST",
          use: [sessionMiddleware],
          body: z.object({
            organizationId: z.string().min(1),
            banMembers: z.boolean().default(false)
          })
        },
        async (ctx) => {
          const admin = await requireInviteAdmin(ctx, "manage-orgs");
          await requireOrgFeatures();
          const org = await findOrg(ctx, ctx.body.organizationId);
          if (!org) {
            throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.ORG_NOT_FOUND);
          }
          const disabledAt = new Date();
          await ctx.context.adapter.update({
            model: "organization",
            where: [{ field: "id", value: org.id }],
            update: { disabledAt }
          });
          const { banned: bannedMembers, skipped: skippedMembers } = ctx.body.banMembers
            ? await banOrgMembers(ctx, org.id, admin.id)
            : { banned: 0, skipped: 0 };
          await orgOpts?.onOrgDisabled?.({
            organization: { ...org, disabledAt },
            bannedMembers,
            skippedMembers
          });
          return ctx.json({ disabled: true, bannedMembers, skippedMembers });
        }
      ),

      enableOrg: createAuthEndpoint(
        "/invite/org/enable",
        {
          method: "POST",
          use: [sessionMiddleware],
          body: z.object({
            organizationId: z.string().min(1),
            // Lift the bans this org's banMembers stamped (default false).
            unbanMembers: z.boolean().default(false)
          })
        },
        async (ctx) => {
          await requireInviteAdmin(ctx, "manage-orgs");
          await requireOrgFeatures();
          const org = await findOrg(ctx, ctx.body.organizationId);
          if (!org) {
            throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.ORG_NOT_FOUND);
          }
          await ctx.context.adapter.update({
            model: "organization",
            where: [{ field: "id", value: org.id }],
            update: { disabledAt: null }
          });
          const unbannedMembers = ctx.body.unbanMembers ? await unbanOrgMembers(ctx, org.id) : 0;
          await orgOpts?.onOrgEnabled?.({
            organization: { ...org, disabledAt: null },
            unbannedMembers
          });
          return ctx.json({ enabled: true, unbannedMembers });
        }
      ),

      deleteOrg: createAuthEndpoint(
        "/invite/org/delete",
        {
          method: "POST",
          use: [sessionMiddleware],
          body: z.object({
            organizationId: z.string().min(1),
            banMembers: z.boolean().default(false)
          })
        },
        async (ctx) => {
          const admin = await requireInviteAdmin(ctx, "manage-orgs");
          await requireOrgFeatures();
          const org = await findOrg(ctx, ctx.body.organizationId);
          if (!org) {
            throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.ORG_NOT_FOUND);
          }
          // Ban first while member rows still exist.
          const { banned: bannedMembers, skipped: skippedMembers } = ctx.body.banMembers
            ? await banOrgMembers(ctx, org.id, admin.id)
            : { banned: 0, skipped: 0 };

          // Drain loops: fetch a page, delete it, repeat. Each pass removes
          // what it read, so the query converges and no IN clause exceeds
          // the page size.
          try {
            for (;;) {
              const teams = await ctx.context.adapter.findMany<TeamRecord>({
                model: "team",
                where: [{ field: "organizationId", value: org.id }],
                limit: DB_PAGE
              });
              if (teams.length === 0) break;
              const teamIds = teams.map((t) => t.id);
              await ctx.context.adapter.deleteMany({
                model: "teamMember",
                where: [{ field: "teamId", value: teamIds, operator: "in" }]
              });
              await ctx.context.adapter.deleteMany({
                model: "team",
                where: [{ field: "id", value: teamIds, operator: "in" }]
              });
            }
          } catch {
            // Teams tables absent (org plugin without teams): nothing to do.
          }
          // Secondary storage cannot be queried by organization, so active
          // org references are cleared per member while member rows still
          // exist. Skipped after banMembers: those sessions are gone.
          if (ctx.context.options.secondaryStorage && !ctx.body.banMembers) {
            for (let offset = 0; ; offset += DB_PAGE) {
              const members = await ctx.context.adapter.findMany<MemberRecord>({
                model: "member",
                where: [{ field: "organizationId", value: org.id }],
                limit: DB_PAGE,
                offset
              });
              if (members.length === 0) break;
              await clearActiveOrg(ctx, org.id, [...new Set(members.map((m) => m.userId))]);
              if (members.length < DB_PAGE) break;
            }
          }
          await ctx.context.adapter.deleteMany({
            model: "member",
            where: [{ field: "organizationId", value: org.id }]
          });
          for (;;) {
            const invites = await ctx.context.adapter.findMany<Invite>({
              model: "invite",
              where: [{ field: "organizationId", value: org.id }],
              limit: DB_PAGE
            });
            if (invites.length === 0) break;
            const inviteIds = invites.map((i) => i.id);
            await ctx.context.adapter.deleteMany({
              model: "inviteUse",
              where: [{ field: "inviteId", value: inviteIds, operator: "in" }]
            });
            await ctx.context.adapter.deleteMany({
              model: "invite",
              where: [{ field: "id", value: inviteIds, operator: "in" }]
            });
            // Deleting the invite row must not leave its pre-created shell
            // behind: with no invite left to own it, the email would be
            // locked forever with nothing left to delete it through.
            await deleteInertShells(
              ctx.context,
              invites
                .filter((i) => i.status !== "accepted")
                .map((i) => i.preCreatedUserId)
                .filter((v): v is string => !!v)
            );
          }
          // The org plugin's own invitation table, when present.
          await ctx.context.adapter
            .deleteMany({
              model: "invitation",
              where: [{ field: "organizationId", value: org.id }]
            })
            .catch(() => {});
          // Custom roles, when dynamic access control is on.
          await ctx.context.adapter
            .deleteMany({
              model: "organizationRole",
              where: [{ field: "organizationId", value: org.id }]
            })
            .catch(() => {});
          if (!ctx.context.options.secondaryStorage) {
            await clearActiveOrg(ctx, org.id, []);
          }
          await ctx.context.adapter.delete({
            model: "organization",
            where: [{ field: "id", value: org.id }]
          });
          await orgOpts?.onOrgDeleted?.({ organization: org, bannedMembers, skippedMembers });
          return ctx.json({ deleted: true, bannedMembers, skippedMembers });
        }
      ),

      cleanupExpiredInvites: createAuthEndpoint(
        "/invite/cleanup-expired",
        {
          method: "POST",
          metadata: { SERVER_ONLY: true },
          body: z
            .object({
              batchSize: z.number().int().positive().max(5000).optional()
            })
            .optional()
        },
        async (ctx) => {
          // Batched so the table size never dictates this request's memory
          // or duration: each pass fetches one batch, deletes it with
          // set-based queries, and repeats until drained. Invites with
          // recorded uses are excluded up front and stay as audit records.
          const batch = ctx.body?.batchSize ?? 500;
          let deleted = 0;
          for (;;) {
            const expired = await ctx.context.adapter.findMany<Invite>({
              model: "invite",
              where: [
                { field: "status", value: "pending" },
                { field: "expiresAt", value: new Date(), operator: "lt" },
                { field: "useCount", value: 0 }
              ],
              limit: batch
            });
            if (expired.length === 0) break;

            // Pre-created users go too, but only while inert: unverified
            // and holding no accounts.
            await deleteInertShells(
              ctx.context,
              expired.map((i) => i.preCreatedUserId).filter((v): v is string => !!v)
            );

            const ids = expired.map((i) => i.id);
            await ctx.context.adapter.deleteMany({
              model: "inviteUse",
              where: [{ field: "inviteId", value: ids, operator: "in" }]
            });
            await ctx.context.adapter.deleteMany({
              model: "invite",
              where: [{ field: "id", value: ids, operator: "in" }]
            });
            for (const invite of expired) {
              await opts.onInviteDeleted?.({ invite, admin: null });
            }
            deleted += expired.length;
            if (expired.length < batch) break;
          }
          return ctx.json({ deleted });
        }
      )
    }
  } satisfies BetterAuthPlugin;
};
