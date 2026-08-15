import type {
  AuthContext,
  BetterAuthOptions,
  BetterAuthPlugin,
  GenericEndpointContext,
  User
} from "better-auth";
import {
  APIError,
  createAuthEndpoint,
  createAuthMiddleware,
  createEmailVerificationToken,
  getSessionFromCtx,
  sessionMiddleware
} from "better-auth/api";
import { generateRandomString } from "better-auth/crypto";
import * as z from "zod";
import { defaultInviteRoles, type InviteManagementAction } from "./access";
import { buildSchema } from "./schema";
import {
  INVITE_ERROR_CODES,
  type BetterEnrollmentOptions,
  type Invite,
  type InviteAdditionalField,
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
  deriveStatus,
  isExpired,
  maskEmail,
  mergeRoles,
  reservedSeats,
  sha256Base64Url,
  splitRoles,
  storedTokenValue
} from "./utils";

export * from "./access";
export * from "./types";
export { roleGate } from "./utils";

const DEFAULT_EXPIRES_IN = 60 * 60 * 24 * 7;

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
};

/** The magic-link plugin config this plugin reads off the plugin object. */
type MagicLinkLikeOptions = {
  disableSignUp?: boolean;
  storeToken?:
    "plain" | "hashed" | { type: "custom-hasher"; hash: (token: string) => Promise<string> };
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
    passwordless: "auto" as const,
    passwordlessVerifyPaths: ["/magic-link/verify"],
    hashTokens: true,
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
    magicLinkOptions: null as MagicLinkLikeOptions | null
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

  async function findInviteByToken(
    ctx: GenericEndpointContext,
    token: string
  ): Promise<Invite | null> {
    const tokenHash = await storedTokenValue(token, opts.hashTokens);
    return await ctx.context.adapter.findOne<Invite>({
      model: "invite",
      where: [{ field: "tokenHash", value: tokenHash }]
    });
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
    const invites = await ctx.context.adapter.findMany<Invite>({
      model: "invite",
      where: [
        { field: "email", value: email.toLowerCase() },
        { field: "mode", value: "invite-only" }
      ]
    });
    return invites.some((i) => i.status !== "accepted" && i.preCreatedUserId);
  }

  function buildInviteUrl(ctx: GenericEndpointContext, token: string, type: InviteType): string {
    if (opts.buildInviteUrl) {
      return opts.buildInviteUrl({ token, type, mode: getMode() });
    }
    const origin = new URL(ctx.context.baseURL).origin;
    return `${origin}/invite?token=${encodeURIComponent(token)}`;
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

  async function assertUsable(invite: Invite | null): Promise<Invite> {
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
      await opts.onInviteExpired?.({ invite });
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

  async function recordUse(
    ctx: GenericEndpointContext,
    invite: Invite,
    userId: string,
    email: string
  ): Promise<void> {
    await ctx.context.adapter.create<Omit<InviteUse, "id">>({
      model: "inviteUse",
      data: {
        inviteId: invite.id,
        usedByUserId: userId,
        inviteeEmail: email.toLowerCase(),
        usedAt: new Date()
      }
    });
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

  // Deletes an invite plus its pre-created user while that user is inert.
  async function deleteInviteAndInertUser(
    ctx: GenericEndpointContext,
    invite: Invite
  ): Promise<void> {
    if (invite.preCreatedUserId) {
      const user = await ctx.context.internalAdapter.findUserById(invite.preCreatedUserId);
      if (user && !user.emailVerified) {
        const accounts = await ctx.context.internalAdapter.findAccounts(user.id);
        if (accounts.length === 0) {
          await ctx.context.adapter.deleteMany({
            model: "session",
            where: [{ field: "userId", value: user.id }]
          });
          await ctx.context.adapter.delete({
            model: "user",
            where: [{ field: "id", value: user.id }]
          });
        }
      }
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
    try {
      return await ctx.context.adapter.findMany<{
        role: string;
        permission: unknown;
      }>({
        model: "organizationRole",
        where: [{ field: "organizationId", value: organizationId }]
      });
    } catch {
      return [];
    }
  }

  async function memberHasInvitePermission(
    ctx: GenericEndpointContext,
    member: MemberRecord,
    action: "create" | "cancel"
  ): Promise<boolean> {
    const roles = splitRoles(member.role);
    for (const name of roles) {
      const configured = orgOpts?.roles?.[name];
      if (configured?.authorize) {
        try {
          if (configured.authorize({ invitation: [action] }).success) {
            return true;
          }
          continue;
        } catch {
          continue;
        }
      }
      // Org plugin defaults apply only when no roles record was given,
      // mirroring its hasPermission (options.roles || defaultRoles):
      // owner and admin hold invitation create/cancel.
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
        if (permission?.invitation?.includes(action)) return true;
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
      const name = body.organizationName?.trim();
      const slug = body.organizationSlug?.trim().toLowerCase();
      if (!name || !slug) {
        throw APIError.from("UNPROCESSABLE_ENTITY", INVITE_ERROR_CODES.ORG_INFO_REQUIRED);
      }
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
    pre: OrgPrecheck
  ): Promise<OrganizationRecord | null> {
    if (invite.kind === "app") return null;
    const now = new Date();

    if (invite.kind === "org-create") {
      if (!pre.orgInput) return null;
      let org: OrganizationRecord;
      try {
        org = await ctx.context.adapter.create<Omit<OrganizationRecord, "id">, OrganizationRecord>({
          model: "organization",
          data: {
            name: pre.orgInput.name,
            slug: pre.orgInput.slug,
            createdAt: now,
            seatLimit: invite.presetSeatLimit ?? null,
            disabledAt: null
          }
        });
      } catch {
        // Unique slug race between precheck and create.
        throw APIError.from("CONFLICT", INVITE_ERROR_CODES.ORG_SLUG_TAKEN);
      }
      const member = await ctx.context.adapter.create<Omit<MemberRecord, "id">, MemberRecord>({
        model: "member",
        data: {
          organizationId: org.id,
          userId: user.id,
          role: orgOpts?.orgCreateRole ?? "owner",
          createdAt: now
        }
      });
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
      await ctx.context.adapter.update({
        model: "member",
        where: [{ field: "id", value: existing.id }],
        update: { role: mergeRoles(existing.role, orgRole) }
      });
      return org;
    }
    const limit = await seatLimitFor(ctx, org);
    if (limit != null) {
      // Guards out-of-band member growth; invite flows are already
      // bounded by creation-time reservations + the atomic claim.
      const members = await ctx.context.adapter.count({
        model: "member",
        where: [{ field: "organizationId", value: org.id }]
      });
      if (members >= limit) {
        await orgOpts?.onSeatLimitReached?.({ organization: org, invite });
        throw APIError.from("UNPROCESSABLE_ENTITY", INVITE_ERROR_CODES.SEAT_LIMIT_REACHED);
      }
    }
    const member = await ctx.context.adapter.create<Omit<MemberRecord, "id">, MemberRecord>({
      model: "member",
      data: {
        organizationId: org.id,
        userId: user.id,
        role: orgRole,
        createdAt: now
      }
    });
    let teamAdded = false;
    if (invite.teamId) {
      // Team deleted since creation: join the org, skip the team.
      const team = await ctx.context.adapter
        .findOne<TeamRecord>({
          model: "team",
          where: [{ field: "id", value: invite.teamId }]
        })
        .catch(() => null);
      if (team && team.organizationId === org.id) {
        await ctx.context.adapter.create({
          model: "teamMember",
          data: {
            teamId: invite.teamId,
            userId: user.id,
            createdAt: now
          }
        });
        teamAdded = true;
      }
    }
    await orgOpts?.onOrgMemberAdded?.({
      organization: org,
      member,
      user,
      invite,
      teamAdded
    });
    return org;
  }

  async function banOrgMembers(
    ctx: GenericEndpointContext,
    organizationId: string
  ): Promise<number> {
    // Member rows are not deleted here, so offset paging is stable.
    let offset = 0;
    let banned = 0;
    for (;;) {
      const members = await ctx.context.adapter.findMany<MemberRecord>({
        model: "member",
        where: [{ field: "organizationId", value: organizationId }],
        limit: DB_PAGE,
        offset
      });
      if (members.length === 0) break;
      const ids = [...new Set(members.map((m) => m.userId))];
      await ctx.context.adapter.updateMany({
        model: "user",
        where: [{ field: "id", value: ids, operator: "in" }],
        update: {
          banned: true,
          banReason: "Organization suspended by administrator"
        }
      });
      await ctx.context.adapter.deleteMany({
        model: "session",
        where: [{ field: "userId", value: ids, operator: "in" }]
      });
      banned += ids.length;
      if (members.length < DB_PAGE) break;
      offset += DB_PAGE;
    }
    return banned;
  }

  async function requireOrgFeatures(): Promise<void> {
    if (!orgEnabled()) {
      throw APIError.from("UNPROCESSABLE_ENTITY", INVITE_ERROR_CODES.ORG_FEATURES_DISABLED);
    }
  }

  // ---------------------------------------------------------- redemption

  async function acceptCore(ctx: GenericEndpointContext, body: RedeemBody) {
    const invite = await assertUsable(await findInviteByToken(ctx, body.token));
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

    const pre = await assertOrgRedeemable(ctx, invite, body);

    if (invite.type === "private") {
      const target = invite.preCreatedUserId
        ? await ctx.context.internalAdapter.findUserById(invite.preCreatedUserId)
        : unwrapUser(
            (await ctx.context.internalAdapter.findUserByEmail(
              invite.email!
            )) as MaybeWithAccounts | null
          );
      if (!target) {
        throw APIError.from("NOT_FOUND", INVITE_ERROR_CODES.PRE_CREATED_USER_MISSING);
      }
      if (isBanned(target)) {
        throw APIError.from("FORBIDDEN", INVITE_ERROR_CODES.USER_BANNED);
      }
      // An invite issued to an already-established account is an activation
      // invite: merging into it requires the owner's session, not the token.
      // Without this, accept would overwrite the account's credential. Only
      // the invite's own pre-created shell is claimable through accept, so
      // a retry whose earlier attempt already wrote the credential still
      // passes, while accounts somebody owns are routed to sign-in.
      // emailVerified counts as established too: magic-link users own zero
      // account rows, so account count alone would misread them as shells.
      if (!invite.preCreatedUserId) {
        const targetAccounts = await ctx.context.internalAdapter.findAccounts(target.id);
        if (targetAccounts.length > 0 || target.emailVerified) {
          return ctx.json({
            action: "SIGN_IN_REQUIRED" as const,
            callbackURL: buildInviteUrl(ctx, body.token, invite.type)
          });
        }
      }
      const claimed = await claimUse(ctx, invite);
      if (!claimed) {
        throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.INVITE_ALREADY_USED);
      }
      let sessionCreated = false;
      try {
        if (body.password) {
          const hash = await ctx.context.password.hash(body.password);
          // Idempotent on retry: a prior attempt may have created the
          // credential account before failing later in the flow.
          const priorCredential = await ctx.context.adapter.findOne<{
            id: string;
          }>({
            model: "account",
            where: [
              { field: "userId", value: target.id },
              { field: "providerId", value: "credential" }
            ]
          });
          if (priorCredential) {
            await ctx.context.adapter.update({
              model: "account",
              where: [{ field: "id", value: priorCredential.id }],
              update: { password: hash }
            });
          } else {
            await ctx.context.internalAdapter.createAccount({
              userId: target.id,
              providerId: "credential",
              accountId: target.id,
              password: hash
            });
          }
        }
        const updated =
          (await ctx.context.internalAdapter.updateUser(target.id, {
            emailVerified: true,
            role,
            name,
            ...extraFields
          })) ?? target;
        const org = await applyOrgEffects(ctx, claimed, updated, pre);
        await recordUse(ctx, invite, target.id, target.email);
        // With a password, no session is created or mutated: the accepter
        // signs in through the app's own flow with the credentials they
        // just set. Passwordless has no credential to sign in with, and
        // the emailed token already proved the mailbox, so the accepter
        // is signed in directly instead of a second email round trip.
        let signedIn = false;
        if (!body.password) {
          const session = await ctx.context.internalAdapter.createSession(updated.id);
          sessionCreated = true;
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
        // A rolled-back invite must not leave a live session behind: the
        // shell had none before, so deleting all of its sessions is exact.
        if (sessionCreated) {
          try {
            await ctx.context.adapter.deleteMany({
              model: "session",
              where: [{ field: "userId", value: target.id }]
            });
          } catch (cleanupError) {
            ctx.context.logger.error(
              `better-enrollment: failed to remove session after failed redemption: ${String(cleanupError)}`
            );
          }
        }
        await rollbackClaim(ctx, invite);
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
    const existingUser = unwrapUser(
      (await ctx.context.internalAdapter.findUserByEmail(email)) as MaybeWithAccounts | null
    );
    if (existingUser) {
      // Do not confirm the account's existence to an unauthenticated
      // caller. Send them through sign-in; a signed-in redeem activates.
      return ctx.json({
        action: "SIGN_IN_REQUIRED" as const,
        callbackURL: buildInviteUrl(ctx, body.token, invite.type)
      });
    }
    const claimed = await claimUse(ctx, invite);
    if (!claimed) {
      throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.INVITE_USES_EXHAUSTED);
    }
    let createdUserId: string | null = null;
    try {
      const user = await ctx.context.internalAdapter.createUser({
        email,
        name,
        emailVerified: opts.autoVerifyPublicInviteEmail,
        role,
        ...extraFields
      });
      createdUserId = user.id;
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
      const org = await applyOrgEffects(ctx, claimed, user, pre);
      await recordUse(ctx, invite, user.id, email);
      await settlePublicStatus(ctx, claimed);
      await opts.onInviteAccepted?.({ invite: claimed, user });
      // No session is created or mutated, even passwordless: a public link
      // proves nothing about the mailbox, so the accepter signs in through
      // the app's own flow (credentials just set, or their first magic
      // link, which also verifies the email).
      return ctx.json({
        action: "ACCEPTED" as const,
        signedIn: false,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          emailVerified: user.emailVerified
        },
        organization: org ? { id: org.id, name: org.name, slug: org.slug } : null
      });
    } catch (e) {
      // No adapter-agnostic transaction exists, so compensate: the user
      // created in THIS attempt must not outlive a failed redemption, or
      // the email would be locked while the invite stays pending.
      if (createdUserId) {
        try {
          await ctx.context.adapter.deleteMany({
            model: "account",
            where: [{ field: "userId", value: createdUserId }]
          });
          await ctx.context.adapter.delete({
            model: "user",
            where: [{ field: "id", value: createdUserId }]
          });
        } catch (cleanupError) {
          ctx.context.logger.warn(
            `better-enrollment: failed to clean up user after failed redemption: ${String(cleanupError)}`
          );
        }
      }
      await rollbackClaim(ctx, invite);
      throw e;
    }
  }

  async function activateCore(ctx: GenericEndpointContext, body: RedeemBody) {
    const invite = await assertUsable(await findInviteByToken(ctx, body.token));

    const session = await getSessionFromCtx(ctx);
    if (!session) {
      // Stateless round-trip: the token in the URL is the only state.
      return ctx.json({
        action: "SIGN_IN_REQUIRED" as const,
        callbackURL: buildInviteUrl(ctx, body.token, invite.type)
      });
    }
    if (isBanned(session.user)) {
      throw APIError.from("FORBIDDEN", INVITE_ERROR_CODES.USER_BANNED);
    }

    if (invite.type === "private") {
      if (session.user.email.toLowerCase() !== invite.email?.toLowerCase()) {
        throw APIError.from("FORBIDDEN", INVITE_ERROR_CODES.EMAIL_MISMATCH);
      }
      if (!session.user.emailVerified) {
        throw APIError.from("FORBIDDEN", INVITE_ERROR_CODES.EMAIL_NOT_VERIFIED);
      }
    }

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
        role: (session.user as { role?: string | null }).role ?? null,
        organization: null
      });
    }

    const role = await resolveRole(invite);
    // Confirm-step fields validate before the claim, so bad input never
    // consumes a use.
    const extraFields = parseAdditionalFields(body, "CONFIRM");
    const pre = await assertOrgRedeemable(ctx, invite, body);
    const claimed = await claimUse(ctx, invite);
    if (!claimed) {
      throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.INVITE_USES_EXHAUSTED);
    }
    try {
      const current = (await ctx.context.internalAdapter.findUserById(
        session.user.id
      )) as BannableUser | null;
      const merged = mergeRoles(current?.role, role);
      const updated = await ctx.context.internalAdapter.updateUser(session.user.id, {
        role: merged,
        ...extraFields
      });
      const org = await applyOrgEffects(ctx, claimed, updated ?? session.user, pre);
      await recordUse(ctx, invite, session.user.id, session.user.email);
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
      await rollbackClaim(ctx, invite);
      throw e;
    }
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
    presetSeatLimit: z.number().int().positive().optional()
  });

  type CreateInviteBody = z.infer<typeof createInviteBody>;

  // A system actor is a trusted server-only caller with no session. It
  // carries its own attribution and skips the permission gates only; every
  // state invariant (seat limits, email locks, org checks) still runs.
  type InviteCreateActor =
    { type: "user" } | { type: "system"; inviterName: string; inviterEmail: string };

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
      if (body.presetSeatLimit != null) {
        throw APIError.from("UNPROCESSABLE_ENTITY", INVITE_ERROR_CODES.ORG_FIELDS_NOT_ALLOWED);
      }
      let memberRoles: string[] = [];
      if (actor.type === "user") {
        creator = await getAuthUser(ctx);
        const access = await requireOrgInviteAccess(ctx, creator, body.organizationId, "create");
        org = access.org;
        memberRoles = splitRoles(access.member.role);
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
      if (organizationRole === "owner") {
        // A system actor has no membership; the option is its only gate.
        const mayInviteOwner =
          actor.type === "system"
            ? !!orgOpts?.allowOwnerInvites
            : !!orgOpts?.allowOwnerInvites && memberRoles.includes("owner");
        if (!mayInviteOwner) {
          throw APIError.from("FORBIDDEN", INVITE_ERROR_CODES.OWNER_INVITES_NOT_ALLOWED);
        }
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
      }
      if (body.organizationId || body.organizationRole || body.teamId) {
        throw APIError.from("UNPROCESSABLE_ENTITY", INVITE_ERROR_CODES.ORG_FIELDS_NOT_ALLOWED);
      }
      if (kind === "org-create") {
        await requireOrgFeatures();
      } else if (body.presetSeatLimit != null) {
        throw APIError.from("UNPROCESSABLE_ENTITY", INVITE_ERROR_CODES.ORG_FIELDS_NOT_ALLOWED);
      }
    }

    // For a user actor, creator is always resolved by the gating above.
    const createdByUserId = creator?.id ?? null;
    const inviterName = actor.type === "system" ? actor.inviterName : (creator?.name ?? "");
    const inviterEmail = actor.type === "system" ? actor.inviterEmail : (creator?.email ?? "");

    let emailHasUser = false;
    if (email) {
      // Pending rows lock the email even past expiresAt.
      // The admin must delete stale invites first.
      // org-join checks within its own org only: the same email may
      // be invited to several orgs, and an org inviter must not be
      // able to probe for pending invites elsewhere in the app.
      const existing = await ctx.context.adapter.findOne<Invite>({
        model: "invite",
        where: [
          { field: "email", value: email },
          { field: "status", value: "pending" },
          ...(kind === "org-join" ? [{ field: "organizationId", value: org!.id }] : [])
        ]
      });
      if (existing) {
        throw APIError.from("CONFLICT", INVITE_ERROR_CODES.EMAIL_ALREADY_INVITED);
      }
      const existingUser = unwrapUser(
        (await ctx.context.internalAdapter.findUserByEmail(email)) as MaybeWithAccounts | null
      );
      if (existingUser && mode === "invite-only") {
        // An org-bound invite to an existing account is an
        // activation invite: no pre-created user, redeem merges
        // the membership onto the signed-in user. App-kind
        // invites grant nothing an existing user lacks.
        if (kind === "app") {
          throw APIError.from("CONFLICT", INVITE_ERROR_CODES.USER_ALREADY_EXISTS);
        }
        emailHasUser = true;
      }
    }

    const expiresIn = body.expiresIn ?? (type === "public" ? opts.publicExpiresIn : opts.expiresIn);
    const expiresAt = expiresIn == null ? null : new Date(Date.now() + expiresIn * 1000);

    let preCreatedUserId: string | null = null;
    if (mode === "invite-only" && type === "private" && email && !emailHasUser) {
      try {
        const created = await ctx.context.internalAdapter.createUser({
          email,
          name: body.name ?? "",
          emailVerified: false,
          role
        });
        preCreatedUserId = created.id;
      } catch {
        // Unique-email race: a concurrent create pre-created this
        // user between our conflict check and now.
        throw APIError.from("CONFLICT", INVITE_ERROR_CODES.EMAIL_ALREADY_INVITED);
      }
    }

    const token = generateRandomString(32);
    const tokenHash = await storedTokenValue(token, opts.hashTokens);
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
          preCreatedUserId,
          createdByUserId,
          inviterName,
          inviterEmail,
          expiresAt,
          maxUses,
          useCount: 0,
          revokedAt: null,
          revokedByUserId: null,
          createdAt: now,
          updatedAt: now
        }
      });

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
            organizationName: org?.name ?? null,
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
            organizationName: org?.name ?? null,
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
      if (preCreatedUserId) {
        await ctx.context.adapter
          .delete({
            model: "user",
            where: [{ field: "id", value: preCreatedUserId }]
          })
          .catch(() => {});
      }
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
          `better-enrollment: mode "${state.mode}" auto-detected (${describePaths(paths)}). Sign-up paths from other plugins are not detectable; set mode explicitly if you use any.`
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

      const orgPlugin = ctx.options.plugins?.find((p) => p.id === "organization");
      state.orgPluginPresent = !!orgPlugin;
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

      return {
        options: {
          databaseHooks: {
            account: {
              create: {
                // Blocks OAuth linking while an invite-only invite is pending.
                before: async (account, context) => {
                  if (state.mode !== "invite-only") return;
                  if (account.providerId === "credential") return;
                  if (!context) return;
                  const user = await context.context.internalAdapter.findUserById(account.userId);
                  if (!user || user.emailVerified) return;
                  // Same scope as the password-reset guard: any non-accepted
                  // invite. A cancelled invite leaves an inert pre-created
                  // user behind; linking must stay blocked for it too.
                  const invites = await context.context.adapter.findMany<Invite>({
                    model: "invite",
                    where: [
                      { field: "email", value: user.email.toLowerCase() },
                      { field: "mode", value: "invite-only" }
                    ]
                  });
                  if (invites.some((i) => i.status !== "accepted")) {
                    throw APIError.from("FORBIDDEN", INVITE_ERROR_CODES.INVITATION_REQUIRED);
                  }
                }
              }
            },
            session: {
              create: {
                // Backstop behind the /magic-link/verify request guard:
                // catches passwordless verify flows the guard cannot
                // resolve (custom paths, storeToken drift). Path-gated so
                // ordinary sign-ins pay zero queries.
                before: async (session, context) => {
                  if (state.mode !== "invite-only") return;
                  const path = context?.path;
                  if (!path || !opts.passwordlessVerifyPaths.includes(path)) return;
                  const userId = (session as { userId: string }).userId;
                  const invites = await context.context.adapter.findMany<Invite>({
                    model: "invite",
                    where: [
                      { field: "preCreatedUserId", value: userId },
                      { field: "mode", value: "invite-only" }
                    ]
                  });
                  if (invites.some((i) => i.status !== "accepted")) {
                    // Verify already flipped emailVerified before this
                    // hook; undo it so the shell stays inert and
                    // deletable, then refuse the session.
                    await context.context.adapter.update({
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
            const email = (ctx.body as { email?: string } | undefined)?.email?.toLowerCase().trim();
            if (!email) return;
            const invites = await ctx.context.adapter.findMany<Invite>({
              model: "invite",
              where: [
                { field: "email", value: email },
                { field: "mode", value: "invite-only" }
              ]
            });
            if (!invites.some((i) => i.status !== "accepted")) return;
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
          // disableSignUp, and a pre-created invite shell exists. Without
          // this guard the invitee could skip the invite flow entirely.
          // The token is resolved to its email without consuming it, using
          // the same storeToken transform the magic-link plugin configured.
          matcher: (ctx) => ctx.path === "/magic-link/verify",
          handler: createAuthMiddleware(async (ctx) => {
            if (state.mode !== "invite-only" || !state.magicLinkOptions) return;
            const token = (ctx.query as { token?: string } | undefined)?.token;
            if (!token) return;
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
            let email: string | undefined;
            try {
              email = (JSON.parse(verification.value) as { email?: string }).email;
            } catch {
              return;
            }
            if (!email) return;
            // Only pre-created shells are locked; activation invites
            // (existing accounts) must not break their owner's sign-in.
            if (await hasPendingShellInvite(ctx, email)) {
              throw APIError.from("FORBIDDEN", INVITE_ERROR_CODES.INVITATION_REQUIRED);
            }
          })
        },
        {
          // Sending a magic link to a pre-created shell would deliver a
          // link the verify guard rejects. Reply with the endpoint's exact
          // success body without sending, mirroring the password-reset
          // guard: no dead link in the inbox, no invite oracle.
          matcher: (ctx) => ctx.path === "/sign-in/magic-link",
          handler: createAuthMiddleware(async (ctx) => {
            if (state.mode !== "invite-only" || !state.magicLinkOptions) return;
            const email = (ctx.body as { email?: string } | undefined)?.email?.toLowerCase().trim();
            if (!email) return;
            if (await hasPendingShellInvite(ctx, email)) {
              return new Response(JSON.stringify({ status: true }), {
                status: 200,
                headers: { "content-type": "application/json" }
              });
            }
          })
        },
        {
          // A disabled org rejects org plugin traffic targeting it,
          // whether addressed by id, slug, invitationId, or implicitly
          // through the session's active organization.
          matcher: (ctx) => !!ctx.path?.startsWith("/organization"),
          handler: createAuthMiddleware(async (ctx) => {
            if (!orgEnabled()) return;
            const str = (v: unknown) => (typeof v === "string" ? v : undefined);
            const body = ctx.body as Record<string, unknown> | undefined;
            const query = ctx.query as Record<string, unknown> | undefined;

            let orgId = str(body?.organizationId) ?? str(query?.organizationId);
            const slug = str(body?.organizationSlug) ?? str(query?.organizationSlug);
            if (!orgId && slug) {
              const bySlug = await ctx.context.adapter
                .findOne<OrganizationRecord>({
                  model: "organization",
                  where: [{ field: "slug", value: slug }]
                })
                .catch(() => null);
              orgId = bySlug?.id;
            }
            const invitationId = str(body?.invitationId) ?? str(query?.invitationId);
            if (!orgId && invitationId) {
              const invitation = await ctx.context.adapter
                .findOne<{ organizationId?: string }>({
                  model: "invitation",
                  where: [{ field: "id", value: invitationId }]
                })
                .catch(() => null);
              orgId = invitation?.organizationId;
            }
            if (!orgId) {
              // No explicit target: most org endpoints then act on the
              // active organization. Endpoints that never do are exempt,
              // or a disabled active org would lock users out of
              // listing, creating, and switching orgs.
              const implicit = ![
                "/organization/list",
                "/organization/create",
                "/organization/set-active"
              ].includes(ctx.path ?? "");
              if (!implicit) return;
              const session = await getSessionFromCtx(ctx).catch(() => null);
              orgId = str(
                (session?.session as { activeOrganizationId?: unknown } | undefined)
                  ?.activeOrganizationId
              );
            }
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
          // Admin plugin ban: a banned inviter's pending invites die.
          matcher: (ctx) => ctx.path === "/admin/ban-user",
          handler: createAuthMiddleware(async (ctx) => {
            if (orgOpts?.revokeInvitesOnInviterBan === false) return;
            if (ctx.context.returned instanceof APIError) return;
            const userId = (ctx.body as { userId?: string } | undefined)?.userId;
            if (!userId) return;
            await ctx.context.adapter.updateMany({
              model: "invite",
              where: [
                { field: "createdByUserId", value: userId },
                { field: "status", value: "pending" }
              ],
              update: {
                status: "cancelled",
                revokedAt: new Date(),
                updatedAt: new Date()
              }
            });
          })
        },
        {
          // Admin plugin removeUser: pending invites go with the inviter;
          // accepted invites survive via denormalized inviter fields.
          matcher: (ctx) => ctx.path === "/admin/remove-user",
          handler: createAuthMiddleware(async (ctx) => {
            if (ctx.context.returned instanceof APIError) return;
            const userId = (ctx.body as { userId?: string } | undefined)?.userId;
            if (!userId) return;
            const pending = await ctx.context.adapter.findMany<Invite>({
              model: "invite",
              where: [
                { field: "createdByUserId", value: userId },
                { field: "status", value: "pending" }
              ]
            });
            for (const invite of pending) {
              await deleteInviteAndInertUser(ctx, invite);
            }
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
        pathMatcher: (path) => path === "/invite/get" || path === "/invite/check-slug",
        window: 60,
        max: 10
      }
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
                email: z.string().max(200).optional()
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
          return await createInviteCore(ctx, ctx.body, {
            type: "system",
            inviterName,
            inviterEmail
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
          const invite = await ctx.context.adapter.findOne<Invite>({
            model: "invite",
            where: [{ field: "id", value: ctx.body.inviteId }]
          });
          if (!invite) {
            throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.INVITE_NOT_FOUND);
          }
          if (invite.status === "cancelled") {
            throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.INVITE_REVOKED);
          }
          if (invite.status === "accepted") {
            throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.INVITE_ALREADY_USED);
          }
          // App admin is a moderation backstop; org members need
          // invitation:create in the invite's org, mirroring creation.
          let org: OrganizationRecord | null = null;
          if (!(await isInviteAdmin(user, "resend"))) {
            if (!orgEnabled() || !invite.organizationId) {
              throw APIError.from("FORBIDDEN", INVITE_ERROR_CODES.NOT_ALLOWED_TO_MANAGE_INVITES);
            }
            const access = await requireOrgInviteAccess(ctx, user, invite.organizationId, "create");
            org = access.org;
          } else if (invite.organizationId) {
            org = await findOrg(ctx, invite.organizationId);
          }
          if (org?.disabledAt) {
            throw APIError.from("FORBIDDEN", INVITE_ERROR_CODES.ORG_DISABLED);
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
          const tokenHash = await storedTokenValue(token, opts.hashTokens);
          const expiresIn =
            ctx.body.expiresIn ??
            (invite.type === "public" ? opts.publicExpiresIn : opts.expiresIn);
          const expiresAt = expiresIn == null ? null : new Date(Date.now() + expiresIn * 1000);
          // CAS on pending: swapping the token hash kills the old link,
          // and a parallel accept that already consumed the invite wins.
          const updated = await ctx.context.adapter.update<Invite>({
            model: "invite",
            where: [
              { field: "id", value: invite.id },
              { field: "status", value: "pending" }
            ],
            update: { tokenHash, expiresAt, updatedAt: new Date() }
          });
          if (!updated) {
            throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.INVITE_ALREADY_USED);
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
                organizationName: org?.name ?? null,
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
                organizationName: org?.name ?? null,
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
          // Invites held by existing accounts redeem as activations: a
          // private invite without a pre-created user was issued to an
          // existing account, and a signed-in user redeeming a public
          // invite already has one.
          const invite = await findInviteByToken(ctx, ctx.body.token);
          if (invite?.type === "private" && !invite.preCreatedUserId) {
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
        async (ctx) => {
          const invite = await findInviteByToken(ctx, ctx.query.token);
          if (!invite) {
            throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.INVITE_NOT_FOUND);
          }
          const status = deriveStatus(invite);
          if (status === "expired") {
            await opts.onInviteExpired?.({ invite });
          }

          let organizationName: string | null = null;
          if (invite.kind === "org-join" && invite.organizationId && orgEnabled()) {
            const org = await findOrg(ctx, invite.organizationId);
            organizationName = org?.name ?? null;
          }

          // nextAction drives a single invite page for every kind.
          const session = await getSessionFromCtx(ctx).catch(() => null);
          let nextAction: "SIGN_UP" | "SIGN_IN" | "CONFIRM" | null = null;
          if (status === "pending") {
            if (getMode() === "invite-only") {
              // Activation invites (existing accounts) sign in, not up.
              const activation =
                (invite.type === "private" && !invite.preCreatedUserId) ||
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
          if (invite.kind === "org-create" && nextAction) {
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
            expiresAt: invite.expiresAt,
            maxUses: invite.maxUses,
            useCount: invite.useCount,
            usesRemaining:
              invite.maxUses == null ? null : Math.max(0, invite.maxUses - invite.useCount)
          });
        }
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
        async (ctx) => {
          const invite = await findInviteByToken(ctx, ctx.query.token);
          if (!invite || invite.kind !== "org-create" || deriveStatus(invite) !== "pending") {
            throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.INVITE_NOT_FOUND);
          }
          const existing = await ctx.context.adapter.findOne<OrganizationRecord>({
            model: "organization",
            where: [
              {
                field: "slug",
                value: ctx.query.slug.trim().toLowerCase()
              }
            ]
          });
          if (existing) {
            throw APIError.from("CONFLICT", INVITE_ERROR_CODES.ORG_SLUG_TAKEN);
          }
          return ctx.json({ status: true });
        }
      ),

      listInvites: createAuthEndpoint(
        "/invite/list",
        {
          method: "GET",
          use: [sessionMiddleware],
          query: z.object({
            status: z.enum(["pending", "accepted", "cancelled", "expired"]).optional(),
            type: z.enum(["private", "public"]).optional(),
            organizationId: z.string().optional(),
            page: z.coerce.number().int().positive().default(1),
            limit: z.coerce.number().int().positive().max(100).default(20)
          })
        },
        async (ctx) => {
          const user = await getAuthUser(ctx);
          const admin = await isInviteAdmin(user, "list");
          const now = new Date();
          const where = [
            ...(ctx.query.type ? [{ field: "type", value: ctx.query.type }] : []),
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
          const [invites, total] = await Promise.all([
            ctx.context.adapter.findMany<Invite>({
              model: "invite",
              where,
              limit: ctx.query.limit,
              offset: (ctx.query.page - 1) * ctx.query.limit,
              sortBy: { field: "createdAt", direction: "desc" }
            }),
            ctx.context.adapter.count({ model: "invite", where })
          ]);
          const uses = invites.length
            ? await ctx.context.adapter.findMany<InviteUse>({
                model: "inviteUse",
                where: [
                  {
                    field: "inviteId",
                    value: invites.map((i) => i.id),
                    operator: "in"
                  }
                ]
              })
            : [];
          const byInvite = new Map<string, InviteUse[]>();
          for (const u of uses) {
            const list = byInvite.get(u.inviteId) ?? [];
            list.push(u);
            byInvite.set(u.inviteId, list);
          }
          return ctx.json({
            invites: invites.map((i) => {
              const { tokenHash: _tokenHash, ...rest } = i;
              return {
                ...rest,
                status: deriveStatus(i, now),
                uses: byInvite.get(i.id) ?? []
              };
            }),
            total,
            page: ctx.query.page,
            limit: ctx.query.limit
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
          const invite = await ctx.context.adapter.findOne<Invite>({
            model: "invite",
            where: [{ field: "id", value: ctx.body.inviteId }]
          });
          if (!invite) {
            throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.INVITE_NOT_FOUND);
          }
          // App admin is a moderation backstop; org members need
          // invitation:cancel in the invite's org.
          if (!(await isInviteAdmin(user, "cancel"))) {
            if (!orgEnabled() || !invite.organizationId) {
              throw APIError.from("FORBIDDEN", INVITE_ERROR_CODES.NOT_ALLOWED_TO_MANAGE_INVITES);
            }
            await requireOrgInviteAccess(ctx, user, invite.organizationId, "cancel");
          }
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
          const invite = await ctx.context.adapter.findOne<Invite>({
            model: "invite",
            where: [{ field: "id", value: ctx.body.inviteId }]
          });
          if (!invite) {
            throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.INVITE_NOT_FOUND);
          }
          if (!(await isInviteAdmin(user, "delete"))) {
            if (!orgEnabled() || !invite.organizationId) {
              throw APIError.from("FORBIDDEN", INVITE_ERROR_CODES.NOT_ALLOWED_TO_MANAGE_INVITES);
            }
            await requireOrgInviteAccess(ctx, user, invite.organizationId, "cancel");
          }
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
          await requireInviteAdmin(ctx, "manage-orgs");
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
          const bannedMembers = ctx.body.banMembers ? await banOrgMembers(ctx, org.id) : 0;
          await orgOpts?.onOrgDisabled?.({
            organization: { ...org, disabledAt },
            bannedMembers
          });
          return ctx.json({ disabled: true, bannedMembers });
        }
      ),

      enableOrg: createAuthEndpoint(
        "/invite/org/enable",
        {
          method: "POST",
          use: [sessionMiddleware],
          body: z.object({
            organizationId: z.string().min(1)
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
          await orgOpts?.onOrgEnabled?.({
            organization: { ...org, disabledAt: null }
          });
          return ctx.json({ enabled: true });
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
          await requireInviteAdmin(ctx, "manage-orgs");
          await requireOrgFeatures();
          const org = await findOrg(ctx, ctx.body.organizationId);
          if (!org) {
            throw APIError.from("BAD_REQUEST", INVITE_ERROR_CODES.ORG_NOT_FOUND);
          }
          // Ban first while member rows still exist.
          const bannedMembers = ctx.body.banMembers ? await banOrgMembers(ctx, org.id) : 0;

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
          }
          // The org plugin's own invitation table, when present.
          await ctx.context.adapter
            .deleteMany({
              model: "invitation",
              where: [{ field: "organizationId", value: org.id }]
            })
            .catch(() => {});
          await ctx.context.adapter
            .updateMany({
              model: "session",
              where: [{ field: "activeOrganizationId", value: org.id }],
              update: { activeOrganizationId: null }
            })
            .catch(() => {});
          await ctx.context.adapter.delete({
            model: "organization",
            where: [{ field: "id", value: org.id }]
          });
          await orgOpts?.onOrgDeleted?.({ organization: org, bannedMembers });
          return ctx.json({ deleted: true, bannedMembers });
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
            const shellIds = expired.map((i) => i.preCreatedUserId).filter((v): v is string => !!v);
            if (shellIds.length > 0) {
              const users = await ctx.context.adapter.findMany<{
                id: string;
                emailVerified: boolean;
              }>({
                model: "user",
                where: [{ field: "id", value: shellIds, operator: "in" }],
                limit: shellIds.length
              });
              const unverified = users.filter((u) => !u.emailVerified).map((u) => u.id);
              if (unverified.length > 0) {
                const accounts = await ctx.context.adapter.findMany<{ userId: string }>({
                  model: "account",
                  where: [{ field: "userId", value: unverified, operator: "in" }],
                  limit: 100000
                });
                const linked = new Set(accounts.map((a) => a.userId));
                const inert = unverified.filter((id) => !linked.has(id));
                if (inert.length > 0) {
                  await ctx.context.adapter.deleteMany({
                    model: "session",
                    where: [{ field: "userId", value: inert, operator: "in" }]
                  });
                  await ctx.context.adapter.deleteMany({
                    model: "user",
                    where: [{ field: "id", value: inert, operator: "in" }]
                  });
                }
              }
            }

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
