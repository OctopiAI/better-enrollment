import type { User } from "better-auth";
import { VALIDATION_ERRORS } from "./validation";

export type InviteMode = "invite-only" | "open";
export type InviteType = "private" | "public";
export type InviteKind = "app" | "org-join" | "org-create";
/** Stored statuses. "expired" is never stored: it is derived from expiresAt. */
export type StoredInviteStatus = "pending" | "accepted" | "cancelled";
export type InviteStatus = StoredInviteStatus | "expired";

export interface Invite {
  id: string;
  type: InviteType;
  kind: InviteKind;
  email: string | null;
  name: string | null;
  role: string;
  tokenHash: string;
  status: StoredInviteStatus;
  mode: InviteMode;
  organizationId: string | null;
  organizationRole: string | null;
  teamId: string | null;
  presetSeatLimit: number | null;
  /** org-create: the founded org's name, fixed by the inviter. */
  presetOrganizationName: string | null;
  /** org-create: the founded org's slug, suffixed when taken at redemption. */
  presetOrganizationSlug: string | null;
  preCreatedUserId: string | null;
  createdByUserId: string | null;
  inviterName: string;
  inviterEmail: string;
  expiresAt: Date | null;
  maxUses: number | null;
  useCount: number;
  revokedAt: Date | null;
  revokedByUserId: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface InviteUse {
  id: string;
  inviteId: string;
  usedByUserId: string;
  inviteeEmail: string;
  usedAt: Date;
}

/** Organization plugin row shapes this plugin reads and writes. */
export interface OrganizationRecord {
  id: string;
  name: string;
  slug: string | null;
  logo?: string | null;
  metadata?: string | null;
  createdAt?: Date;
  seatLimit?: number | null;
  disabledAt?: Date | null;
}

export interface MemberRecord {
  id: string;
  organizationId: string;
  userId: string;
  role: string;
  createdAt?: Date;
}

export interface TeamRecord {
  id: string;
  name: string;
  organizationId: string;
}

/**
 * Structural Standard Schema shape (https://standardschema.dev). Zod v4
 * schemas satisfy it, so validators can be plain zod: `z.string().min(2)`.
 */
export interface StandardSchemaLike {
  "~standard": {
    validate: (
      value: unknown
    ) =>
      | { value: unknown; issues?: undefined }
      | { issues: ReadonlyArray<{ message?: string }> }
      | Promise<unknown>;
  };
}

export type InviteAdditionalFieldType = "string" | "number" | "boolean" | "date";

/**
 * The two nextActions that render a form and may carry additional
 * fields. SIGN_IN and the terminal state collect nothing.
 */
export type InviteFieldAction = "SIGN_UP" | "CONFIRM";

/**
 * One extra field collected at redemption. Mirrors Better Auth's
 * additionalFields attribute shape: type, required (default true),
 * defaultValue, and an optional standard-schema input validator.
 */
export interface InviteAdditionalField {
  type: InviteAdditionalFieldType;
  /**
   * Which redemption steps collect this field. "SIGN_UP" is the
   * account-creating accept flow; "CONFIRM" is a signed-in activation.
   * Default ["SIGN_UP"]. The list is exact, never additive: ["CONFIRM"]
   * means confirm only; name both steps to collect on both forms.
   */
  actions?: InviteFieldAction[];
  /**
   * Whether redemption must provide a value. Default true, matching
   * Better Auth. A field with a defaultValue never fails this check.
   */
  required?: boolean;
  /** Applied when redemption provides no value. */
  defaultValue?: string | number | boolean | Date | (() => string | number | boolean | Date);
  /** Validated against the provided value; synchronous schemas only. */
  validator?: { input?: StandardSchemaLike };
}

/**
 * Structural type for roles built with createAccessControl().newRole().
 * Declared with method syntax so concrete Role objects, whose authorize
 * parameter is a narrower statement-typed request, remain assignable.
 */
export interface OrgRoleLike {
  authorize(
    permissions: Record<string, string[]>,
    connector?: "OR" | "AND"
  ): { success: boolean; error?: string };
}

export interface PrivateInvitationEmailData {
  email: string;
  name: string | null;
  role: string;
  kind: InviteKind;
  mode: InviteMode;
  url: string;
  token: string;
  inviterName: string;
  inviterEmail: string;
  organizationName: string | null;
  /** The invite row this email is for. */
  inviteId: string;
  /** Set for org-join invites; null for app and org-create. */
  organizationId: string | null;
  /** The org role an org-join invite grants. */
  organizationRole: string | null;
  /** The team an org-join invite adds the member to, if any. */
  teamId: string | null;
  expiresAt: Date | null;
}

export interface PublicInvitationData {
  role: string;
  kind: InviteKind;
  mode: InviteMode;
  url: string;
  token: string;
  inviterName: string;
  inviterEmail: string;
  organizationName: string | null;
  /** The invite row this email is for. */
  inviteId: string;
  /** Set for org-join invites; null for app and org-create. */
  organizationId: string | null;
  /** The org role an org-join invite grants. */
  organizationRole: string | null;
  /** The team an org-join invite adds the member to, if any. */
  teamId: string | null;
  maxUses: number | null;
  expiresAt: Date | null;
}

export interface BetterEnrollmentOrgOptions {
  /** Kept for parity with the org plugin config; not read directly. */
  ac?: unknown;
  /**
   * The same roles record passed to the org plugin. When omitted, the org
   * plugin defaults apply: owner and admin hold invitation create/cancel.
   * When provided, it fully replaces those defaults, mirroring the org
   * plugin's own permission resolution.
   */
  roles?: Record<string, OrgRoleLike>;
  /** Overrides the invitation:create permission check for org-join creation. */
  canCreateOrgInvites?: (
    member: MemberRecord,
    org: OrganizationRecord
  ) => Promise<boolean> | boolean;
  /**
   * Org roles each member role may grant through org-join invites without
   * holding member:update, e.g. `{ recruiter: ["member", "viewer"] }`.
   * defaultOrganizationRole is always grantable. Granting any other role
   * requires member:update in the org, the permission the org plugin
   * itself requires to change a member's role.
   *
   * Only list roles that can do no more than the holder: the holder can
   * invite a second address it controls. Checked at startup by the
   * top-level grantableRolesCheck.
   */
  grantableRoles?: Record<string, string[]>;
  /** Overrides the org role ceiling. Receives the requested org role string. */
  canGrantOrgRole?: (
    member: MemberRecord,
    org: OrganizationRecord,
    role: string
  ) => Promise<boolean> | boolean;
  /**
   * Allow org-join invites that grant the org plugin's creatorRole ("owner"
   * unless configured), for members holding it. Default false.
   */
  allowOwnerInvites?: boolean;
  /**
   * Org roles a public org-join invite may grant, like the top-level
   * publicInviteRoles. Checked at create, resend and redemption. Default:
   * any role.
   */
  publicInviteRoles?: string[];
  /**
   * Apply the seat limit to the org plugin's own /organization/invite-member
   * and /organization/accept-invitation, which would otherwise add members
   * past it. Default true; only orgs with a seat limit are affected. The
   * server-only addMember is never checked (trusted server code). These
   * checks cannot be atomic, since the org plugin does the writing.
   */
  enforceSeatLimitOnOrgPlugin?: boolean;
  /**
   * Run the org plugin's organizationHooks.beforeAddMember / afterAddMember
   * when a redemption adds a member, and honor a numeric
   * teams.maximumMembersPerTeam (a full team is skipped like a deleted
   * one). Default false: these hooks were never called for invite
   * redemptions, so turning them on may duplicate work you already do in
   * onOrgMemberAdded.
   */
  runOrgPluginHooks?: boolean;
  /**
   * Also enforce the org plugin's membershipLimit at redemption, exactly as
   * the org plugin does (its default is 100 members). Default false.
   */
  respectMembershipLimit?: boolean;
  /** Org role granted when an org-join invite does not name one. Default "member". */
  defaultOrganizationRole?: string;
  /**
   * Org role granted to the founder via an org-create invite. Default: the
   * org plugin's creatorRole ("owner" unless configured).
   */
  orgCreateRole?: string;
  /** Seat limit applied when the organization row has none. */
  defaultSeatLimit?: number;
  /** Highest-priority seat limit source, e.g. read a subscription tier. */
  resolveSeatLimit?: (org: OrganizationRecord) => Promise<number | null> | number | null;
  /** Revoke an inviter's pending invites when the admin plugin bans them. Default true. */
  revokeInvitesOnInviterBan?: boolean;

  /**
   * Runs when an org-create redemption is about to found its org. The
   * returned fields are added to the organization row (your org plugin
   * additionalFields); name, slug, createdAt, seatLimit and disabledAt
   * always come from the invite flow. Throw an APIError to refuse the
   * redemption with that error.
   */
  beforeOrgCreate?: (data: {
    invite: Invite;
    user: User;
    organization: { name: string; slug: string };
  }) => Promise<Record<string, unknown> | void> | Record<string, unknown> | void;

  onOrgMemberAdded?: (data: {
    organization: OrganizationRecord;
    member: MemberRecord;
    user: User;
    invite: Invite;
    teamAdded: boolean;
  }) => Promise<void> | void;
  onSeatLimitReached?: (data: {
    organization: OrganizationRecord;
    invite?: Invite;
  }) => Promise<void> | void;
  /** skippedMembers: platform staff (the caller, invite admins) that banMembers left alone. */
  onOrgDisabled?: (data: {
    organization: OrganizationRecord;
    bannedMembers: number;
    skippedMembers: number;
  }) => Promise<void> | void;
  /** unbannedMembers: bans lifted by enableOrg's unbanMembers. */
  onOrgEnabled?: (data: {
    organization: OrganizationRecord;
    unbannedMembers: number;
  }) => Promise<void> | void;
  onOrgDeleted?: (data: {
    organization: OrganizationRecord;
    bannedMembers: number;
    skippedMembers: number;
  }) => Promise<void> | void;
}

export interface BetterEnrollmentOptions {
  /**
   * "invite-only": the app is closed; invites are the only way in.
   * "open": self sign-up is enabled; invites merge roles.
   * "auto" (default): detect from sign-up config; mixed configs throw.
   */
  mode?: InviteMode | "auto";
  /**
   * With mode "invite-only", downgrade the open-sign-up init throw to a
   * warning. The invite guarantee then becomes per-email, not app-wide.
   */
  allowOpenSignup?: boolean;

  /** Called for private (email-bound) invites. Implementation is yours. */
  sendPrivateInvitation?: (
    data: PrivateInvitationEmailData,
    request?: Request
  ) => Promise<void> | void;
  /** Called for public (shareable) invites, e.g. to notify or log. */
  sendPublicInvitation?: (data: PublicInvitationData, request?: Request) => Promise<void> | void;

  /** Roles that may be granted through invites. Omit to skip validation. */
  validRoles?: string[];
  /** Used when an invite's role was removed before acceptance. */
  fallbackRole?: string;
  /** Role used when the admin does not specify one. Default "user". */
  defaultRole?: string;

  /** Private invite lifetime in seconds. Default 7 days. */
  expiresIn?: number;
  /** Public invite lifetime in seconds. null = never expires. Default 7 days. */
  publicExpiresIn?: number | null;
  /**
   * Upper bound, in seconds, on an `expiresIn` sent to create or resend.
   * Larger values get UNPROCESSABLE_ENTITY. null = no cap. Default 365 days.
   * Your own `expiresIn` / `publicExpiresIn` options are not capped.
   */
  maxExpiresIn?: number | null;
  /**
   * Upper bound on a public invite's `maxUses`. null = no cap.
   * Default 10000.
   */
  maxPublicUses?: number | null;
  /**
   * Minimum seconds between two sends of the same private invite (create
   * counts as the first). A resend sooner gets 429 RESEND_TOO_SOON.
   * 0 = off. Default 60.
   */
  resendCooldown?: number;

  /**
   * Passwordless redemption for magic-link apps. "auto" (default) turns it
   * on when the magic-link plugin is registered and emailAndPassword is
   * not enabled. When active, accept works without a password: private
   * invites also sign the accepter in (the emailed token proves the
   * mailbox); public accepters sign in with their first magic link.
   */
  passwordless?: boolean | "auto";
  /**
   * @deprecated Ignored. Pre-created invite shells are now refused a
   * session on every path, so no per-path list is needed.
   */
  passwordlessVerifyPaths?: string[];

  /**
   * Hash invite tokens at rest with SHA-256 (default true). Set false to
   * store raw tokens (not recommended; a DB leak then exposes live links).
   */
  hashTokens?: boolean;
  /**
   * Invite-only mode, public invites: mark the signup's email verified
   * immediately. Default false so a leaked link cannot claim someone
   * else's address as verified.
   */
  autoVerifyPublicInviteEmail?: boolean;
  /** Return the full invitee email from GET /invite/get. Default: masked. */
  exposeEmailOnGet?: boolean;

  /**
   * The access controller from your shared permissions file, the same one
   * passed to the admin plugin. Accepted for config parity; the permission
   * checks read `roles`. Setting it (without `roles`) switches the gate to
   * the built-in defaultInviteRoles.
   */
  ac?: unknown;
  /**
   * The same roles record passed to the admin plugin, built from a
   * statement object that spreads in inviteStatements. When set, it is the
   * highest-priority invite gate: a role must grant `invite: [<action>]`
   * (create, resend, list, cancel, delete, manage-orgs) for the matching
   * endpoints. adminUserIds still bypasses, mirroring the admin plugin;
   * canManageInvites and adminRoles are then ignored.
   */
  roles?: { [role: string]: OrgRoleLike | undefined };
  /**
   * The statement resource the AC check authorizes against. Default
   * "invite" (the shape of the exported inviteStatements). Point it at
   * your own resource ("enrollment", "invitations", ...) if your AC file
   * already names one; the action verbs stay create, resend, list,
   * cancel, delete, manage-orgs. Only meaningful together with `roles`:
   * the built-in defaultInviteRoles grant under "invite".
   */
  permissionResource?: string;
  /** Roles allowed to manage invites when `roles` is not set. Default ["admin"]. */
  adminRoles?: string[];
  /** User ids that may always manage invites. */
  adminUserIds?: string[];
  /**
   * Custom gate. When set (and `roles` is not), replaces
   * adminRoles/adminUserIds entirely.
   */
  canManageInvites?: (user: User & { role?: string | null }) => Promise<boolean> | boolean;
  /**
   * App roles each role may grant through invites without holding the
   * admin plugin's user:set-role, e.g. `{ support: ["user", "partner"] }`.
   * defaultRole is always grantable. Any other role requires user:set-role
   * (read from the admin plugin's own config), adminUserIds, or, without
   * the admin plugin, an adminRoles role. Applies to create and to resend
   * of public invites, which hands out the link.
   *
   * Only list roles that can do no more than the holder: the holder can
   * invite a second address it controls, so a grantable role is
   * effectively available to the holder. Holders can never redeem their
   * own grantable-only invites. See grantableRolesCheck.
   */
  grantableRoles?: Record<string, string[]>;
  /**
   * App roles a public invite may grant. A public link reaches whoever holds
   * it, so keep this to low roles. Checked at create, resend and redemption,
   * so narrowing it also stops existing links. Default: any role.
   */
  publicInviteRoles?: string[];
  /**
   * Startup check for `grantableRoles` and `organization.grantableRoles`:
   * each grantable role's access control permissions must be a subset of
   * its holder's, because a holder can always send a grantable role to a
   * second account it controls. "warn" (default) logs every gap and every
   * entry it cannot verify (roles without declared statements, dynamic org
   * roles); "error" throws at startup; "off" skips the check.
   */
  grantableRolesCheck?: "warn" | "error" | "off";
  /** Overrides the app role ceiling. Receives the requested role string. */
  canGrantRole?: (
    user: User & { role?: string | null },
    role: string
  ) => Promise<boolean> | boolean;

  /**
   * Extra user fields collected when a redemption signs the invitee up
   * (nextAction SIGN_UP). The plugin adds them to the user model schema
   * (nullable at the database level; requiredness is enforced by the
   * redeem flow), validates the redeem body against them, stores the
   * values on the created or claimed user, and lists them in GET
   * /invite/get so the invite page knows what to render. Do not also
   * declare these under user.additionalFields.
   */
  additionalFields?: Record<string, InviteAdditionalField>;

  /**
   * Enables organization plugin integration: org-join and org-create
   * invite kinds, seat limits, and platform controls. Requires the
   * organization plugin to be registered.
   */
  organization?: BetterEnrollmentOrgOptions;

  /**
   * Build the URL embedded in invitation emails / returned from create.
   * Default: `${origin(baseURL)}/invite?token=${token}`.
   */
  buildInviteUrl?: (data: { token: string; type: InviteType; mode: InviteMode }) => string;
  /**
   * Where the default invite link carries its token. "query"
   * (`/invite?token=`, default) or "fragment" (`/invite#token=`): a
   * fragment never reaches servers, so it stays out of access logs, proxies
   * and Referer headers. The page then reads `location.hash` and looks the
   * invite up with POST, which takes the token in the body. Ignored when
   * buildInviteUrl is set.
   */
  linkStyle?: "query" | "fragment";

  /** `admin` is null when the invite was created through the server-only system endpoint. */
  onInviteCreated?: (data: { invite: Invite; admin: User | null }) => Promise<void> | void;
  onInviteResent?: (data: { invite: Invite; admin: User }) => Promise<void> | void;
  onInviteAccepted?: (data: { invite: Invite; user: User }) => Promise<void> | void;
  onInviteRevoked?: (data: { invite: Invite; admin: User }) => Promise<void> | void;
  onInviteDeleted?: (data: { invite: Invite; admin: User | null }) => Promise<void> | void;
  /** Fires lazily when an expired invite is touched. May fire more than once. */
  onInviteExpired?: (data: { invite: Invite }) => Promise<void> | void;
  onInvalidRole?: (data: { invite: Invite; role: string }) => Promise<void> | void;
  /**
   * Fires when the plugin withdraws invites on its own because their
   * inviter or invitee lost standing (see InviteCancelReason). Called once
   * per batch of up to 1000 invites. `deleted` is true when the rows were
   * deleted (inviter deleted) rather than cancelled. Errors are logged and
   * never undo the cancellation.
   */
  onInvitesCancelled?: (data: InvitesCancelledData) => Promise<void> | void;

  /**
   * Re-check at redemption (and in invite.get) that the invite's creator
   * still holds the rights it used: org membership with invitation:create
   * and the org role ceiling for org-join, the invite gate and app role
   * ceiling otherwise. Default false. An invite whose creator was deleted
   * or banned is always withdrawn, with or without this option. Leave it
   * off when createSystemInvite attributes invites to users who are not
   * members of the target org.
   */
  revalidateInviterOnRedeem?: boolean;
}

/**
 * Why invites were withdrawn automatically:
 * - inviter-banned: the creator was banned (any path, or banMembers)
 * - inviter-deleted: the creator's account was deleted (rows deleted)
 * - invitee-deleted: the account the private invite is addressed to was deleted
 * - inviter-removed-from-org / inviter-left-org: org-join invites of a former member
 * - inviter-role-changed: org-join invites the creator's new org role may no longer create or grant
 * - inviter-inactive: found at redemption or invite.get (creator gone, banned,
 *   or, with revalidateInviterOnRedeem, no longer authorized)
 */
export type InviteCancelReason =
  | "inviter-banned"
  | "inviter-deleted"
  | "invitee-deleted"
  | "inviter-removed-from-org"
  | "inviter-left-org"
  | "inviter-role-changed"
  | "inviter-inactive";

export interface InvitesCancelledData {
  reason: InviteCancelReason;
  inviteIds: string[];
  deleted: boolean;
  /** The inviter or invitee the event is about, when known. */
  userId: string | null;
  organizationId: string | null;
}

const err =<const C extends string>(code: C, message: string) => ({
  code,
  message
});

export const INVITE_ERROR_CODES = {
  INVITE_NOT_FOUND: err("INVITE_NOT_FOUND", "Invitation not found or no longer valid"),
  INVITE_EXPIRED: err("INVITE_EXPIRED", "This invitation has expired"),
  INVITE_REVOKED: err("INVITE_REVOKED", "This invitation has been revoked"),
  INVITE_ALREADY_USED: err("INVITE_ALREADY_USED", "This invitation has already been used"),
  INVITE_USES_EXHAUSTED: err("INVITE_USES_EXHAUSTED", "This invitation has no remaining uses"),
  EMAIL_ALREADY_INVITED: err(
    "EMAIL_ALREADY_INVITED",
    "A pending invitation already exists for this email. Delete the existing invite first."
  ),
  USER_ALREADY_EXISTS: err("USER_ALREADY_EXISTS", "A user with this email already exists"),
  EMAIL_REQUIRED_FOR_PRIVATE_INVITE: err(
    "EMAIL_REQUIRED_FOR_PRIVATE_INVITE",
    "Private invitations require an email"
  ),
  EMAIL_REQUIRED_FOR_PUBLIC_ACCEPT: err(
    "EMAIL_REQUIRED_FOR_PUBLIC_ACCEPT",
    "An email is required to accept a public invitation"
  ),
  MAX_USES_INVALID_FOR_PRIVATE: err(
    "MAX_USES_INVALID_FOR_PRIVATE",
    "Private invitations are always single use"
  ),
  INVALID_ROLE: err("INVALID_ROLE", "The requested role is not allowed"),
  ROLE_NO_LONGER_VALID: err("ROLE_NO_LONGER_VALID", "The invited role is no longer valid"),
  NOT_ALLOWED_TO_MANAGE_INVITES: err(
    "NOT_ALLOWED_TO_MANAGE_INVITES",
    "You are not allowed to manage invitations"
  ),
  ACCEPT_ONLY_IN_INVITE_ONLY_MODE: err(
    "ACCEPT_ONLY_IN_INVITE_ONLY_MODE",
    "invite/accept is only available in invite-only mode; use invite/activate"
  ),
  ACTIVATE_ONLY_IN_OPEN_MODE: err(
    "ACTIVATE_ONLY_IN_OPEN_MODE",
    "invite/activate is only available in open mode; use invite/accept"
  ),
  EMAIL_MISMATCH: err("EMAIL_MISMATCH", "This invitation was issued to a different email address"),
  EMAIL_NOT_VERIFIED: err(
    "EMAIL_NOT_VERIFIED",
    "Verify your email address before activating this invitation"
  ),
  PRE_CREATED_USER_MISSING: err(
    "PRE_CREATED_USER_MISSING",
    "The invited account could not be found"
  ),
  ACCEPTED_INVITES_ARE_PERMANENT: err(
    "ACCEPTED_INVITES_ARE_PERMANENT",
    "Accepted invitations are audit records and cannot be deleted"
  ),
  USED_INVITES_CANNOT_BE_DELETED: err(
    "USED_INVITES_CANNOT_BE_DELETED",
    "This invitation has recorded uses; revoke it instead of deleting"
  ),
  INVITATION_REQUIRED: err(
    "INVITATION_REQUIRED",
    "An invitation link is required to activate your account"
  ),
  PASSWORD_REQUIRED: err("PASSWORD_REQUIRED", "A password is required to accept this invitation"),
  PASSWORD_NOT_AVAILABLE: err(
    "PASSWORD_NOT_AVAILABLE",
    "This app does not use passwords; accept the invitation without one"
  ),
  NAME_REQUIRED: err("NAME_REQUIRED", "A name is required to accept this invitation"),
  ADDITIONAL_FIELD_REQUIRED: err("ADDITIONAL_FIELD_REQUIRED", "A required field is missing"),
  ADDITIONAL_FIELD_INVALID: err("ADDITIONAL_FIELD_INVALID", "A field value failed validation"),
  USER_BANNED: err("USER_BANNED", "This account has been banned"),

  ORG_FEATURES_DISABLED: err(
    "ORG_FEATURES_DISABLED",
    "Organization features are not enabled for this plugin"
  ),
  ORGANIZATION_ID_REQUIRED: err(
    "ORGANIZATION_ID_REQUIRED",
    "org-join invitations require an organizationId"
  ),
  ORG_FIELDS_NOT_ALLOWED: err(
    "ORG_FIELDS_NOT_ALLOWED",
    "Organization fields are not allowed for this invite kind"
  ),
  ROLE_NOT_ALLOWED_FOR_ORG_JOIN: err(
    "ROLE_NOT_ALLOWED_FOR_ORG_JOIN",
    "org-join invitations cannot set an app role; new members receive the default role"
  ),
  ORG_NOT_FOUND: err("ORG_NOT_FOUND", "Organization not found"),
  ORG_DISABLED: err("ORG_DISABLED", "This organization has been disabled"),
  ORG_INVITE_NOT_ALLOWED: err(
    "ORG_INVITE_NOT_ALLOWED",
    "You are not allowed to manage invitations for this organization"
  ),
  TEAM_NOT_FOUND: err("TEAM_NOT_FOUND", "Team not found in this organization"),
  INVALID_ORG_ROLE: err("INVALID_ORG_ROLE", "The requested organization role does not exist"),
  OWNER_INVITES_NOT_ALLOWED: err(
    "OWNER_INVITES_NOT_ALLOWED",
    "Invitations may not grant the owner role"
  ),
  ROLE_NOT_GRANTABLE: err("ROLE_NOT_GRANTABLE", "You are not allowed to grant this role"),
  ROLE_NOT_ALLOWED_FOR_PUBLIC_INVITE: err(
    "ROLE_NOT_ALLOWED_FOR_PUBLIC_INVITE",
    "Public invitations cannot grant this role"
  ),
  ORG_ROLE_NOT_GRANTABLE: err(
    "ORG_ROLE_NOT_GRANTABLE",
    "You are not allowed to grant this organization role"
  ),
  CANNOT_REDEEM_OWN_INVITE: err(
    "CANNOT_REDEEM_OWN_INVITE",
    "You cannot redeem an invitation that grants yourself a role you may not assign"
  ),
  SEAT_LIMIT_REACHED: err("SEAT_LIMIT_REACHED", "This organization has no seats remaining"),
  MEMBERSHIP_LIMIT_REACHED: err(
    "MEMBERSHIP_LIMIT_REACHED",
    "This organization has reached its membership limit"
  ),
  PUBLIC_ORG_INVITE_REQUIRES_MAX_USES: err(
    "PUBLIC_ORG_INVITE_REQUIRES_MAX_USES",
    "Public invitations for a seat-limited organization must set maxUses"
  ),
  ORG_INFO_REQUIRED: err(
    "ORG_INFO_REQUIRED",
    "organizationName and organizationSlug are required to accept this invitation"
  ),
  ORG_SLUG_TAKEN: err("ORG_SLUG_TAKEN", "An organization with this slug already exists"),
  INVALID_CURSOR: err("INVALID_CURSOR", "The pagination cursor is invalid"),
  INVALID_ORG_SLUG: err(VALIDATION_ERRORS.INVALID_ORG_SLUG.code, VALIDATION_ERRORS.INVALID_ORG_SLUG.message),
  INVALID_ORG_NAME: err(VALIDATION_ERRORS.INVALID_ORG_NAME.code, VALIDATION_ERRORS.INVALID_ORG_NAME.message),
  EXPIRES_IN_TOO_LONG: err("EXPIRES_IN_TOO_LONG", "The requested invitation lifetime is too long"),
  MAX_USES_TOO_HIGH: err("MAX_USES_TOO_HIGH", "The requested number of uses is too high"),
  RESEND_TOO_SOON: err(
    "RESEND_TOO_SOON",
    "This invitation was sent moments ago; wait before sending it again"
  )
} as const;
