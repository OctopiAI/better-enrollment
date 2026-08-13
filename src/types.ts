import type { User } from "better-auth";

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

/** Structural type for roles built with createAccessControl().newRole(). */
export interface OrgRoleLike {
  authorize: (
    permissions: Record<string, string[]>,
    connector?: "OR" | "AND"
  ) => { success: boolean; error?: string };
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
  maxUses: number | null;
  expiresAt: Date | null;
}

export interface BetterEnrollmentOrgOptions {
  /** Kept for parity with the org plugin config; not read directly. */
  ac?: unknown;
  /**
   * The same roles record passed to the org plugin. When omitted, the org
   * plugin defaults apply: owner and admin hold invitation create/cancel.
   */
  roles?: Record<string, OrgRoleLike>;
  /** Overrides the invitation:create permission check for org-join creation. */
  canCreateOrgInvites?: (
    member: MemberRecord,
    org: OrganizationRecord
  ) => Promise<boolean> | boolean;
  /** Allow org-join invites that grant the "owner" org role. Default false. */
  allowOwnerInvites?: boolean;
  /** Org role granted when an org-join invite does not name one. Default "member". */
  defaultOrganizationRole?: string;
  /** Org role granted to the founder via an org-create invite. Default "owner". */
  orgCreateRole?: string;
  /** Seat limit applied when the organization row has none. */
  defaultSeatLimit?: number;
  /** Highest-priority seat limit source, e.g. read a subscription tier. */
  resolveSeatLimit?: (org: OrganizationRecord) => Promise<number | null> | number | null;
  /** Revoke an inviter's pending invites when the admin plugin bans them. Default true. */
  revokeInvitesOnInviterBan?: boolean;

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
  onOrgDisabled?: (data: {
    organization: OrganizationRecord;
    bannedMembers: number;
  }) => Promise<void> | void;
  onOrgEnabled?: (data: { organization: OrganizationRecord }) => Promise<void> | void;
  onOrgDeleted?: (data: {
    organization: OrganizationRecord;
    bannedMembers: number;
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

  /** Roles allowed to manage invites. Default ["admin"]. */
  adminRoles?: string[];
  /** User ids that may always manage invites. */
  adminUserIds?: string[];
  /** Custom gate. When set, replaces adminRoles/adminUserIds entirely. */
  canManageInvites?: (user: User & { role?: string | null }) => Promise<boolean> | boolean;

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

  /** `admin` is null when the invite was created through the server-only system endpoint. */
  onInviteCreated?: (data: { invite: Invite; admin: User | null }) => Promise<void> | void;
  onInviteResent?: (data: { invite: Invite; admin: User }) => Promise<void> | void;
  onInviteAccepted?: (data: { invite: Invite; user: User }) => Promise<void> | void;
  onInviteRevoked?: (data: { invite: Invite; admin: User }) => Promise<void> | void;
  onInviteDeleted?: (data: { invite: Invite; admin: User | null }) => Promise<void> | void;
  /** Fires lazily when an expired invite is touched. May fire more than once. */
  onInviteExpired?: (data: { invite: Invite }) => Promise<void> | void;
  onInvalidRole?: (data: { invite: Invite; role: string }) => Promise<void> | void;
}

const err = <const C extends string>(code: C, message: string) => ({
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
  SEAT_LIMIT_REACHED: err("SEAT_LIMIT_REACHED", "This organization has no seats remaining"),
  PUBLIC_ORG_INVITE_REQUIRES_MAX_USES: err(
    "PUBLIC_ORG_INVITE_REQUIRES_MAX_USES",
    "Public invitations for a seat-limited organization must set maxUses"
  ),
  ORG_INFO_REQUIRED: err(
    "ORG_INFO_REQUIRED",
    "organizationName and organizationSlug are required to accept this invitation"
  ),
  ORG_SLUG_TAKEN: err("ORG_SLUG_TAKEN", "An organization with this slug already exists")
} as const;
