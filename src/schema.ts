import type { BetterAuthPlugin } from "better-auth";
import type { InviteAdditionalField } from "./types";

const inviteFields = {
  type: { type: "string", required: true, input: false },
  kind: {
    type: "string",
    required: true,
    input: false,
    defaultValue: "app"
  },
  email: { type: "string", required: false, input: false, index: true },
  name: { type: "string", required: false, input: false },
  role: { type: "string", required: true, input: false },
  tokenHash: { type: "string", required: true, input: false, unique: true },
  status: {
    type: "string",
    required: true,
    input: false,
    defaultValue: "pending",
    index: true
  },
  mode: { type: "string", required: true, input: false },
  // Plain columns, no FK: org rows may be removed by the org plugin's own
  // flows and accepted invites must survive as audit records.
  organizationId: { type: "string", required: false, input: false, index: true },
  organizationRole: { type: "string", required: false, input: false },
  teamId: { type: "string", required: false, input: false },
  presetSeatLimit: { type: "number", required: false, input: false },
  preCreatedUserId: { type: "string", required: false, input: false },
  // No FK: accepted invites outlive their inviter (denormalized fields).
  createdByUserId: { type: "string", required: false, input: false, index: true },
  inviterName: { type: "string", required: true, input: false },
  inviterEmail: { type: "string", required: true, input: false },
  expiresAt: { type: "date", required: false, input: false, index: true },
  maxUses: { type: "number", required: false, input: false },
  useCount: { type: "number", required: true, input: false, defaultValue: 0 },
  revokedAt: { type: "date", required: false, input: false },
  revokedByUserId: { type: "string", required: false, input: false },
  createdAt: { type: "date", required: true, input: false },
  updatedAt: { type: "date", required: true, input: false }
} as const;

const inviteUseFields = {
  inviteId: {
    type: "string",
    required: true,
    input: false,
    index: true,
    references: { model: "invite", field: "id", onDelete: "cascade" }
  },
  usedByUserId: { type: "string", required: true, input: false },
  inviteeEmail: { type: "string", required: true, input: false },
  usedAt: { type: "date", required: true, input: false }
} as const;

/**
 * The organization extension is added only when org features are configured,
 * so apps without the org plugin never get a stray organization table.
 *
 * Additional fields extend the user model but are always nullable at the
 * database level: pre-created and open-mode users exist before redemption
 * collects a value. Requiredness is enforced by the redeem flow instead.
 */
export function buildSchema(
  withOrg: boolean,
  additionalUserFields?: Record<string, InviteAdditionalField>
) {
  const userFields: Record<string, { type: InviteAdditionalField["type"]; required: false }> = {};
  for (const [name, field] of Object.entries(additionalUserFields ?? {})) {
    userFields[name] = { type: field.type, required: false };
  }
  return {
    invite: { fields: inviteFields },
    inviteUse: { fields: inviteUseFields },
    ...(Object.keys(userFields).length > 0 ? { user: { fields: userFields } } : {}),
    ...(withOrg
      ? {
          organization: {
            fields: {
              seatLimit: { type: "number", required: false, input: false },
              disabledAt: { type: "date", required: false, input: false }
            }
          }
        }
      : {})
  } satisfies BetterAuthPlugin["schema"];
}

export const schema = buildSchema(false);
