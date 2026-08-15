import { createAccessControl } from "better-auth/plugins/access";

/**
 * The invite resource this plugin authorizes against. Spread it into the
 * statement object of the same access-control file you pass to the admin
 * plugin, so one file drives permissions everywhere:
 *
 * ```ts
 * // permissions.ts — shared by admin() and betterEnrollment()
 * import { createAccessControl } from "better-auth/plugins/access";
 * import { defaultStatements, adminAc } from "better-auth/plugins/admin/access";
 * import { inviteStatements, inviteAdminAc } from "@octopi-ai/better-enrollment";
 *
 * export const statement = { ...defaultStatements, ...inviteStatements } as const;
 * export const ac = createAccessControl(statement);
 * export const admin = ac.newRole({ ...adminAc.statements, ...inviteAdminAc.statements });
 * ```
 */
export const inviteStatements = {
  invite: ["create", "resend", "list", "cancel", "delete", "manage-orgs"]
} as const;

/** One action per admin-gated invite endpoint. */
export type InviteManagementAction = (typeof inviteStatements.invite)[number];

/** Access controller over just the invite statements. */
export const inviteAc = createAccessControl(inviteStatements);

/** Full invite management; merge into your admin role. */
export const inviteAdminAc = inviteAc.newRole({
  invite: ["create", "resend", "list", "cancel", "delete", "manage-orgs"]
});

/** No invite permissions; merge into non-managing roles. */
export const inviteUserAc = inviteAc.newRole({
  invite: []
});

/**
 * Fallback used when the `roles` option is omitted, mirroring the admin
 * plugin's defaults: the "admin" role manages invites, "user" does not.
 */
export const defaultInviteRoles = {
  admin: inviteAdminAc,
  user: inviteUserAc
};
