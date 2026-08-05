<div align="center">
    <h1>【 Better Enrollment 】</h1>
    <h3></h3>
</div>

<div align="center">

![](https://shields.octopi.ai/github/last-commit/OctopiAI/better-enrollment?&style=for-the-badge&color=8ad7eb&logo=git&logoColor=D9E0EE&labelColor=1E202B)
![](https://shields.octopi.ai/github/stars/OctopiAI/better-enrollment?style=for-the-badge&logo=andela&color=86dbd7&logoColor=D9E0EE&labelColor=1E202B)
![](https://shields.octopi.ai/github/repo-size/OctopiAI/better-enrollment?color=86dbce&label=SIZE&logo=protondrive&style=for-the-badge&logoColor=D9E0EE&labelColor=1E202B)
![](https://shields.octopi.ai/github/forks/OctopiAI/better-enrollment?color=86dbce&label=FORKS&logo=forgejo&style=for-the-badge&logoColor=D9E0EE&labelColor=1E202B)

</div>

<p align="center">
  A plugin for <a href="https://www.better-auth.com">Better Auth</a> that makes invitations the front door of your app: run fully invite-only, hand out shareable invite links, or use invites as role and organization grants in an open app.
  <br />
  <br />
  <a href="https://github.com/OctopiAI/better-enrollment/issues">Issues</a>
</p>

<p align="center">
  <a href="https://choosealicense.com/licenses/mit/">
    <img src="https://img.shields.io/badge/License-MIT-green.svg" />
  </a>
  <a href="https://www.typescriptlang.org/">
    <img src="https://img.shields.io/badge/TypeScript-Ready-blue?logo=typescript&logoColor=white" />
  </a>
  <a href="https://www.npmjs.com/package/@octopi-ai/better-enrollment/">
    <img src="https://img.shields.io/npm/v/%40octopi-ai%2Fbetter-enrollment?logo=npm" />
  </a>
  <a href="https://www.npmjs.com/package/@octopi-ai/better-enrollment/">
    <img src="https://img.shields.io/npm/dm/%40octopi-ai%2Fbetter-enrollment?logo=npm&label=Downloads&labelColor=gray&color=red" />
  </a>
  <a href="https://www.better-auth.com/docs/concepts/plugins/">
    <img src="https://img.shields.io/badge/Better_Auth-Plugin-blue?logo=better-auth" />
  </a>
  <a href="https://github.com/OctopiAI/better-enrollment/actions/workflows/ci.yml">
    <img src="https://github.com/OctopiAI/better-enrollment/actions/workflows/ci.yml/badge.svg?branch=main" />
  </a>
</p>

## Features

- 🚪 **Invite-only mode**: close every sign-up route and let people in only through invitations.
- 🔓 **Open mode**: invitations become role and organization grants for self-serve sign-ups.
- ✉️ **Private invites**: email-bound, single use, verified on accept.
- 🔗 **Public invites**: shareable links with use caps, expiry, and revocation.
- 🏢 **Organization onboarding**: one link joins an org, or lets the invitee found their own.
- 💺 **Seat limits**: per-org caps with pending-invite reservations and subscription hooks.
- 🛡️ **Security first**: hashed tokens, atomic race-safe redemption, no email oracles.
- 🧾 **Audit trail**: append-only record of who invited whom and who redeemed what.
- 🧩 **One redemption page**: a single `?token=` page and one `redeem` call handle every invite kind in both modes.
- ⚙️ **Adapter-agnostic**: works with any Better Auth database adapter, no extra infrastructure.

---

## Installation

```bash
npm install @octopi-ai/better-enrollment
# or
pnpm add @octopi-ai/better-enrollment
# or
yarn add @octopi-ai/better-enrollment
# or
bun add @octopi-ai/better-enrollment
```

Requires `better-auth >= 1.4.0` and `zod >= 4`.

---

## Server-Side Setup

Import `betterEnrollment` and add it to your `betterAuth` configuration. This example is a fully closed app where invitations are the only way in:

```ts
import { betterAuth } from "better-auth";
import { admin } from "better-auth/plugins";
import { betterEnrollment } from "@octopi-ai/better-enrollment";

export const auth = betterAuth({
  emailAndPassword: {
    enabled: true,
    disableSignUp: true
  },
  plugins: [
    admin(),
    betterEnrollment({
      async sendPrivateInvitation({ email, url }) {
        await sendInvitationEmail(email, url);
      }
    })
  ]
});
```

Then generate or migrate your schema as usual:

```bash
npx @better-auth/cli migrate
# or
npx @better-auth/cli generate
```

This creates the `invite` and `inviteUse` tables.

> **Role field required.** Invited roles are stored in a string `role` field on your user model, and the default admin gate reads it. The admin plugin provides one, or add it yourself via `user.additionalFields`. Without it, the plugin warns at startup and you must gate management with `adminUserIds` or `canManageInvites` instead.

---

## Client-Side Setup

Import `betterEnrollmentClient` and add it to your auth client:

```ts
import { createAuthClient } from "better-auth/react";
import { betterEnrollmentClient } from "@octopi-ai/better-enrollment/client";

export const authClient = createAuthClient({
  plugins: [betterEnrollmentClient()]
});
```

---

## How it works

- An admin (or an org member with permission) creates an invite; private invites are emailed, public invites return a shareable URL once.
- Tokens are crypto-random and stored SHA-256 hashed, so a database leak exposes no usable links. A private invite link is never shown to its creator: only the emailed recipient holds it, which is why accepting one marks the email verified.
- Every invite link points at one page in your app carrying only `?token=`. The page calls `invite.get`, renders what `nextAction` and `requiredFields` say, and submits to `invite.redeem`.
- In invite-only mode redemption creates the user, credential account, and session. In open mode it merges the invited role (and org membership) into the signed-in user's account. Roles always merge as a union, so an invite can never demote anyone.
- All state changes are guarded atomic writes: parallel redemptions of a one-seat invite produce exactly one winner. Expiry is derived from `expiresAt` at read time, so there is no cron and nothing to sweep.
- While a private invite is pending, its email is locked on every path: sign-in, sign-up, password reset, and OAuth linking are all blocked without leaking that the invite exists.

> **Role changes made outside this plugin do not merge.** Better Auth stores multiple roles as one comma-separated string (for example `"user,org-creator"`), and only invite redemption merges into it as a union. The admin plugin's `setRole` (and any direct write) replaces the field with exactly what you send, so a bare `setRole({ role: "admin" })` silently strips invite-granted roles. When changing roles from your own admin UI, always send the full set: `role: [...existingRoles, "admin"]`.

---

## The two modes

`mode` accepts `"auto"` (default), `"invite-only"`, or `"open"`. In `auto` the plugin inspects your config at startup: everything closed means invite-only, everything open means open, and a mixed config throws with a message naming each path, asking you to set `mode` explicitly.

> **Your responsibility, for now:** detection only sees `emailAndPassword` and `socialProviders`. Sign-up paths added by other plugins (magic link, email OTP, passkey, phone number, anonymous, generic OAuth) are invisible to it and are NOT blocked at runtime, so any of them silently bypasses invite-only mode. If you use one, you must close or remove its sign-up path yourself. A runtime backstop that rejects non-invite user creation is on the [roadmap](#roadmap).

**`invite-only`**: all sign-up routes are disabled and the plugin creates users through Better Auth's internal adapter. Setting it explicitly while a sign-up path is still open throws at init; `allowOpenSignup: true` downgrades that to a warning, and the guarantee becomes per-email: pending invites still lock their own address while everyone else signs up freely.

**`open`**: anyone signs up normally, and activating an invite merges the invited role and any org membership into their existing account.

```ts
emailAndPassword: { enabled: true },
plugins: [admin(), betterEnrollment({ /* ... */ })],
```

---

## Invite kinds and delivery

Two choices define every invite: what it grants (`kind`) and how it travels (`type`). Everything else resolves server-side.

| Kind            | Grants                                 | Who may create it                                |
| --------------- | -------------------------------------- | ------------------------------------------------ |
| `app` (default) | Access to the app                      | App admins                                       |
| `org-join`      | Membership in an existing organization | That org's members with `invitation: ["create"]` |
| `org-create`    | Founding and owning a new organization | App admins                                       |

App admins deliberately cannot create `org-join` invites: an organization owns its member list, and the platform's lever is the seat limit. Org kinds require the organization plugin.

|                          | Private                                 | Public                                   |
| ------------------------ | --------------------------------------- | ---------------------------------------- |
| Bound to                 | One email address                       | Nobody                                   |
| Uses                     | Always exactly 1                        | `maxUses`, or unlimited when `null`      |
| Delivery                 | Emailed by your `sendPrivateInvitation` | A link you distribute                    |
| Link visible to creator  | **Never**                               | Yes, returned once                       |
| Email verified on accept | Yes                                     | No, unless `autoVerifyPublicInviteEmail` |

No email delivery? Use a public invite with `maxUses: 1`. There is deliberately no option to reveal a private link, because possession of one is proof of mailbox access.

### Verifying public-invite emails

That last table row matters in practice. A private invite token traveled through the recipient's inbox, so accepting it proves mailbox ownership and the user is marked verified. A public invite proves only possession of the link: the accepter can type any email address, so the user is created with `emailVerified: false`.

Verification then happens through Better Auth's standard flow, which this plugin deliberately does not replace. Configure it and public-invite signups are covered automatically:

```ts
export const auth = betterAuth({
  emailVerification: {
    sendVerificationEmail: async ({ user, url }) => {
      await sendEmail(user.email, "Verify your email", url);
    },
    sendOnSignUp: true // also fires for public-invite signups, since they start unverified
  },
  // Optional: block sign-in until verified
  emailAndPassword: { requireEmailVerification: true }
});
```

The accepter still gets a session immediately; they verify by clicking the emailed link like any other signup. Set `autoVerifyPublicInviteEmail: true` only when you skip that flow entirely (internal tools, trusted environments). It marks public-invite users verified on the spot, which means anyone holding the link can register an address they do not own.

---

## Creating invites

A private invite for a closed beta:

```ts
await auth.api.createInvite({
  body: { type: "private", email: "ada@example.com", name: "Ada", role: "user" },
  headers
});
// -> { inviteId, expiresAt }
```

A capped public signup link:

```ts
await auth.api.createInvite({
  body: { type: "public", role: "user", maxUses: 50 },
  headers
});
// -> { inviteId, expiresAt, token, url }
```

An org owner inviting a teammate (`organizationRole` goes to `member.role`):

```ts
await auth.api.createInvite({
  body: {
    kind: "org-join",
    type: "private",
    email: "dev@acme.com",
    organizationId: org.id,
    organizationRole: "developer"
  },
  headers: ownerHeaders
});
```

The app-level `role` field is admin-only. `org-join` invites reject it (`ROLE_NOT_ALLOWED_FOR_ORG_JOIN`) and always grant `defaultRole`: org inviters are trusted by their organization, not by the app, so letting them pick `user.role` would let any org owner mint app admins.

Partner onboarding, where the recipient signs up and founds their own organization in one form:

```ts
await auth.api.createInvite({
  body: {
    kind: "org-create",
    type: "private",
    email: "founder@acme.com",
    role: "user",
    presetSeatLimit: 25
  },
  headers
});
```

A public `org-join` invite is a shareable join link for one org (in a seat-limited org `maxUses` is required). A public `org-create` invite founds a separate organization per use.

**Inviting someone who already has an account** works out of the box for org kinds: the invite becomes an activation invite, the invitee signs in and confirms, and redemption merges roles and membership instead of creating a user. A plain `app` invite to an existing email is rejected with `USER_ALREADY_EXISTS`, since it grants nothing an existing user lacks.

---

## The invite page

Every invitation link points at the same page, carrying only `?token=`. The invitee never needs to know what kind of invite they hold.

```ts
const { data: invite } = await authClient.invite.get({ token });
```

| `invite.nextAction` | Meaning                       | What to render                               |
| ------------------- | ----------------------------- | -------------------------------------------- |
| `SIGN_UP`           | Invite-only, no session       | The fields listed in `requiredFields`        |
| `SIGN_IN`           | Open mode, no session         | Your sign-in form; keep the token in the URL |
| `CONFIRM`           | Open mode, session present    | A single confirm button                      |
| `null`              | Expired, revoked, or consumed | A clear terminal message                     |

`requiredFields` lists exactly what to collect: always `password` for sign-up, plus `email` for public invites, plus `organizationName` and `organizationSlug` for `org-create`. Submit everything to one endpoint:

```ts
await authClient.invite.redeem({
  token,
  password,
  name,
  email,
  organizationName,
  organizationSlug
});
// -> { status: "ACCEPTED", user, organization? }
```

`redeem` routes to the right semantics for the mode and kind, so your page never branches. The response says what happened, so you can render "You joined Acme" or "Your organization is ready".

`invite.get` returns a deliberately thin payload: kind, role, derived status, expiry, uses remaining, and a masked email such as `a***@example.com`. Never the inviter's identity or internal ids.

---

## Organizations

Org features switch on when the organization plugin is detected. Pass the same `ac` and `roles` objects you gave the org plugin:

```ts
import { organization } from "better-auth/plugins";
import { betterEnrollment, roleGate } from "@octopi-ai/better-enrollment";

plugins: [
  admin(),
  organization({
    ac, roles,
    allowUserToCreateOrganization: roleGate(["admin", "org-creator"]),
  }),
  betterEnrollment({
    organization: {
      ac, roles,
      defaultOrganizationRole: "member",
      defaultSeatLimit: 10,
    },
  }),
],
```

Redeeming an org invite writes the member row (and team membership when `teamId` is set) in the same flow that creates the account, then sets the session's active organization. Redemption re-validates everything, since state drifts between create and accept.

**Seat limits** resolve in order: `resolveSeatLimit(org)` callback, the org's `seatLimit` column, `defaultSeatLimit`, then unlimited. Seats used = members + pending invite reservations (a private invite reserves one seat, a public one reserves `maxUses - useCount`). Enforcement happens at creation and again inside a guarded write at redemption, so parallel accepts never overshoot.

```ts
await authClient.invite.org.setSeatLimit({ organizationId, seatLimit: 25 });
await authClient.invite.org.usage({ organizationId });
// -> { seatLimit, members, pendingReserved, remaining }
```

**Platform controls** (app-admin only): disable, enable, and delete organizations. A disabled org refuses invite creation, redemption, and org plugin mutations. Member accounts are never touched by default; `banMembers: true` additionally bans every member app-wide, for fraud takedowns.

```ts
await authClient.invite.org.disable({ organizationId });
await authClient.invite.org.enable({ organizationId });
await authClient.invite.org.delete({ organizationId });
```

### Who can do what

| Action                             | App admin           | Org owner or admin | Member with `invitation:create` | Plain member |
| ---------------------------------- | ------------------- | ------------------ | ------------------------------- | ------------ |
| Create `app` / `org-create` invite | Yes                 | No                 | No                              | No           |
| Create `org-join` invite           | **No**              | Yes                | Yes                             | No           |
| List invites                       | All                 | Own org            | Own org                         | No           |
| Revoke or delete                   | Moderation backstop | Own org            | Own org (`invitation:cancel`)   | No           |
| Seat limits, disable, delete org   | Yes                 | No                 | No                              | No           |

App admins come from `adminRoles` (default `["admin"]`), `adminUserIds`, or your own `canManageInvites(user)` callback. Org permissions are the org plugin's own access control. Cross-org calls return `FORBIDDEN`, and unknown org ids look identical so they cannot be enumerated.

---

## Options reference

```ts
betterEnrollment({
  // Mode
  mode: "auto", // "auto" | "invite-only" | "open"
  allowOpenSignup: false,

  // Delivery. Implementations are yours; the plugin never sends mail.
  async sendPrivateInvitation({
    email,
    name,
    role,
    kind,
    mode,
    url,
    token,
    inviterName,
    inviterEmail,
    organizationName,
    expiresAt
  }) {},
  async sendPublicInvitation({
    role,
    kind,
    mode,
    url,
    token,
    inviterName,
    inviterEmail,
    organizationName,
    maxUses,
    expiresAt
  }) {},

  // Roles
  validRoles: ["user", "admin"], // omit to skip validation
  fallbackRole: undefined, // used when an invited role was deleted
  defaultRole: "user",

  // Lifetime and usage
  expiresIn: 60 * 60 * 24 * 7, // private invites, in seconds
  publicExpiresIn: 60 * 60 * 24 * 7, // public invites; null = never

  // Security posture
  hashTokens: true,
  autoVerifyPublicInviteEmail: false, // see "Verifying public-invite emails"
  exposeEmailOnGet: false,

  // Who may manage invitations
  adminRoles: ["admin"],
  adminUserIds: [],
  canManageInvites: undefined, // (user) => boolean, replaces the two above

  // Links
  buildInviteUrl: ({ token, type, mode }) => `https://app.example.com/invite?token=${token}`,

  // Organizations
  organization: {
    ac,
    roles, // the same objects given to the org plugin
    canCreateOrgInvites: undefined, // (member, org) => boolean
    allowOwnerInvites: false,
    defaultOrganizationRole: "member",
    orgCreateRole: "owner",
    defaultSeatLimit: undefined,
    resolveSeatLimit: undefined, // async (org) => number | null
    revokeInvitesOnInviterBan: true,
    onOrgMemberAdded,
    onSeatLimitReached,
    onOrgDisabled,
    onOrgEnabled,
    onOrgDeleted
  },

  // Lifecycle hooks
  onInviteCreated,
  onInviteAccepted,
  onInviteRevoked,
  onInviteDeleted,
  onInviteExpired,
  onInvalidRole
});
```

All client methods:

```ts
// Redemption, for the invite page
authClient.invite.get({ token });
authClient.invite.redeem({ token, ... });

// Management
authClient.invite.create({ kind?, type?, email?, name?, role?, maxUses?, expiresIn?,
                           organizationId?, organizationRole?, teamId?, presetSeatLimit? });
authClient.invite.list({ status?, type?, organizationId?, page?, limit? });
authClient.invite.revoke({ inviteId });
authClient.invite.delete({ inviteId });

// Mode-specific primitives, kept for compatibility
authClient.invite.accept({ token, password, name?, email? });
authClient.invite.activate({ token });

// Organization administration
authClient.invite.org.usage({ organizationId });
authClient.invite.org.setSeatLimit({ organizationId, seatLimit });
authClient.invite.org.disable({ organizationId, banMembers? });
authClient.invite.org.enable({ organizationId });
authClient.invite.org.delete({ organizationId, banMembers? });
```

Server-only, for your own scheduler:

```ts
const { deleted } = await auth.api.cleanupExpiredInvites();
```

Built-in rate limits: `/invite/accept`, `/invite/activate`, and `/invite/redeem` allow 5 requests per 60 seconds; `/invite/get` allows 10.

---

## Security notes

What is blocked in invite-only mode while a private invite is pending:

| Attempt                               | Blocked by                                                       | Response                                |
| ------------------------------------- | ---------------------------------------------------------------- | --------------------------------------- |
| `POST /sign-up/email`                 | Better Auth `disableSignUp`                                      | `EMAIL_PASSWORD_SIGN_UP_DISABLED`       |
| `POST /sign-in/email`                 | No credential account exists yet                                 | `INVALID_EMAIL_OR_PASSWORD`             |
| `POST /request-password-reset`        | Plugin before-hook                                               | Silent success, nothing sent, no oracle |
| OAuth sign-up as a new user           | Provider `disableSignUp`                                         | Redirect with `?error=signup_disabled`  |
| OAuth linking to the pre-created user | `requireLocalEmailVerified` plus an `account.create.before` hook | Account not linked                      |

After acceptance the user is verified, so OAuth linking works normally.

The password-reset hook exists because a private invite pre-creates an inert user, which locks the email. Without it, whoever controls the mailbox could set a password through the reset flow and skip the invite entirely, and outsiders could probe the endpoint to learn who has been invited. The hook returns Better Auth's own generic success response, byte-identical to the unknown-email case, and sends nothing.

An address stays locked while a pending invite row exists for it, even past `expiresAt`; re-inviting returns `CONFLICT`. The lock is global for `app` and `org-create` invites but per-organization for `org-join`, so the same person can hold pending invites to several orgs, and an org inviter cannot probe for pending invites outside their own org. `invite.delete` removes a pending or cancelled invite plus its still-inert pre-created user, which frees the address. Accepted invites are permanent audit records and cannot be deleted.

Revoking is softer than deleting: the pre-created user stays behind, so both the password-reset hook and the OAuth-linking hook keep blocking for any non-accepted invite (pending or cancelled), not just pending ones. When a signed-out visitor tries to accept a public invite with an email that already has an account, the response is the same `SIGN_IN_REQUIRED` action the activation flow uses, so the endpoint never confirms whether an account exists. The same guard covers activation invites called through `/invite/accept` directly: an invite issued to an already-established account can only merge inside that account's own session, never set its password from the token. The invite token proves mailbox control; changing or joining an existing account requires proof of account control, which is a session.

Tokens are `generateRandomString(32)` from Better Auth's crypto module, roughly 190 bits of entropy, stored as SHA-256 base64url and looked up by hash.

---

## Recipes

**Custom invite link URL:**

```ts
buildInviteUrl: ({ token }) => `${process.env.APP_URL}/invite?token=${encodeURIComponent(token)}`,
```

**Captcha on redemption endpoints:**

```ts
captcha({ endpoints: ["/invite/redeem", "/invite/accept", "/invite/activate"] });
```

**Breached password checks for invited users:**

```ts
haveIBeenPwned({
  paths: ["/sign-up/email", "/reset-password", "/invite/redeem", "/invite/accept"]
});
```

**Gating org creation by role** (an `org-create` invite bypasses this gate by design; the invitation is itself the authorization):

```ts
organization({ allowUserToCreateOrganization: roleGate(["admin", "org-creator"]) });
```

---

## Operations at scale

- **Expired-invite cleanup** is batched: `POST /invite/cleanup-expired` (server-only) deletes in passes of `batchSize` (default 500, max 5000) until drained, so table size never dictates the request's memory or duration. Run it on a cron.
- **Bulk org operations** (`disableOrg` with `banMembers`, `deleteOrg`) read and delete in pages of 1000, so they stay within driver bind-parameter limits on orgs of any size.
- **Indexes**: the schema indexes `email`, `organizationId`, `tokenHash` (unique), `status`, `expiresAt`, and `createdByUserId`. If your invite table grows into the millions, consider adding composite indexes `(email, status)` and `(organizationId, status)` in your own migrations; Better Auth's schema DSL only expresses single-column indexes.
- **Rate limits** ship with the plugin (5/min on redemption endpoints, 10/min on `get`/`check-slug`) but Better Auth stores counters in memory by default. If you run more than one instance, configure Better Auth's `rateLimit.storage` (e.g. `"secondary-storage"` with Redis) so the limits are shared instead of per-pod.

---

## Error codes

Errors are Better Auth `APIError`s carrying a `code` and a `message`:

```ts
import { INVITE_ERROR_CODES } from "@octopi-ai/better-enrollment";
```

| Code                                                      | When                                           |
| --------------------------------------------------------- | ---------------------------------------------- |
| `INVITE_NOT_FOUND`                                        | Unknown or no longer valid token               |
| `INVITE_EXPIRED`, `INVITE_REVOKED`, `INVITE_ALREADY_USED` | Terminal states                                |
| `EMAIL_ALREADY_INVITED`                                   | A pending invite already holds that address    |
| `USER_ALREADY_EXISTS`                                     | That address already has an account            |
| `INVALID_ROLE`, `ROLE_NO_LONGER_VALID`                    | Role rejected at create, or at redeem          |
| `ROLE_NOT_ALLOWED_FOR_ORG_JOIN`                           | `org-join` invites cannot set an app role      |
| `NOT_ALLOWED_TO_MANAGE_INVITES`                           | Failed the admin gate                          |
| `EMAIL_MISMATCH`, `EMAIL_NOT_VERIFIED`                    | Open-mode activation guards                    |
| `SEAT_LIMIT_REACHED`                                      | No seats left, at create or at redeem          |
| `ORG_INVITE_NOT_ALLOWED`                                  | Not permitted to invite into that organization |
| `ORG_DISABLED`                                            | The organization is disabled                   |
| `ORG_SLUG_TAKEN`                                          | Slug collision while founding an organization  |
| `USER_BANNED`                                             | Banned accounts cannot redeem                  |

---

## Database schema

**`invite`** holds the token hash (unique), type, kind, email, roles, org bindings, denormalized inviter fields, expiry, use counts, and revocation details. Status is only `pending`, `accepted`, or `cancelled`; expired is derived.

**`inviteUse`** is an append-only audit table: one row per redemption.

**`organization`** gains `seatLimit` and `disabledAt` when org features are enabled.

A Prisma example lives in [`examples/prisma`](./examples/prisma).

---

## Roadmap

- **Runtime sign-up backstop for invite-only mode.** A `user.create` database hook that rejects any user creation not originating from this plugin's own flows (or the admin plugin), so sign-up paths the mode detection cannot see (magic link, email OTP, passkey, phone number, anonymous, generic OAuth) are blocked at runtime instead of by configuration discipline alone. Until this lands, closing those paths is the developer's responsibility.

- **A `better-enrollment` skill on [skills.sh](https://skills.sh).** An Agent Skill that teaches coding agents how to install the plugin, pick the right mode, wire up delivery, and build the invite page, so adding Better Enrollment to a project is a one-prompt job.

- **A changelog blog on the [docs site](https://better-enrollment.octopi.ai).** Versioned release notes for every Better Enrollment release: what changed, why, and any migration steps, so you can upgrade with confidence instead of diffing the source. Until it lands, [GitHub releases](https://github.com/OctopiAI/better-enrollment/releases) are the record.

Have an idea or found a problem? [Open an issue](https://github.com/OctopiAI/better-enrollment/issues).

## License

MIT
