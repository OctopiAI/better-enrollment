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
  <a href="https://better-enrollment.octopi.ai">Documentation</a>
  ·
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

## How it works

Better Enrollment runs in one of two modes, auto-detected from your config: **invite-only** (every sign-up route is closed, invitations are the only way in) or **open** (normal sign-up, invites grant roles and organization membership). See [The two modes](https://better-enrollment.octopi.ai/docs/modes).

**Private invites** are bound to one email. Creating one pre-creates an inert, unverified user, which locks that address on every path (sign-in, sign-up, password reset, OAuth linking) without revealing that the invite exists. The link is emailed by your `sendPrivateInvitation` and never shown to its creator, so the token only ever exists in the recipient's mailbox. Redeeming it sets their password and marks the email **verified**: presenting the token is proof of mailbox access.

**Public invites** are shareable links with a use cap. Nothing is pre-created; the accepter types their own email at redemption, and since holding a shared link proves nothing about a mailbox, the account is created **unverified**. The plugin then sends Better Auth's standard verification email (when `sendOnSignUp` or `requireEmailVerification` is configured), and the user verifies by clicking it like any other signup.

Redemption never creates a session. After redeeming, the user signs in through your normal flow with the credentials they just set:

```ts
await authClient.invite.redeem({ token, password, email });
await authClient.signIn.email({ email, password });
```

> **Recommended.** Keep `requireEmailVerification: true` in your `auth.ts` unless you want unverified users signing in. With it, a public-invite accepter cannot sign in until they click the verification link; private-invite accepters are already verified by the invite itself.

```ts
export const auth = betterAuth({
  emailVerification: {
    sendVerificationEmail: async ({ user, url }) => {
      await sendEmail(user.email, "Verify your email", url);
    },
    sendOnSignUp: true // also fires for public-invite redemptions
  },
  emailAndPassword: { requireEmailVerification: true }
});
```

Tokens are crypto-random and stored SHA-256 hashed, every state change is a guarded atomic write (parallel redemptions of a one-seat invite produce exactly one winner), and expiry is derived at read time, so there is no cron and nothing to sweep. Details in [How it works](https://better-enrollment.octopi.ai/docs/how-it-works) and [Security](https://better-enrollment.octopi.ai/docs/security).

> **Role changes made outside this plugin do not merge.** Better Auth stores multiple roles as one comma-separated string, and only invite redemption merges into it as a union. A bare `setRole({ role: "admin" })` silently strips invite-granted roles; always send the full set. See the [recipe](https://better-enrollment.octopi.ai/docs/recipes#changing-roles-without-losing-invite-granted-ones).

---

## Installation

```bash
npm install @octopi-ai/better-enrollment
```

Requires `better-auth >= 1.4.0` and `zod >= 4`.

Add the plugin to your `betterAuth` config (this example is a fully closed app) and your auth client, then migrate:

```ts
// auth.ts
import { betterAuth } from "better-auth";
import { admin } from "better-auth/plugins";
import { betterEnrollment } from "@octopi-ai/better-enrollment";

export const auth = betterAuth({
  emailAndPassword: { enabled: true, disableSignUp: true },
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

```ts
// auth-client.ts
import { createAuthClient } from "better-auth/react";
import { betterEnrollmentClient } from "@octopi-ai/better-enrollment/client";

export const authClient = createAuthClient({
  plugins: [betterEnrollmentClient()]
});
```

```bash
npx @better-auth/cli migrate # creates the invite and inviteUse tables
```

> **Role field required.** Invited roles live in a string `role` field on your user model, and the default admin gate reads it. The admin plugin provides one, or add it via `user.additionalFields`; otherwise gate management with `adminUserIds` or `canManageInvites`.

Full walkthrough: [Quick Start](https://better-enrollment.octopi.ai/docs/quick-start).

---

## Invite kinds and delivery

Two choices define every invite: what it grants (`kind`) and how it travels (`type`).

| Kind            | Grants                                 | Who may create it                                |
| --------------- | -------------------------------------- | ------------------------------------------------ |
| `app` (default) | Access to the app                      | App admins                                       |
| `org-join`      | Membership in an existing organization | That org's members with `invitation: ["create"]` |
| `org-create`    | Founding and owning a new organization | App admins                                       |

|                          | Private                                 | Public                                   |
| ------------------------ | --------------------------------------- | ---------------------------------------- |
| Bound to                 | One email address                       | Nobody                                   |
| Uses                     | Always exactly 1                        | `maxUses`, or unlimited when `null`      |
| Delivery                 | Emailed by your `sendPrivateInvitation` | A link you distribute                    |
| Link visible to creator  | **Never**                               | Yes, returned once                       |
| Email verified on accept | Yes                                     | No, unless `autoVerifyPublicInviteEmail` |

No email delivery? Use a public invite with `maxUses: 1`. There is deliberately no option to reveal a private link, because possession of one is proof of mailbox access.

```ts
// Private: emailed, single use
await auth.api.createInvite({
  body: { type: "private", email: "ada@example.com", name: "Ada", role: "user" },
  headers
});
// -> { inviteId, expiresAt }

// Public: a capped shareable link, returned once
await auth.api.createInvite({
  body: { type: "public", role: "user", maxUses: 50 },
  headers
});
// -> { inviteId, expiresAt, token, url }
```

Org invites (`org-join`, `org-create`), inviting existing accounts, and every field: [Invites](https://better-enrollment.octopi.ai/docs/invites).

---

## The invite page

Every invitation link points at the same page, carrying only `?token=`. The page calls `invite.get`, renders what `nextAction` says, and submits everything to `invite.redeem`; it never needs to know the invite kind or the mode.

| `invite.nextAction` | Meaning                       | What to render                               |
| ------------------- | ----------------------------- | -------------------------------------------- |
| `SIGN_UP`           | Invite-only, no session       | The fields listed in `requiredFields`        |
| `SIGN_IN`           | Open mode, no session         | Your sign-in form; keep the token in the URL |
| `CONFIRM`           | Open mode, session present    | A single confirm button                      |
| `null`              | Expired, revoked, or consumed | A clear terminal message                     |

```ts
const { data: invite } = await authClient.invite.get({ token });

await authClient.invite.redeem({ token, password, name, email });
// -> { action: "ACCEPTED", organization? }

await authClient.signIn.email({ email, password });
```

`invite.get` returns a deliberately thin payload: kind, role, derived status, expiry, uses remaining, and a masked email. Never the inviter's identity or internal ids. Full rendering guide: [The invite page](https://better-enrollment.octopi.ai/docs/invite-page).

---

## Organizations

Org features switch on when the organization plugin is detected. Pass the same `ac` and `roles` objects you gave the org plugin:

```ts
plugins: [
  admin(),
  organization({ ac, roles }),
  betterEnrollment({
    organization: { ac, roles, defaultOrganizationRole: "member", defaultSeatLimit: 10 }
  })
],
```

- **Seat limits** resolve `resolveSeatLimit(org)` → `seatLimit` column → `defaultSeatLimit` → unlimited. Seats used = members + pending invite reservations, enforced at creation and again at redemption.
- **Platform controls** (app-admin only): disable, enable, and delete organizations; `banMembers: true` bans every member app-wide for fraud takedowns.
- **Org sovereignty**: app admins deliberately cannot create `org-join` invites; only the org invites into itself.
- Setting the active organization after an org invite is your app's job, at sign-in or via a switcher.

Permissions table, seat math, and platform controls: [Organizations](https://better-enrollment.octopi.ai/docs/organizations).

---

## API

```ts
// Redemption, for the invite page
authClient.invite.get({ token });
authClient.invite.redeem({ token, ... });

// Management (admin- or org-gated)
authClient.invite.create({ ... });
authClient.invite.list({ ... });
authClient.invite.resend({ inviteId }); // rotate the token, invalidate the old link, redeliver
authClient.invite.revoke({ inviteId });
authClient.invite.delete({ inviteId });

// Organization administration
authClient.invite.org.usage({ organizationId });
authClient.invite.org.setSeatLimit({ organizationId, seatLimit });
authClient.invite.org.disable({ organizationId, banMembers? });
authClient.invite.org.enable({ organizationId });
authClient.invite.org.delete({ organizationId, banMembers? });
```

Server-only, never mounted as HTTP routes: headless invite creation for cron jobs and system integrations, plus batched cleanup for your scheduler.

```ts
await auth.api.createSystemInvite({
  body: {
    type: "private",
    email: "ada@example.com",
    inviter: { name: "Billing", email: "billing@acme.com" } // optional
  }
});

const { deleted } = await auth.api.cleanupExpiredInvites();
```

> **Trusted server code only.** `createSystemInvite` skips authentication and the admin gate; whoever can call it can mint invites for any role. Keep it in code paths you fully control, never behind a client-reachable route, and never forward unvalidated client input into it. It also thins the audit trail: system invites store a null `createdByUserId` and a self-declared inviter.

Every method, payloads, and rate limits: [API reference](https://better-enrollment.octopi.ai/docs/api).

---

## Options

```ts
betterEnrollment({
  mode: "auto", // "auto" | "invite-only" | "open"
  sendPrivateInvitation,
  sendPublicInvitation,
  validRoles: ["user", "admin"],
  defaultRole: "user",
  expiresIn: 60 * 60 * 24 * 7,
  adminRoles: ["admin"],
  buildInviteUrl,
  organization: {/* ... */},
  onInviteCreated,
  onInviteAccepted,
  onInviteRevoked /* ... */
});
```

Every option with its default: [Options](https://better-enrollment.octopi.ai/docs/options).

---

## Security

While a private invite is pending, its email is locked on every path with no oracle: sign-up is disabled, sign-in fails naturally, password reset returns a byte-identical silent success, and OAuth linking is blocked. Accepted invites are permanent audit records; revoking keeps the lock, deleting frees the address.

The full block table, the email-lock semantics, and token storage: [Security](https://better-enrollment.octopi.ai/docs/security). Report vulnerabilities privately to [talat@octopi.ai](mailto:talat@octopi.ai).

---

## More

- [Error codes](https://better-enrollment.octopi.ai/docs/errors): every `APIError` code the plugin returns.
- [Database](https://better-enrollment.octopi.ai/docs/database): the `invite` and `inviteUse` tables, every column and index, plus a [Prisma example](./examples/prisma).
- [Recipes](https://better-enrollment.octopi.ai/docs/recipes): captcha, breached-password checks, custom URLs, role-change patterns.
- [Operations at scale](https://better-enrollment.octopi.ai/docs/operations): batched cleanup, bulk org operations, composite indexes, shared rate limits.
- [Roadmap](https://better-enrollment.octopi.ai/docs/roadmap): runtime sign-up backstop, an Agent Skill.
- [Releases](https://github.com/OctopiAI/better-enrollment/releases): the changelog, with migration notes per version.

Have an idea or found a problem? [Open an issue](https://github.com/OctopiAI/better-enrollment/issues).

## License

MIT
