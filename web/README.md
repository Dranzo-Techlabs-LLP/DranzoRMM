# DranzoRMM web dashboard

React + TypeScript (strict) + Vite single-page app for technicians. It talks to the server's dashboard listener
(`/api/v1/*` REST and the `/hubs/live` SignalR hub) and is served from the same origin as the API.

Scope so far: Phase 0 and Phase 1 (sign-in with mandatory two-step sign-in, organizations / sites / groups,
enrollment tokens, device list and detail, users and roles, audit log).

## Requirements

- Node 22 or newer (developed on Node 26, npm 11).
- The server running on `http://localhost:8080` (see the repository root for how to start it).

## Run

```sh
npm ci
npm run dev        # http://localhost:5173, proxies /api and /hubs (WebSocket) to http://localhost:8080
```

Set `DRANZO_API_URL` to proxy to a server somewhere else, for example
`DRANZO_API_URL=http://localhost:9090 npm run dev`.

Sign in with the bootstrap administrator the server was started with. The first sign-in asks you to set up an
authenticator app; there is no way to skip it. For local development without a phone, `scripts/dev-totp.mjs` prints
the current code for a secret:

```sh
node scripts/dev-totp.mjs <base32 secret shown under the QR code>
node scripts/dev-totp.mjs <secret> --next   # wait for the next 30-second window first
```

The server accepts each code once, so a step-up prompt right after signing in needs `--next`. Never use this script
with a real account's secret.

## Check

```sh
npm run lint        # ESLint (type-aware, jsx-a11y), zero warnings allowed
npm run typecheck   # tsc -b --noEmit
npm run test        # Vitest + Testing Library (jsdom)
npm run build       # type-check, then production build into dist/
npm run preview     # serve dist/ on http://localhost:4173 with the production CSP and the same proxy
npm run format      # Prettier
```

`npm run preview` is the quickest way to confirm a change still works under the strict Content Security Policy
(`script-src 'self'`, no inline scripts).

## Docker

```sh
docker build -t dranzo-web .
docker run --rm -p 8081:8080 --network <compose network> dranzo-web
```

The image builds with Node and serves the static files with `nginx-unprivileged` on port 8080 (non-root).
`nginx.conf` proxies `/api/` and `/hubs/` (with WebSocket upgrade) to `http://server:8080` and sends the same
security headers and CSP as the server. The CSP is written in three places that must stay identical:
`server/src/Dranzo.Api/DranzoApp.cs`, `nginx.conf` and `vite.config.ts` (preview).

## Layout

```
src/
  app/            App providers, router, page registry, shell (sidebar, top bar), guards, theme, organization filter
  lib/api/        Typed API client: errors, CSRF, step-up, 401 handling, endpoint functions, query keys, types
  lib/auth/       Session (GET /auth/me), permissions
  lib/live/       SignalR connection and cache updates for device events
  features/<area> One folder per page area: auth, overview, organizations, devices, enrollment, admin, audit
  components/ui/  shadcn/ui components (Radix + Tailwind)
  components/     Shared building blocks: page header, panels, loading/empty/error states, status, dialogs
  test/           Test setup, fetch mock, render helper
```

### Adding a page

`src/app/pages.ts` is the one place that defines navigation and routes. Later-phase pages (Scripts, Jobs, Software,
Patches, Security, Alerts, Remote, Policies, Reports) are already listed there without a `load` function, which keeps
them out of the sidebar and the router. To turn one on, build the page component with a default export and add
`load: () => import('@/features/<area>/<Page>')` to its entry. The sidebar link, route, permission gate and tab title
follow from that entry.

Device detail tabs work the same way: add an entry to `src/features/devices/tabs/registry.ts`.

## How the client handles the session

- **Cookie session.** The session token is an HttpOnly cookie; the app never sees it. Requests use
  `credentials: 'same-origin'`.
- **CSRF.** `GET /auth/me` (and the MFA responses) return a CSRF token that is kept in memory only. The API client
  adds it as `X-CSRF-Token` to every POST / PUT / PATCH / DELETE, and to the SignalR negotiate request. If the server
  answers `403 csrf`, the client refreshes the token once and retries.
- **Step-up.** When any call is answered `401 step_up_required`, the API client opens the "Confirm it is you" dialog,
  calls `POST /auth/step-up`, and retries the original request exactly once. Concurrent requests share one dialog.
  Features do not need to do anything.
- **Session loss.** `401 unauthenticated` from any call clears all cached data and sends the user to `/login` with
  the current URL as `returnTo` (same-origin paths only). After an explicit sign-out there is no `returnTo`.
- **Temporary passwords.** If `/auth/me` says `mustChangePassword`, or any call is answered
  `403 password_change_required` (an administrator reset the password while the tab was open), every page redirects
  to Account until the password is changed.
- **Uploads.** Raw-body uploads (agent releases, remote file transfer) use `lib/api/upload.ts` (XMLHttpRequest for
  progress) with the same cookie, CSRF header and step-up retry as the API client.
- **Permissions.** Navigation, pages and action buttons are hidden when `/auth/me` shows the user lacks the
  permission. This only avoids dead ends; the server enforces everything.
- **Storage.** Nothing secret is stored in the browser. `localStorage` holds three UI preferences
  (`dranzo.theme`, `dranzo.sidebar`, `dranzo.org`); ESLint forbids using web storage anywhere except `lib/prefs.ts`.
- **Output encoding.** Server-provided strings are always rendered as text. ESLint rejects
  `dangerouslySetInnerHTML`. The TOTP QR code is drawn as SVG from the module matrix.

## Live updates

`LiveProvider` connects to `/hubs/live` when the user holds `devices.read`. A `device` event patches the matching row
in every cached device list and the cached device detail straight away, then (at most once every 1.5 seconds)
refetches device lists and per-organization counts. The top bar shows whether the connection is live; lists also
refetch every 60 seconds as a fallback. An `alert` event refetches alert lists and the open-alert count in the
navigation. Features reach the connection through `useLive().client` (`on`, `invoke`) for their own events.

## Remote sessions

A device page owns its sessions (`features/remote/RemoteSessions.tsx`): starting needs step-up, then the page calls
`JoinSession` and follows `sessionState` events (with `GET /sessions/{id}` polling as a fallback) through a pure
reducer (`session-machine.ts`). Terminal bytes travel base64 in both directions and are written to xterm.js as bytes.
Leaving the device page ends any open session; a reload does not resume one (the page offers to end the leftover).
The consent text shown before starting comes from the organization's consent mode; the on-screen indicator is always
described, since every mode shows it.

## Design notes

- Type: Atkinson Hyperlegible Next and Atkinson Hyperlegible Mono (self-hosted through `@fontsource-variable`, so
  no third-party requests). The mono face is used for machine identifiers (hostnames, serials, tokens, hashes) because
  it keeps `0`/`O` and `1`/`l`/`I` apart.
- Colour is reserved for state. Every status also has a distinct shape and a text label (online: solid disc,
  offline: hollow ring, revoked: barred circle; offline share in bars is hatched), so nothing depends on colour alone.
- Tokens live in `src/index.css` (light and dark). Theme choice is light / dark / match system;
  `public/theme-init.js` applies it before first paint as an external script (the CSP forbids inline scripts).
