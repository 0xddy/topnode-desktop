# Architecture

## Dependency map

    apps/desktop
      -> application
      -> infrastructure -> application
      -> domain         -> domain

The desktop app is the composition root. Slint-generated types stop there.
Domain and application contracts do not know how windows, HTTP, credential
vaults, files, or processes are implemented.

## Workspace responsibilities

Windows selects Slint's Winit software renderer by default to keep startup and
login surfaces visible in remote sessions and native capture. An explicit
`SLINT_BACKEND` setting retains its override. Other platforms keep Slint's
default selection. Shared buttons use solid fills so rounded corners render
consistently. The frameless login page owns configuration discovery and update
prompts. The same window and custom window controls remain in use after login.
Large node and checkout dialogs reserve space below these controls while their
backdrops cover the full window.

Static icons are SVG assets drawn through `Image`, with `colorize` retaining
their theme and state colours. Slint 1.17.1's software path drawing does not
restrict its writes to dirty regions like texture drawing does; this allowed
hidden `Path` icons to bleed over dialogs during partial repaint. Keep icons
on the image path until that upstream behaviour is fixed and verified. The
desktop rendering regression compares reused-buffer frames after pointer
movement with a full redraw of the same UI state. Country flags choose either
their image or a fallback glyph, never both under a translucent node card.

Shared buttons, navigation items, mode selectors, and settings switches expose
accessible actions and keyboard focus. Update, logout, and subscription-reset
confirmations keep Tab navigation inside the dialog. Updates initially focus
the dialog itself without highlighting a button; logout and subscription reset
focus their secondary action. Escape dismisses optional confirmations;
mandatory updates continue to require upgrade or exit.

`SmoothCard` gives shared surfaces, subscription plans and node cards a uniform
1px outline. Individual SVG corner assets render at the displayed corner size;
only straight edges stretch. This avoids the software renderer's coarse rounded
border coverage and integer truncation of a selected card's former 1.5px border.
Native fills, shadows and clipping remain in place. Use `outline-color` and
`outlined` to customize these borders. Navigation uses its fill and left marker
for selection, with a muted fill for keyboard focus and no focus outline.

### `crates/domain`

- `ConnectionState`, `StopReason`, and connection lifecycle types.
- Aggregate-only `RuntimeTelemetrySnapshot` values; per-connection destination
  metadata never enters presentation state.
- `ConnectionPreferences` and route-mode invariants.
- User/session, server-group, entitlement, and node models. Endpoint IDs remain
  opaque strings rather than being reinterpreted by the client.
- `RuntimeId`, `RuntimeDescriptor`, `EngineCapabilities`, and
  `ConnectionEngine`.
- `RuntimeConfiguration`, whose server JSON payload is opaque and redacted from
  debug output while carrying the preferences and entitlement expiry needed at
  the engine boundary.

### `crates/application`

- `PanelRepository` defines restore, login, logout, and resource operations.
- `PanelCoordinator` serializes account operations and publishes explicit
  restoring, signed-out, authenticating, resource-loading/refreshing, ready,
  and failed states.
- `ConfigurationSource` obtains the selected node's runtime configuration.
- `ConfigurationRequest` carries the Android contract's group, opaque endpoint
  ID, preferences, runtime ID, and supported schema versions.
- `ConnectionCoordinator` serializes fetch, validate, start, and stop
  operations, propagates a generation-scoped cancellation signal through every
  awaited startup stage, and stops a running sidecar when its configuration
  entitlement expires.

### `crates/infrastructure`

- `AppPaths` resolves the immutable
  `current_exe().parent()/runtime/core/sing-box[.exe]` path and writable OS
  application-data paths.
- `SettingsStore` persists non-secret preferences, selections, and the stable
  installation device ID.
- The cold-start transport adapter owns ordered bootstrap loading, document
  validation, Android-compatible endpoint racing, and direct/fronted route
  construction. It exposes only the winning reusable Panel route; it never
  persists a remote bootstrap document or supplies a fixed API fallback.
- `HttpPanelClient` is both `PanelRepository` and `ConfigurationSource`. Under
  the cold-start contract it uses the winning logical endpoint and exact
  transport route, rejects redirects and proxy discovery, preserves WebPKI and
  pin validation, parses the Panel envelope, and performs mutex-protected token
  refresh with one authenticated-request replay.
- `SessionVault` stores a random 256-bit data-encryption key in the platform
  credential vault and atomically writes the session as a versioned,
  authenticated XChaCha20-Poly1305 envelope at `auth/session.v1.bin`. Missing
  or corrupt key/envelope pairs are cleared rather than treated as a usable
  session.
- The engine-boundary normalizer applies the tested Android-compatible local
  sing-box transformations. In normal proxy mode it replaces server-provided
  Mixed/SOCKS listeners with one private Mixed listener on an OS-assigned IPv4
  loopback port; TUN mode has no local system-proxy listener. UI and application
  code never rewrite the server-provided JSON.
- `SingBoxSidecar` owns normalization, private Clash-controller injection,
  in-memory configuration checking and launch, authenticated readiness,
  mode-specific traffic readiness, aggregate telemetry, process lifecycle,
  output draining, and lifecycle-state publication.
- `SystemProxyManager` owns the recoverable proxy transaction. Its Windows
  WinINet backend snapshots flags, manual proxy/bypass, PAC, auto-detection and
  auto-discovery state; a private atomic journal records `Prepared` or `Active`
  plus an owner UUID. Apply and restore are queried back, and restore occurs
  only when the observed settings still equal the owned snapshot. Startup
  reconciliation resolves each crash point before core probing or account
  restoration. Non-Windows backends currently return `Unsupported`.
- `InstanceGuard` owns the operating-system single-instance lock;
  `InstanceActivation` is its authenticated IPv4-loopback wake-up channel. A
  second `instance-handoff.lock` remains owned by the old process throughout a
  UAC replacement, so an unrelated launch cannot take the primary lock during
  the transfer. A replacement may pre-bind its activation listener, but it
  publishes the new discovery record only inside the reversible commit stage,
  before `FINAL`; an abort restores the old primary's record. Once `FINAL` is
  accepted, acquisition of the handoff gate retries in the background and
  cannot terminate the committed replacement.
- `ProcessContainmentGuard` installs a Windows Job Object with
  `KILL_ON_JOB_CLOSE`. On Unix and macOS, `sidecar_guardian` is an internal mode
  of the same desktop executable: it supervises the long-lived core in its own
  process group and kills that group when the GUI parent disappears.
- `DevelopmentConfigurationSource` remains available for isolated development
  and tests, but the desktop composition root no longer uses it by default.

### `apps/desktop`

- `bootstrap.rs` acquires single-instance ownership, loads the packaged
  payment-presentation fallback, and resolves the reusable remote Panel route
  before constructing the client. It then wires the encrypted session vault,
  coordinators, sidecar, Slint window, and native system tray. `startup.rs` shows
  the login page before network discovery starts, then hosts update
  overlays or retry feedback in that same window. Retry repeats the complete
  ordered discovery sequence. Closing the page cancels pending discovery. Startup also
  reconciles a stale system-proxy journal before probing the core or enabling login.
- `controller.rs` translates UI intents into account and connection use cases,
  reconciles resource selections, persists non-secret settings, and performs
  the first TUN permission gate.
- `platform/elevation.rs` implements the Windows UAC handoff. A fixed-argument
  hidden launcher explicitly breaks away from the old containment Job before
  invoking UAC. The authenticated replacement verifies elevation, acquires the
  primary lock, and preflights the controller, window, tray, and activation
  channel. The old instance closes only after the replacement has persisted the
  committed preference and acknowledged it; abort paths restore the original
  settings and primary lock. UAC cancellation leaves both unchanged.
- `presentation.rs` maps domain snapshots onto Slint properties on the UI event
  loop.
- `ui` contains declarative login/signed-in states, resource-group
  and node views, subscriptions, purchase, profile, settings, and callbacks. Callbacks never perform
  blocking I/O directly.

## Cold-start bootstrap and payment-presentation flow

The bootstrap implementation follows this flow before any login request:

    launch
      -> acquire single-instance ownership and initialize activation routing
      -> load local runtime/startup.json payment.presentation default
      -> show frameless login page; read opted-in inputs from the OS credential store
      -> GET https://0x10.topboot.top/desktop.config.json
         -> invalid/unreachable -> GET https://0x11.boot1.top/desktop.config.json
         -> invalid/unreachable -> GET https://0x12.boot2.top/desktop.config.json
      -> accept the first structurally valid document
      -> validate baseApiServer, fake, apiProbe, version, optional website and payment
      -> compare remote versionCode with the Git-derived desktop versionCode
         -> newer version -> update overlay on login page before API probing or login
            -> upgrade -> use downloads[current target], else download.url
                       -> open selected URL; keep app and prompt available
            -> optional defer -> continue startup
            -> required update -> upgrade or exit; keep login disabled
      -> apply remote payment.presentation over the local default when present
      -> build direct and fake-fronted route candidates
      -> probe every valid baseApiServer route concurrently
      -> first TLS-complete candidate returning any HTTP response wins
      -> cancel every remaining probe
      -> reuse the winning route for all Panel traffic
      -> enable the login button; remain on the same login page
      -> saved auto-login inputs, no update and no user edit -> wait 2 seconds -> submit login
      -> otherwise wait for a manual login

Bootstrap source requests are strictly sequential; API route probes begin only
after one source has supplied a valid document and any startup update prompt has
been handled. Every launch displays the login page; stored session tokens never bypass it. About-page manual update checks fetch metadata without probing the API.
An HTTP 404 or 500 response is
enough to win an API probe, while DNS, connect, TLS, and timeout failures are
not. If all bootstrap sources fail, or if no route from the accepted document
wins, the login page shows retry feedback and keeps login disabled. Retry and any later launch start
again from the first source. It does not try a fixed API, a later bootstrap
source after accepting a valid document, or a cached/packaged remote document.

When `fake` is absent or `fake.enable=false` (the current deployment), the
logical `baseApiServer` host remains the connection target, TLS identity, and
HTTP authority. With `fake.enable=true`, each exact
`real.domain` match produces a candidate that connects to the literal
`real.ip`, sends `fakeSNI`, verifies the peer certificate for the logical
domain plus `real.pk`, and sends the logical domain as the HTTP authority.
Unmatched hosts remain direct candidates; a host with one or more matches uses
only those fronted candidates. The selected candidate's connection IP, SNI,
logical certificate identity, authority, and pin policy are retained by
`HttpPanelClient`; probing and authenticated requests therefore cannot take
different routes.

The remote `version` object keeps the Android-compatible singular `download`
for structural/older-client compatibility and adds a `downloads` map keyed by
the exact Rust target triple. A strict `remote.versionCode > local.versionCode`
comparison may open only that target's HTTPS `Browser` entry. An unmatched target uses the legacy download URL. There is no downgrade or
in-process installer. UAC successors complete their authenticated handoff before
presenting optional updates and enabling login. The only remote payment setting is optional
`payment.presentation = qr_code|browser`; it overrides the read-only local
default from `runtime/startup.json`. It is a UI policy, not a payment-method
catalog. Once authenticated, the existing shop-catalog path continues to load
available methods from `GET /api/v1/users/payment-methods`, as the Web and
Android clients do. Merchant IDs, gateway secrets, signing keys, and provider
configuration remain exclusively on the Panel and are invalid content for a
public bootstrap document.

## Account and Panel flow

    launch (including an internal elevation restart)
      -> SignedOut, with login disabled during configuration discovery
      -> read explicit auto-login consent and inputs from the OS credential store
      -> no opted-in inputs -> manual login
      -> opted-in inputs + no update + no user edit -> wait 2 seconds -> POST auth/login

    login
      -> POST auth/login
      -> atomically persist encrypted session
      -> GET users/client/resources
      -> user selects a node for this run

    open or refresh shop catalog
      -> authenticated GET users/shop/plans
      -> authenticated GET users/payment-methods
      -> validate the public display fields and publish available methods

    authenticated request receives HTTP 401
      -> single-flight POST auth/refresh
      -> persist rotated token pair
      -> replay original request once
      -> second 401 / failed refresh -> clear session

    logout
      -> publish SignedOut and clear local session
      -> best-effort POST auth/logout

Every request has a generated request ID. Panel business errors are separated
from HTTP/transport errors, and a successful envelope must contain `data`.
Session tokens and passwords have redacted debug representations and are never
stored in the TOML settings file.

## Configuration and connection flow

    selected group + node + preferences
      -> POST users/client/config
      -> validate runtime_id=rt1 and schema version 1
      -> keep server configuration opaque
      -> normalize at the sing-box boundary
      -> replace any server controller with a random authenticated loopback API
      -> keep the exact normalized bytes in zeroizing memory
      -> pipe those bytes to sing-box check -c stdin
      -> if TUN is enabled:
           require the second, engine-boundary privilege check before spawn
      -> pipe the same checked bytes to sing-box run -c stdin
      -> authenticated GET /version reports the exact release-selected sing-box version
      -> if TUN is disabled:
           wait for the random 127.0.0.1 Mixed listener
           write Prepared proxy journal
           apply complete Windows WinINet snapshot and query it back
           promote journal to Active
      -> publish Connected and aggregate /connections telemetry

The configuration request sends `group_id`, `selected_endpoint_id`,
`route_mode`, `bypass_mainland`, `bypass_lan`, `ipv6=true`,
`multiplex_enabled`, `runtime_id=rt1`, and
`supported_schema_versions=[1]`. IPv6 is enabled so the Panel does not force
IPv4-only DNS resolution or remove IPv6 TUN addresses. Node domain resolution
follows the server template (normally `prefer_ipv4`, which also permits
AAAA-only nodes). UDP is not sent to the Panel.

The normalizer always starts from the original server payload so toggling a
preference cannot retain an earlier locally injected rule. Its scoped policy
is:

- remove detour references to empty direct outbounds;
- add/remove the canonical LAN private rule-set definitions and local direct
  routes according to LAN bypass;
- add the local direct UDP rule when UDP forwarding is disabled;
- enable or remove multiplex only on generated VLESS outbounds whose tags begin
  with `tn-endpoint-`;
- remove every server-selected Mixed/SOCKS listener and its now-invalid
  references, then add exactly one client-owned random loopback Mixed listener
  when TUN is disabled; add no system-proxy listener when TUN is enabled.

The server document remains opaque everywhere above this adapter. The
normalized configuration never needs a new plaintext runtime file: the pinned
binary checks and launches the same in-memory byte sequence through standard
input. Legacy candidate/session files from earlier builds are removed before a
connection attempt; a cleanup failure blocks startup.

## Connection lifecycle

    Disconnected
       -> Preparing
       -> Validating
       -> Starting
       -> Connected
       -> Stopping
       -> Disconnected

Validation, launch, I/O, timeout, and unexpected-exit failures publish
`Failed`. A Tokio mutex gates every user action so rapid clicks cannot create
overlapping sidecars. Slint observes watch snapshots and is never the source of
truth. An OS file lock ensures only one GUI instance can own the shared
sidecar and runtime files. Node and group selection is mutable only while the
connection is disconnected or failed.

Logout, session invalidation, disconnect, and application shutdown synchronously
cancel the active generation before waiting for the operation gate. The same
signal interrupts Panel configuration fetch, `sing-box check`, configuration
stdin delivery, authenticated readiness, and Mixed-listener readiness. A child
spawned during an incomplete start is killed as a process group (or Windows
process) and reaped before cancellation returns.

Each successful connection generation owns an entitlement-expiry task derived
from the Panel's `expires_at` value. Expiry stops that exact generation with
`EntitlementExpired`; reconnect and disconnect cancel stale tasks. Losing the
authenticated account session likewise disconnects the sidecar.

In normal Windows mode the sidecar is not declared connected until its private
controller and random Mixed listener are ready and the WinINet lease has been
applied and verified. Disconnect and explicit application exit compare the
observed settings with the lease before restoring the original snapshot; a
mismatch preserves the external owner's settings. If restore fails, the live
lease and child are retained for retry rather than creating a dead proxy. An
unexpected process exit attempts the same restoration, and the next startup
reconciles any remaining `Prepared` or `Active` journal before continuing.

The Settings UI calls the default path **System Proxy mode** and the TUN-backed
path **Global mode**. Routing preferences such as mainland/LAN bypass remain
independent of that capture-mode choice and apply in either mode. Selecting
Global mode on Windows requests a UAC restart, and only the elevated replacement
saves the internal TUN preference after it owns the single-instance lock and
receives the authenticated commit. The old instance retains a separate handoff
lock until its process actually exits; the replacement waits for that lock
before entering its Slint event loop. This prevents both a third process from
stealing ownership and the old containment Job from killing the new process.
Connect checks permission again in the controller, while `SingBoxSidecar`
repeats the check immediately before spawn; either failure blocks startup. The
current implementation elevates the entire Windows GUI as a temporary safety
tradeoff. A narrow privileged broker is the intended long-term boundary. Linux
and macOS system-proxy integration and TUN permission handling are not
implemented and fail closed.

Telemetry polling keeps only totals, rates, memory, and an active count;
connection details are discarded during deserialization.

Closing the main window hides it and leaves the event loop, tray, controller,
and sidecar alive. A later executable launch only wakes and restores that
window. Explicit tray exit ends the event loop and then awaits sidecar shutdown.
The internal Unix guardian dispatch occurs before bootstrap and the
single-instance lock, so it is never mistaken for a second GUI instance and
does not add another distributable binary.

## Deliberately unfinished boundaries

- Node latency tests and runtime node switching.
- A narrowly privileged TUN broker that lets the Windows GUI return to an
  unprivileged token instead of remaining Administrator for the TUN session.
- Linux and macOS system-proxy ownership and TUN permission adapters.
- Signed updates, platform installers, and release hardening.

Android-only application package routing is intentionally absent. Desktop TUN
and system-proxy support remain capability-specific platform adapters rather
than pretending Android package routing works across operating systems.

## Explicit auto-login inputs

`AutoLoginStore` uses a separate versioned OS credential entry for email and
password. An absent entry means auto-login is off. Only successful authentication
can replace it; failed login never overwrites a working saved credential. Invalid
stored entries are cleared, and storage failure leaves manual login available.
Credentials and serialized secret buffers are redacted from Debug and zeroed on
drop; neither field is written to TOML, logs, or command-line arguments.

Configuration and saved-input loading run while the login window is visible.
The two-second countdown starts after discovery, API selection and controller
preflight finish. Manual input, unchecking auto-login or discovering an update
cancels it. Discovering an update disables auto-login for that launch even after
an optional defer; the user can log in manually. Failed auto-login is not retried
in a loop. Unchecking, explicit logout and successful password change remove
saved inputs. The existing encrypted token vault remains for authenticated
request refresh, but application startup no longer restores it.
