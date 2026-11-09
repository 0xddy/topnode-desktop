# TOPNODE Desktop

TOPNODE Desktop is a cross-platform Rust + Slint client. The UI is written in
Slint's declarative language with the Fluent widget style; Rust owns account
state, Panel communication, persistence, and the external sing-box process.

The current framework connects the desktop shell to the real Panel and
implements the authenticated resource-to-runtime path, single-instance desktop
lifecycle, a supervised sing-box sidecar, and Windows traffic takeover. The
user-facing **System Proxy mode** is the default: it starts a private Mixed
listener and transactionally points the current user's WinINet proxy at it only
after both the sidecar and listener are ready. **Global mode** is the
user-facing name for the TUN-based capture path.

## What is included

- A Cargo workspace with domain, application, infrastructure, and Slint UI
  boundaries.
- A Fluent desktop shell with session restore, login/logout, account resource
  loading and refresh, server-group and node selection, subscription purchase,
  personal center and software-settings pages.
- An HTTPS Panel client using the real `auth/login`, `auth/refresh`,
  `auth/logout`, `users/me`,
  `users/client/resources`, `users/client/config`, shop-plan, payment-method,
  and order contracts under `/api/v1/`. The cold-start contract below selects
  the logical Panel endpoint and transport route before this client is used;
  the packaged application does not define a production API fallback.
- Rotating-token handling with one automatic refresh and one request replay
  after an authenticated request receives HTTP 401. Refresh is single-flight;
  logout removes the local session before best-effort remote revocation.
- Session persistence as a versioned XChaCha20-Poly1305 envelope under the OS
  application-data directory. A random data-encryption key is stored in the
  platform credential vault; tokens are not written to `settings.toml`.
- The Android connection-preference model: rule/global mode, mainland/LAN
  bypass, TUN (off by default), UDP forwarding, multiplexing, serialized
  connect/stop operations, and generation-scoped cancellation that interrupts
  configuration fetch, core check, stdin delivery, and readiness without
  waiting for their full timeout.
- An Android-equivalent engine-boundary normalizer for the server's opaque rt1
  JSON. It cleans redundant direct detours, applies LAN private rule sets and
  local direct routes, applies the local UDP-disabled rule, and limits local
  multiplex policy changes to generated VLESS endpoint outbounds. In normal
  proxy mode it removes server-selected Mixed/SOCKS listeners and injects one
  client-owned Mixed listener on a random `127.0.0.1` port; TUN mode does not
  create that listener.
- A sing-box sidecar adapter that discovers the binary under the executable's
  fixed `runtime/core` directory, runs version/check/run without a shell,
  drains both output streams, redacts
  credential-like log lines, and observes unexpected exits. The adapter injects
  a random authenticated loopback Clash API, keeps the normalized configuration
  in zeroizing memory, sends the exact same bytes to `check` and `run` over
  standard input, waits for the exact core version, and publishes bounded
  aggregate traffic, connection-count, and memory telemetry.
- A recoverable Windows WinINet proxy lease. It preserves the complete previous
  flags, manual proxy/bypass, PAC, and auto-detection values in a private atomic
  `Prepared`/`Active` journal with a random owner ID. Apply and restore are
  queried back; disconnect and explicit exit restore only when the current
  settings still match TOPNODE's applied snapshot, so another application's
  changes are never overwritten. Startup reconciles a journal left by a crash
  before normal initialization continues.
- A Windows Global-mode permission handoff. Selecting Global mode from Settings
  requests UAC because that mode uses TUN internally. A fixed-argument hidden
  launcher explicitly leaves the old GUI's containment Job before invoking
  UAC, so orderly shutdown of the old process cannot terminate the elevated
  replacement. The authenticated replacement acquires the single-instance
  lock and preflights its controller, window, tray, and activation channel
  before the old window is allowed to close. The enabled preference is written
  only after the commit message; an abort restores the previous settings.
  Cancelling or rejecting UAC keeps System Proxy mode. Connect performs a
  controller permission check and the sidecar repeats it immediately before
  launch.
- An OS-level single-instance lock. A later launch authenticates to a loopback
  activation channel, restores the existing window, and exits before touching
  settings, credentials, runtime files, or the sidecar. A separate handoff lock
  prevents another launch from taking ownership while an authenticated UAC
  replacement is assuming the primary lock.
- A native Slint system tray: closing the window hides it while the sidecar
  remains supervised; explicit tray exit performs orderly shutdown. Windows
  places the GUI and ordinary children in a kill-on-close Job Object; only the
  fixed internal UAC launcher may explicitly break away. Unix and macOS run the
  long-lived core through a hidden mode of the same desktop executable; that
  guardian reclaims the complete process group when its GUI parent dies.
- OS-specific writable data paths, persisted non-secret settings, 4 MiB
  size-rotated app logs (at most seven files and about 32 MiB total), tests,
  staging scripts, and multi-platform CI configuration.

## Current security and networking boundary

The Panel client requires HTTPS, disables redirects and environment/system
proxy discovery, sends per-request IDs, applies connection/request timeouts,
and rejects responses larger than 8 MiB. The cold-start selection described
below never weakens normal WebPKI chain, hostname, validity, or signature
validation. The configuration request contains:

    group_id
    selected_endpoint_id
    route_mode
    bypass_mainland
    bypass_lan
    ipv6=true
    multiplex_enabled
    runtime_id=rt1
    supported_schema_versions=[1]

IPv6 is enabled in configuration requests so the Panel preserves the template's
DNS strategy and IPv6 TUN addresses. The default `prefer_ipv4` strategy supports
both IPv4 and AAAA-only node domains; IPv6 connections require working IPv6 on
the host network.

UDP is intentionally not a Panel request field. Its local policy is applied
only inside the sing-box adapter. Above that boundary, configuration JSON is
opaque and its debug representation is redacted.

On Windows, `Connected` is published only after the validated sidecar answers
the authenticated loopback `/version` probe with the exact ACP version in
`config/sing-box-acp.lock` and the chosen
traffic path is ready. In the default mode that additionally means the random
Mixed listener accepted a loopback connection and the WinINet lease was applied
and read back. In TUN mode it means both privilege gates passed and the checked
TUN configuration reached authenticated sidecar readiness.

A narrowly privileged TUN broker is not implemented yet. The current Windows
TUN handoff restarts the entire GUI as Administrator; this is an explicit
temporary safety tradeoff, not the long-term privilege boundary. Linux and
macOS system-proxy adapters and TUN permission adapters are also not
implemented, so those modes fail closed rather than reporting a
traffic-capturing connection.

## Cold-start bootstrap contract

The bootstrap implementation performs these steps on every cold start.
Bootstrap sources are requested sequentially in this exact order, and
fetching stops at the first structurally valid document:

1. `https://0x10.topboot.top/desktop.config.json`
2. `https://0x11.boot1.top/desktop.config.json`
3. `https://0x12.boot2.top/desktop.config.json`

A transport, HTTP, size, JSON, or schema failure advances to the next source.
Once a valid document is accepted, later bootstrap sources are not consulted.
There is no fixed Panel API fallback and no cached or packaged copy of a remote
bootstrap document to fall back to. If all three sources fail, startup remains
blocked on a visible error window. Retry repeats the complete discovery
sequence from the first source; Exit closes the client, and a later launch also
starts again from the first source.

The accepted document uses the Android bootstrap semantics. All valid HTTPS
entries in `baseApiServer` are probed concurrently with the configured
`apiProbe` policy. A candidate wins as soon as TLS completes and any HTTP
response is received, including a non-2xx response. DNS, connection, TLS, and
timeout failures do not count as connectivity. The first successful candidate
wins and all remaining probes are cancelled. If no candidate wins, the client
does not fall back to a fixed API, a later bootstrap source, or a remote
configuration saved on disk.

Both direct and `fake` fronted candidates are supported. Direct candidates use
the logical `baseApiServer` host for connection routing, TLS identity, and HTTP
authority. For an enabled `fake` route, an exact `real.domain` mapping connects
to its literal `ip`, sends `fakeSNI` in TLS, verifies the certificate against
the logical domain and configured SPKI pin, and keeps the logical domain as the
HTTP authority. Unmatched logical hosts remain direct candidates, and multiple
matching `real` entries are independent concurrent candidates. A host with a
matching `real` entry does not also add a direct candidate. The winning route,
including connection IP, SNI, certificate identity, HTTP authority, and pin
policy, is reused unchanged by the authenticated Panel client.

The Android-shaped `version` object remains structurally required. Desktop
builds use the same Git-derived identity as Android: the complete-history commit
count is `versionCode`, and `YYYY.MM.DD-<8-char-SHA>` is `versionName`. After a
valid bootstrap and API route are selected, a strictly greater remote
`versionCode` opens the exact current-target entry from `version.downloads` in
the default browser. Entries must use `downType=Browser` and HTTPS. Target keys
are restricted to the six published Rust triples; Windows entries must use
ZIP/application-zip and Linux/macOS entries tar.gz/application-gzip. Equality or
a lower code never triggers an update, and a missing target entry only logs a
warning. The legacy singular `version.download` remains required for older
clients but is never used by the desktop updater, preventing the live Android
APK entry from being opened on desktop. `updateInfo` and `forceUpdate` remain
contract-compatible metadata; desktop currently opens the browser and continues
startup rather than implementing a blocking native updater.

`payment.presentation` is an optional presentation-only policy with the values
`qr_code` and `browser`. When present remotely it overrides the packaged
`runtime/startup.json` default; when absent, the local default remains in
effect. It does not define available payment methods. The desktop already
loads those methods after authentication from
`GET /api/v1/users/payment-methods`, matching the Web and Android clients, and
continues to use the returned method ID when creating or paying an order.
Public bootstrap documents must never contain a payment gateway secret,
merchant credential, signing key, or other provider configuration.
The checked-in `config/desktop-config.json` is a schema example for publishing
that remote document; it is not copied into the application distribution and
editing it does not update any live bootstrap domain. The same document,
including `payment.presentation` when a remote override is desired, must be
published independently to the configured HTTPS sources.

## Prerequisites

- Rust 1.92.0, pinned by the checked-in toolchain file.
- A platform build toolchain supported by Slint/winit.
- Python 3.11+ and the Go version in `config/sing-box-acp.lock` to build and
  package the ACP sidecar. The lock pins the same core revision as Android.

Slint and `slint-build` are pinned to 1.17.1. This version supplies the native
cross-platform `SystemTrayIcon` used by the desktop lifecycle.

## Build and test

From this directory:

    cargo fmt --all --check
    cargo test --workspace
    cargo clippy --workspace --all-targets -- -D warnings
    cargo build -p topnode-desktop

`cargo run -p topnode-desktop` keeps workspace code unoptimized with debug
symbols, but optimizes third-party dependencies (including Slint's software
renderer). The first development build after changing this profile recompiles
dependencies and takes longer; subsequent builds reuse them. The node selector
only creates visible plan/node cards, so large plans do not instantiate their
entire lists when opened or switched.

When complete Git metadata is available, `apps/desktop/build.rs` derives the
same commit-count/date/SHA version used by Android. Source archives without Git
metadata fall back to version code `1` and the Cargo package version. Controlled
builds can set `TOPNODE_VERSION_CODE`, `TOPNODE_VERSION_NAME`, and
`TOPNODE_GIT_COMMIT`; invalid or shallow automatic version inputs fail closed.

## UI preview

The checked-in preview gallery uses production page components with fixed,
non-sensitive sample data. It lets `slint-viewer` render every customer page
and important state without starting the Panel client or sing-box:

    ./scripts/preview-ui.ps1

The script compiles every `.slint` source with the Fluent style, then writes
the login, connection, node, subscription, purchase, profile, settings, and design-system
screenshots to `target/ui-preview`. To run only the full compile check:

    ./scripts/preview-ui.ps1 -CheckOnly

For interactive inspection with automatic reload:

    slint-viewer --style fluent --auto-reload --component ConnectedPreview apps/desktop/ui/preview/gallery.slint

Other exported preview components include `LoginPreview`,
`LoginErrorPreview`, `HomePreview`, `CoreUnavailablePreview`, `ConnectingPreview`, `NodeSelectorPreview`,
`SubscriptionsPreview`, `PurchasePreview`, `ProfilePreview`, `BalanceDetailsPreview`, `SettingsPreview`,
and `DesignSystemPreview`.

For a development launch, build the locked core before building the desktop
application. For example, on Windows x86_64:

    python scripts/build-sing-box-acp.py --target x86_64-pc-windows-msvc --output runtime --require-native
    cargo build -p topnode-desktop

The builder uses the sibling `../third_party/sing-box-acp` Git repository if
present, or fetches the pinned commit from the locked repository. Use
`--source` to select another local checkout and `--help` to list targets.
Cargo copies the binary from `runtime/core/` beside the development executable:

- Windows: `target/debug/runtime/core/sing-box-acp.exe`
- Linux/macOS: `target/debug/runtime/core/sing-box-acp`

The application never searches `PATH` or the shell working directory. It
resolves the sidecar as
`current_exe().parent()/runtime/core/sing-box-acp[.exe]`, so shortcuts and app
bundles cannot accidentally select a different executable.

The read-only deployment configuration is loaded from
`current_exe().parent()/runtime/startup.json`. Payment presentation is selected
with `payment.presentation`: `qr_code` (the default when the file or field is
missing) keeps the user in the desktop app and displays a scannable code, while
`browser` opens the payment session in the system default browser. A valid
remote bootstrap document may override only this presentation policy. The
local file is not a Panel API fallback and never stores a remote bootstrap
document or payment-provider credentials.

On first launch, the client creates and persists a stable installation device
ID in non-secret settings, restores an encrypted session when present, and
otherwise shows the login page. After login it fetches resource groups and
nodes; selecting a connectable group and selectable node enables the runtime
configuration request.

Both Panel requests send `Topnode-Accept-Protocols` for VLESS Reality
(Raw/Vision and XHTTP), AnyTLS, Hysteria2, Juicity, and Mieru (TCP/UDP).

## Test Naive on Windows

Build the test core and run the loopback connection checks:

    python scripts/build-sing-box-acp.py --target x86_64-pc-windows-msvc --output runtime --require-native --with-naive
    python -m pip install cryptography
    python scripts/verify-naive.py --core runtime/core/sing-box-acp.exe

The builder stages the matching Cronet DLL from the ACP dependency lock.
The tests send HTTP traffic through real Naive HTTPS and QUIC connections.
They cover private CA and self-signed trust, plus rejection of untrusted CA,
expired certificates, wrong names and wrong passwords. They leave system
trust untouched.

Quit any running desktop instance, including the tray instance, then run:

    cargo run --locked -p topnode-desktop

The debug app offers Naive HTTPS and QUIC (including custom CA) to the Panel
when the matching core reports Naive support and its Cronet library is present.
Log in with a test account that has Naive nodes in its plan. In system proxy
mode, select an HTTPS node and a QUIC node separately, and load a page through
each. Use a node with a publicly trusted certificate to verify system trust.
Portable release packaging rejects the test core.

`DevelopmentConfigurationSource` and `config/sing-box.example.json` remain in
the repository for isolated adapter tests and manual sidecar development. They
are not wired into the desktop application's default startup path, which uses
the authenticated Panel configuration endpoint.

## Distribution layout

The release directory must contain at least:

    topnode.exe  # topnode-desktop on Unix
    runtime/
      startup.json
      core/
        sing-box-acp[.exe]
    BUILD-INFO.json
    THIRD_PARTY_NOTICES.md
    LICENSE.sing-box-acp

The `desktop-candidates` workflow (portable-release.yml) requires the default
branch and complete Git history. Its six native runners build the pinned Naive
core, bundle Cronet where required, run TCP/UoT certificate tests and assemble
explicit candidates. It does not publish releases or change online bootstrap
configuration. Build success alone does not grant protocol or system-takeover
qualification.

The release baseline is Windows 11, macOS 13+, and Ubuntu 24.04 GNOME, on both
x86_64 and ARM64. Windows retains the WinINet/UAC lifecycle. Linux includes a
GSettings backend and a restricted systemd/polkit TUN helper; macOS includes a
per-network-service SystemConfiguration backend and an SMAppService/XPC helper.
These new platform integrations require installed-system acceptance on their
actual targets. Linux full installation uses the .deb; macOS full installation
uses a root-owned, Developer ID signed and notarized .pkg. No ad-hoc signature
is treated as production qualification.

`BUILD-INFO.json` records candidate/supported status from artifact-bound evidence,
not from the operating system name. Formal packaging requires matching core,
Cronet and native reports plus a complete installed-system acceptance report
bound to the application and helpers. Missing evidence leaves Naive capabilities
unadvertised. System proxy mode covers proxy-aware TCP applications; application
UDP takeover is verified separately in TUN mode.

For build, signing, fixture, installation, qualification and rollback steps see
[Naive/UoT release procedure](docs/naive-uot-release.md). `publish-dufs.py` rejects
candidate/preview packages. Publication and bootstrap updates require a separate
release operation after acceptance, reusing the exact verified artifacts.
Keep the previous complete release for rollback and clean up network ownership
before replacing application or helper files.

Release helper tests run with `python -m unittest discover -s scripts/tests -v`.
The checked-in workflows assume client-desktop is the repository root.
