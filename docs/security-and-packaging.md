# Security and packaging notes

## Files and credentials

- The executable directory is read-only input at runtime. Only the application
  binary, the local `runtime/startup.json` presentation default, the
  `runtime/core` directory, and its sing-box binary belong there.
- Configuration, cache, logs, and settings belong in the OS application-data
  directory selected by the platform path adapter.
- Runtime configuration payloads must not appear in panic reports, tracing
  fields, UI messages, or analytics. New connections normalize once into
  zeroizing memory and pipe the exact same bytes to sing-box `check` and `run`;
  they do not create plaintext candidate/session files. Startup and connection
  preparation remove legacy files from earlier builds, and cleanup failure
  blocks startup.
- App logs rotate before a segment exceeds 4 MiB and retain at most seven files
  and about 32 MiB in total, both during runtime and at startup. Sidecar stdout
  is debug-only by default and sensitive-looking lines are suppressed.
- `settings.toml` contains only non-secret preferences and the installation's
  stable device UUID. It never contains passwords or tokens.
- A remote `desktop.config.json` is public discovery input, not a credential
  container. Its optional `payment.presentation` value may select `qr_code` or
  `browser`, but payment gateway secrets, merchant credentials, signing keys,
  and provider configuration must remain on the Panel. The remote document is
  held only for the current cold start and is never cached to disk.
- The OS credential vault stores only a random 32-byte data-encryption key.
  The session is an XChaCha20-Poly1305 authenticated envelope at
  `data/auth/session.v1.bin`; every replacement uses a fresh nonce and an
  atomic file commit. Clearing a session deletes the vault key first, making a
  leftover envelope unusable after a crash.
- Vault operations are serialized in-process and run off the async executor.
  All login, restore, refresh, and logout session mutations share one session
  gate, while the GUI's OS lock prevents two normal application instances from
  sharing the envelope concurrently.
- The single-instance activation record contains only a random token and an
  IPv4-loopback port. It is size-limited, atomically written with mode 0600 on
  Unix, authenticated with a constant-time comparison, and never decides lock
  ownership by itself.
- The Windows system-proxy journal is a private application-data file with an
  atomic replacement protocol, an owner UUID, and explicit `Prepared`/`Active`
  phases. Its opaque snapshots can contain the user's previous proxy and PAC
  values, so snapshot and journal types have redacted debug representations and
  those values must never enter logs, UI errors, or diagnostics exports. Unix
  journal creation uses mode 0600; Windows relies on the per-user LocalAppData
  ACL inherited by the application directory.

## Traffic ownership

The user-facing System Proxy mode is the default. On Windows it reserves a random
`127.0.0.1` port, replaces server-provided Mixed/SOCKS listeners with one
client-owned Mixed listener, and keeps the reservation until immediately before
sing-box spawn. The client waits for both its authenticated control API and the
Mixed listener before writing a `Prepared` journal and applying the complete
WinINet per-connection settings. It sends the documented settings-changed and
refresh notifications, queries the result back, and only then marks the journal
`Active` and publishes `Connected`.

Disconnect and explicit exit compare the current WinINet snapshot with the
owned applied snapshot. Only an exact match may be replaced with the saved
original; an external change is preserved and ownership is abandoned. A failed
restore retains the child and live lease so the listener does not disappear
under an active proxy. Startup reconciliation handles crashes before apply,
after apply, after activation, and after restore but before journal deletion.
Proxy and PAC contents are never included in errors or debug output.

Linux and macOS system-proxy backends and TUN permission adapters are not yet
implemented. They return an unsupported/fail-closed result instead of claiming
traffic ownership.

## Process containment milestones

The client explicitly stops and waits for the child and enables kill-on-drop.
On Windows it assigns the GUI to a Job Object with `KILL_ON_JOB_CLOSE`; sing-box
inherits that job and is reclaimed even when Task Manager terminates the GUI.
The Job permits explicit (not silent) breakaway solely for the fixed internal
elevation launcher. That launcher leaves the old Job before invoking UAC, so
the elevated replacement is not killed when the old GUI exits. Ordinary child
processes, including sing-box, never receive the breakaway creation flag.
Unix and macOS launch the long-lived core through a hidden guardian mode of the
same desktop executable. The guardian validates its direct parent before
starting sing-box, remains alive across group `SIGTERM`, and checks the parent
relationship every 100 ms; parent loss kills the entire process group with
`SIGKILL`. Normal shutdown still uses group TERM, a bounded grace period, then
group KILL.

Selecting Global mode in the Windows Settings UI currently requests UAC because
that mode uses TUN internally, then starts a replacement copy of the complete
GUI as Administrator. The launcher and replacement accept only fixed internal
arguments and authenticate over a random loopback handoff. The old process
retains a dedicated handoff lock while the replacement acquires the primary
lock and preflights settings, controller, window, tray, and activation. A
`READY -> COMMIT -> COMMITTED -> FINAL` exchange delays persistence and old-UI
shutdown until those prerequisites succeed; abort paths restore the original
setting and lock. The replacement listener is pre-bound without overwriting
the old discovery record, then publishes its own record during the reversible
commit stage before `FINAL`; an abort restores the old record. Post-`FINAL`
handoff-gate acquisition retries in the background instead of terminating the
committed replacement. Rejected or cancelled UAC keeps System Proxy mode. Connect
performs one permission gate in the controller and another immediately before
the sidecar is spawned. Elevating the whole GUI is an explicit temporary
security tradeoff. The long-term design must move privileged TUN operations
into a narrow, authenticated broker and return the Fluent GUI to an
unprivileged token; Linux and macOS require separate least-privilege adapters.

## Panel transport

Every cold start requests these public HTTPS bootstrap sources sequentially and
stops at the first structurally valid document:

1. `https://0x10.topboot.top/desktop.config.json`
2. `https://0x11.boot1.top/desktop.config.json`
3. `https://0x12.boot2.top/desktop.config.json`

No fixed API endpoint, cached bootstrap response, or packaged remote document
is a fallback. A source response is rejected on transport, size, JSON, or
schema failure; failure of all sources keeps startup blocked behind a visible
Retry/Exit error window. Retry and any later launch restart discovery from the
first source.
After a valid document is accepted, every valid `baseApiServer` route is probed
concurrently. The first candidate that completes TLS and returns any HTTP
response wins even when the status is non-2xx, and all remaining requests are
cancelled. DNS, connect, TLS, and timeout failures never count as success. A
valid document whose API candidates all fail is not replaced with a later
bootstrap source.

Direct routes preserve the logical host as the connection target, TLS
identity, and HTTP authority. An enabled fake-fronted mapping instead connects
to the declared literal IP, sends `fakeSNI`, verifies the normal WebPKI chain,
certificate validity, handshake signatures, the logical-domain hostname, and
the configured SPKI SHA-256 pin, then sends the logical domain as the HTTP
authority. A logical host with a matching mapping uses its fronted candidates
instead of also adding a direct candidate; an unmatched host remains direct.
Pins are an additional requirement and never replace standard certificate
validation. The exact winning connection IP, SNI, logical
identity, authority, and pin policy are reused for authenticated Panel traffic.
Redirects and environment or system proxy discovery remain disabled. Route
diagnostics may identify the mode, logical host, and connection IP, but must
never log an SPKI pin or credential.

The optional remote `payment.presentation` field controls only whether a
server-provided payment URL is rendered as an in-app QR code or opened in the
system browser. It overrides the local `runtime/startup.json` default and must
not carry a payment-method list or any merchant configuration. The desktop's
existing authenticated client continues to obtain enabled payment methods from
`GET /api/v1/users/payment-methods`, matching Web and Android. Provider
credentials remain server-side. `config/desktop-config.json` is only a
publishing schema example; it is not packaged as the remote document and does
not change any live bootstrap source until deployment publishes it there.

## Version policy

The Android-shaped `version` object in the remote bootstrap document is
structurally validated so a malformed or incompatible document cannot select a
Panel route. Desktop versions follow Android: a complete-history Git commit
count becomes the numeric `versionCode`, while the commit date and eight-character
SHA become `versionName`. Only a strictly greater remote code can update. The
updater selects an exact Rust-target key from `version.downloads`, requires a
Browser/HTTPS entry with the expected platform archive extension and MIME type,
and delegates the URL to the hardened system-browser
adapter. It never uses the legacy singular `download`, downloads code inside
the process, accepts a non-web scheme, or treats inequality as an upgrade.

The manual release workflow queries the official SagerNet GitHub Release by an
exact stable version and asset name, requires GitHub's SHA-256 asset digest,
verifies the download, extracts only the expected binary/license/`libcronet.*`
members, executes an exact version probe, requires advertised PureGo/Naive
builds to carry their Cronet companion, and runs the runtime's stdin-based
`sing-box check` command against a representative configuration. The selected
version is compiled into the client and checked again during staging. Every archive includes a
manifest with the source commit, target, Rust toolchain, Cargo.lock digest,
upstream asset metadata, payload hashes, and the bundled core's version output;
the Release also publishes aggregate SHA-256 checksums. A future formal release
process should additionally produce an SBOM and signed provenance.

Git commit count is monotonic only on a non-rewritten release branch. The
workflow therefore accepts the repository default branch only, fetches complete
history, and rejects a code not greater than earlier desktop release tags. A
different sing-box selection requires a new source commit; repackaging the same
desktop version with different runtime contents would be invisible to the
client's update comparison.

The generated `desktop.config.release.json` is a deployment artifact, not a
public GitHub Release/Actions artifact or an automatic boot-origin mutation.
Generate it only inside the controlled deployment environment after publishing
the GitHub Release, then copy the version data to all three configured HTTPS
origins. Because the renderer starts
from the checked-in schema example, deployment must preserve the production
document's `baseApiServer`, `apiProbe`, `fake`, and `payment` policy; merge only
the generated `version` object unless those fields have first been synchronized
into the template. Updating only the legacy singular `version.download` does not
enable desktop updates. Deployment credentials and server access are
intentionally outside this repository workflow.

Generated GitHub URLs are anonymous only for a public repository. A private
source repository may still build its Release, but operators must replace those
URLs with anonymously accessible official/CDN distribution links before
boot-origin deployment. They must also verify every archive, a `versionCode`
greater than every previously distributed desktop build, identical JSON on all
three origins, and no HTTP redirects. The verify job renders the release
document and feeds it through the Rust startup-contract test before the native
build matrix runs.

## License obligations

sing-box is GPL-3.0-or-later. Bundling it as a sidecar does not remove binary
redistribution obligations. Ship the GPL license, notices, corresponding source
or a compliant source offer, build metadata, and consult legal counsel for the
combined distribution.

Slint has its own royalty-free/commercial terms. The restoring splash screen includes
the AboutSlint badge required by the royalty-free option. Preserve it or obtain
the appropriate commercial license.
