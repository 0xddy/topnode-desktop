# Desktop startup configuration audit

Checked on 2026-09-08 against the deployment repository and all three live sources:

- https://0x10.topboot.top/desktop.config.json
- https://0x11.boot1.top/desktop.config.json
- https://0x12.boot2.top/desktop.config.json

All three documents were byte-identical and matched the JSON in
`0xddy/topnode-bootstrap-config/desktop.config.json`. SHA-256:
`6ab1940b7de59b167eee0080a9df3cf77eb1a35db06768b1672e3caa790e0b13`.
The local proxy returned HTTP 403; direct HTTPS requests using the desktop
bootstrap user agent succeeded, matching the application's no-proxy policy.

| Field | Deployed value | Result |
| --- | --- | --- |
| `website` | `https://topnode.cc` | HTTPS; HEAD 200, HTML |
| `version.metadata.versionCode` | `100` | Intentionally retained for upgrade testing, confirmed by the owner |
| `version.metadata.versionName` | `2026.09.08-23606851` | Valid release display name |
| `version.metadata.updateInfo` | Empty string | Dialog explicitly says no release notes were supplied |
| `version.metadata.forceUpdate` | `false` | Optional upgrade with a defer action |
| `payment.presentation` | `qr_code` | Valid desktop payment presentation |
| `apiProbe` | GET `/`, FirstSuccessful, 10/30/35-second timeouts, cancellation enabled | Within accepted bounds |

All six exact-target download URLs returned HEAD 200. Windows x86_64/ARM64
archives use ZIP and `application/zip`; Linux and macOS x86_64/ARM64 archives
use `.tar.gz` and `application/gzip`. The legacy singular download remains a
directory page and serves as the fallback when `downloads` has no entry matching
the current build target. A matching platform archive always takes priority.

The download directory is `desktop-v8-2026.09.08-23606851`; the source build's
Git-derived version code is 8. The remote code 100 intentionally triggers the
upgrade prompt for testing even though the display name is the same. No live
configuration was modified. Before a real rollout, publish metadata and an
artifact carrying the same version code to avoid repeatedly offering the same
package. Publishing permits lower version codes; clients still offer updates only
when the remote code is greater than the installed code.

These are configuration and HTTP availability checks, not checksum verification
or execution of the six downloaded artifacts. No installer was downloaded or run.

The production bootstrap integration test also passed with the actual Rust HTTP
client, selecting the first source and receiving HTTP 200 from the selected Panel
route. A regression test separately verifies that version metadata is available
before an unreachable Panel API is contacted. Startup prompts run before saved
login restoration, and manual checks likewise do not require a healthy Panel API.
