TOPNODE Desktop portable package
================================

Keep this directory layout intact. The application resolves runtime/startup.json
and runtime/core/sing-box-acp only beside its own executable; it intentionally does
not search PATH or the current working directory.

Windows
-------
Run topnode.exe. Windows x86_64 and ARM64 are the complete supported
desktop packages. An unsigned build can show a SmartScreen warning; production
releases should be Authenticode-signed.

Linux preview
-------------
Run ./topnode-desktop. The archive preserves executable permissions and expects
a glibc desktop with Fontconfig, XKB, a graphical session, and a Secret Service
credential provider. System-proxy takeover and TUN integration are not yet
implemented, so this package is a UI/integration preview rather than a complete
traffic-routing client.

macOS preview
-------------
Open TOPNODE Desktop.app on macOS 12 or later. The package is ad-hoc signed, but is not Developer ID
signed or notarized; Gatekeeper may require right-clicking Open on first launch.
System-proxy takeover and TUN integration are not yet implemented, so this
package is a UI/integration preview rather than a complete traffic-routing
client.

BUILD-INFO.json records the exact application and sing-box-acp commits, Rust
target and SHA-256 hashes. SHA256SUMS.txt beside the GitHub Release assets
can be used to verify the downloaded archive.
