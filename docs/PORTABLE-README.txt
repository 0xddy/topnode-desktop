TOPNODE Desktop candidate / qualified package
============================================

Keep the directory layout intact. Read BUILD-INFO.json: candidate means the
complete native and installed-system matrix has NOT been accepted. A package
without matching Naive qualification intentionally does not advertise Naive.
Never alter the report or supportTier to bypass verification.

Windows 11: run topnode.exe. TUN mode requires the existing UAC handoff.
System proxy mode covers applications honoring HTTP/HTTPS proxy settings;
it does not capture every application's UDP traffic.

Ubuntu 24.04 GNOME: use the .deb for full installation. It installs the fixed
root-owned core, systemd helper and polkit authorization. The GUI stays an
ordinary user. A portable archive alone does not install the privileged helper.
Other desktop environments are not qualified for system proxy mode.

macOS 13+: full installation requires the signed/notarized .pkg installed at
/Applications/TOPNODE Desktop.app. Approve the SMAppService background item
when enabling TUN. Unsigned candidates cannot establish the authenticated
privileged-service connection and are not a production distribution.

Quit before upgrading or removing the application. Let the GUI restore its
proxy lease; after a crash, relaunch it to reconcile the journal. On macOS,
unregister the background service with the installed signed bridge before
removing the app. Keep the prior complete package for rollback.

BUILD-INFO.json and the validation reports bind exact artifact hashes.
No transport, certificate-validation or failed-UoT direct fallback is enabled.
