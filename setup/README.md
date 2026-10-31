# Setup-only native Mystic profile capture

These files are installer assets, separate from the two-file converter archive.
They contain API forwarding code and a synthetic fixture runner. They contain
no Mystic key labels, keyset passwords, real keys or generated profiles.

The mysticd mpemtrans/install.ps1 component verifies that installed MIS matches
the supplied vendor executable and uses matching qualified developer records.
It creates a private disposable fixture from manufacturer template data only.
Linux runs it in a loopback-only user/network namespace. Windows binds only to
127.0.0.1 and uses a fresh private directory with protected ACLs. Windows setup
requires an elevated PowerShell 7.4+ session and currently qualified layouts.

The capture shim is copied only beside that disposable MIS. All calls are
forwarded to the explicit real cryptlib through its public API; it records the
label/password actually passed to cryptGetPrivateKey into private files. The
installer validates the files, writes an owner-only local INI, stops the fixture
and removes its temporary directory. Production libcl files are never replaced.
No installed Mystic DAT file is changed and no production service is restarted.

The label/password are Base64-encoded solely for unambiguous INI storage.
Base64 is not encryption. The profile must remain private and must never be
committed, uploaded or attached to logs. Linux profile mode is 0600; use the
installer's ProfileOwner parameter for the account that will run the converter.
Windows restricts access to the selected account, SYSTEM and administrators.
The public schema stores version and native binary hashes for provenance;
these hashes are not a signature or an authentication mechanism.

The capture mechanism has no version-specific credential table. Fixture layout
qualification is separate: unknown layouts are refused until verified. The
current initializer qualifies A48/A49 record definitions. Explicit label and
password-file conversion remains available for other controlled workflows.

The normal converter accepts --profile FILE and loads the real cryptlib
directly. No capture shim is needed for normal conversion or server operation.
Do not copy the setup-only libcl.so/cl32.dll/cl64.dll over a working library.
