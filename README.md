# mpemtrans

Mystic PEM certificate conversion for cryptlib-compatible keysets.

Status: repository and requirements prepared; no qualified executable release yet.

## Distribution

Windows releases use ZIP archives; Linux releases use tar.gz archives. Extract
beside Mystic in `/opt/mystic` or `C:\Mystic`. No MSI, DEB, system service,
global PATH change or machine-wide installation is planned for this small tool.
Each archive contains exactly one native executable and README.txt. Embed
profiles/data in the program; do not ship script wrappers, helper DLLs or
sidecar configuration. Identify architecture and runtime/library requirements
in the README. Checksums are published beside the archive on GitHub.
There is no release artifact until native tests pass.

## Requirements

- Accept certificate, chain and matching private key from an external issuer.
- Target the actual Mystic/cryptlib 3.4.5 keyset format after qualification.
- Verify key/certificate matching, chain handling and RSA/ECDSA support explicitly.
- Do not claim that renaming a PEM or PKCS#12 file converts it to a cryptlib keyset.
- Protect output key material; never print private keys or passwords.
- Stage new output, reopen it through the target cryptlib and test a native Mystic handshake before activation.
- Support both the stable old cryptlib and the newer cryptlib through explicitly selected and verified library/version profiles. Attribute numbers and API differences must not be assumed interchangeable.
- No overwriting production certificates or deployment/restart side effects.

## Repository boundary

The program, its builds and tests live here. Installation/configuration integration
belongs to the separate mysticd repository. BBS artwork and presentation assets
belong to mystic-theme. Existing live data must not be changed without explicit
operator approval. License: the original permissive notice in pemtrans.c and LICENSE.
See UPSTREAM-REVIEW.md for the required modernization before release.
