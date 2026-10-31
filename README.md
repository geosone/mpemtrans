# pemtrans

Certificate conversion for Mystic-compatible cryptlib keysets.

Status: repository and requirements prepared; no qualified executable release yet.

## Distribution

Windows releases use ZIP archives; Linux releases use tar.gz archives. Extract
beside Mystic in `/opt/mystic` or `C:\Mystic`. No MSI, DEB, system service,
global PATH change or machine-wide installation is planned for this small tool.
Each release must include architecture identification, checksums and its runtime
requirements. There is no release artifact until native tests pass.

## Requirements

- Accept certificate, chain and matching private key from an external issuer.
- Target the actual Mystic/cryptlib 3.4.5 keyset format after qualification.
- Verify key/certificate matching, chain handling and RSA/ECDSA support explicitly.
- Do not claim that renaming a PEM or PKCS#12 file converts it to a cryptlib keyset.
- Protect output key material; never print private keys or passwords.
- Stage new output, reopen it through the target cryptlib and test a native Mystic handshake before activation.
- No overwriting production certificates or deployment/restart side effects.

## Repository boundary

The program, its builds and tests live here. Installation/configuration integration
belongs to the separate mysticd repository. BBS artwork and presentation assets
belong to mystic-theme. Existing live data must not be changed without explicit
operator approval. License: GPL-3.0-only.
