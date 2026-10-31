# Mystic A48/A49 BinkP TLS qualification

An isolated Linux amd64 Mystic 1.12 A49 instance successfully loaded a keyset
created by mpemtrans and completed a BinkP TLS 1.2 connection with cryptlib 3.4.5.

The synthetic input was an encrypted PKCS#8 RSA private key and an ordered PEM
fullchain (leaf plus test CA). The test client trusted only that test CA and
verified `localhost`. The received leaf DER had to equal the original leaf
exactly, preventing a pass based on Mystic silently generating another key.

After the handshake, the client parsed an encrypted BinkP M_NUL greeting and
sent an encrypted M_NUL command. The test checked the mapped cryptlib file and
that the converted `data/ssl.cert` bytes were unchanged. This was a real MIS
process with the actual cryptlib, without an interception shim during the final
test. No node authentication or mail/file transfer was attempted.

## Native keyset interface

A49 uses a fixed legacy key label and short internal keyset password. A converter
keyset using arbitrary values can reopen successfully in cryptlib but fail in
Mystic. The synthetic fixture's native interface parameters were measured and
kept in private owner-only files; their password contents are not published.
Preview 1 incorrectly imposed a minimum of eight password bytes. Preview 2
accepts nonempty protected password files and lets cryptlib enforce its keyset
constraints. Encrypted PEM input passwords are likewise not subject to an
unrelated output-keyset length requirement.

## Repeating the protocol test

Prepare a separate offline installation with loopback BinkP enabled and its TLS
port set to 24553. Use the matching A49 developer records and tested configuration
helpers; never patch an unknown DAT layout. Convert synthetic PEM input with the
native keyset label/password and place the result at that fixture's
`data/ssl.cert`, preserving its previous file as a backup. Do not use production
configuration, certificates or passwords.

Create `.mpemtrans-handshake-fixture` in the fixture root containing exactly
`Synthetic offline mpemtrans fixture`. Then run the committed test in a new
loopback-only network namespace:

```sh
unshare -Urn python3 tests/test_mystic_binkp.py \
  --fixture /absolute/path/to/synthetic-mystic \
  --library /absolute/path/to/libcl.so.3.4.5 \
  --leaf /absolute/path/to/test-leaf.pem \
  --ca /absolute/path/to/test-ca.pem
```

The test starts and stops only the selected fixture. The fixture marker and
loopback-only namespace are mandatory. A CA/hostname failure, wrong leaf,
missing encrypted frame, different library or changed keyset fails the test.

This result qualifies this BinkP TLS combination. It does not establish native
Mystic compatibility with newer cryptlib releases, HTTP(S), other Mystic
versions or Windows protocol handshakes. The conversion-level Windows tests
are recorded separately in the release build report.

## Stable A48 verification

The official stable Linux amd64 A48 archive was extracted into a second isolated
fixture. Configuration was prepared using A48's own `records.112` compiled in a
fixture-only Pascal helper, not A49 byte offsets. A48's shipped data-change
marker is `1.12 A47`; this is recorded rather than falsely upgrading the marker.

The exact same converted `ssl.cert` used by A49 was then copied into the offline
A48 fixture. Real A48 MIS with cryptlib 3.4.5 completed the same verified BinkP
TLS 1.2 test: exact input leaf DER, test CA and localhost validation, encrypted
BinkP M_NUL receive/send, actual library mapping and unchanged keyset. No shim
was used for this A48 qualification. Thus the tested keyset profile works on
both versions. Native Windows A48 protocol handshakes remain unqualified.

## Why a DAT field cannot configure this in stock Mystic

The A48/A49 public RecConfig and ServerInfoRecord definitions do not declare
keyset-label or `ssl.cert` password fields. `RecEchoMailNode.CryptKey` belongs
to a different function: A48 WHATSNEW explains that the node Encryption Key
encrypts Netmail contents using AES-256. It must not be repurposed as a TLS
keyset password.

Adding bytes or a new setting to a DAT file would not make an unchanged Mystic
binary read it. The converter must produce a keyset accepted by the native
version-specific interface. An automatic converter profile is distinct from a
new Mystic configuration option; the current CLI still accepts explicit label
and protected password-file inputs.

Sources: official A48 archive and shipped developer record/changelog files;
https://mysticbbs.com/downloads.html lists A48 as the stable release.
